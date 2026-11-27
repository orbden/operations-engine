//! Nextcloud for `application.install`: the pinned server archive instead of
//! Composer, a managed data directory beside the site, and `occ
//! maintenance:install` with no password in any command line.
//!
//! 1. The request names the archive (`archive.url`, `archive.sha256`, from
//!    the panel's pinned catalog). Only
//!    `https://download.nextcloud.com/server/releases/nextcloud-X.Y.Z.tar.bz2`
//!    is accepted; `pinned_download` streams it into a 0600 file of the
//!    engine's own state directory (no redirect, size and time limits) and
//!    hands it back only when its SHA-256 equals the pin.
//! 2. `tar_extract` unpacks it into the staging directory (no absolute
//!    names, no `..`, no symlink leaving the tree, no hardlinks or devices,
//!    entry and byte limits). The archive's `nextcloud/` becomes the docroot
//!    `public/`; its `.user.ini` is dropped because the site's own one
//!    (kept in the docroot) belongs to the panel. The tree then passes to the
//!    site's UID with the descriptor-based ownership walk.
//! 3. The data directory is `<content root>/<domain>-data`: outside the
//!    document root, owned by the site's UID, mode 0700. An existing one that
//!    is not empty (or not a plain directory) is refused before anything is
//!    downloaded. On failure one this install created is removed, and one that
//!    was already there (empty) is emptied again. `site.removeRoot` removes
//!    only `<content root>/<domain>`, so deleting the site keeps the data
//!    unless the caller also asks for `--with-data-dir`.
//! 4. `occ maintenance:install` runs through `INSTALL_SCRIPT`, which builds
//!    Nextcloud's argv inside PHP from positional arguments and two
//!    environment variables, then loads `console.php`: the passwords are in
//!    neither the `docker` nor the container's `php` command line. Then
//!    `trusted_domains`, `overwrite.cli.url`, `overwriteprotocol` and
//!    `overwritehost` are set for the site's address, `trusted_proxies` names
//!    the loopback hop, and `occ status` must report it installed.

use std::{io::BufReader, time::Duration};

use super::{Context, Error, Request, exec, rel};
use crate::{
    filesystem::ManagedRoot,
    pinned_download,
    process::{self, CancellationToken, ProcessOutput},
    site::{SiteRelativePath, TrustedRoot},
    tar_extract,
};

pub(crate) const ARCHIVE_PREFIX: &str = "https://download.nextcloud.com/server/releases/nextcloud-";
const ARCHIVE_SUFFIX: &str = ".tar.bz2";
/// The 35.0 archive is about 250 MB and unpacks to about 800 MB in 32 000
/// entries.
pub(crate) const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const EXTRACT_LIMITS: tar_extract::Limits = tar_extract::Limits {
    max_entries: 100_000,
    max_file_bytes: 2 * 1024 * 1024 * 1024,
};
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DB_PASSWORD_ENV: &str = "NC_INSTALL_DB_PASSWORD";
const ADMIN_PASSWORD_ENV: &str = "NC_INSTALL_ADMIN_PASSWORD";
/// Run as `php -r INSTALL_SCRIPT -- <db type> <host> <port> <name> <user>
/// <admin email> <data dir>` in the Nextcloud root. Fixed text: values come
/// in as arguments, the two passwords from the environment, and `occ`'s own
/// argv is assembled here so no process shows them.
const INSTALL_SCRIPT: &str = r#"[, $db, $host, $port, $name, $user, $email, $data] = $argv;
$dbPass = getenv('NC_INSTALL_DB_PASSWORD');
$adminPass = getenv('NC_INSTALL_ADMIN_PASSWORD');
putenv('NC_INSTALL_DB_PASSWORD');
putenv('NC_INSTALL_ADMIN_PASSWORD');
if ($dbPass === false || $adminPass === false) { fwrite(STDERR, "missing password\n"); exit(2); }
$_SERVER['argv'] = $argv = ['occ', 'maintenance:install', '--no-interaction', '--no-warnings',
  '--database=' . $db, '--database-host=' . $host, '--database-port=' . $port,
  '--database-name=' . $name, '--database-user=' . $user, '--database-pass=' . $dbPass,
  '--admin-user=admin', '--admin-pass=' . $adminPass, '--admin-email=' . $email,
  '--data-dir=' . $data];
$_SERVER['argc'] = $argc = count($argv);
unset($dbPass, $adminPass);
require 'console.php';
"#;

/// A release archive on Nextcloud's own download server: exactly
/// `…/server/releases/nextcloud-<major>.<minor>.<patch>.tar.bz2`.
pub(crate) fn archive_url_ok(url: &str) -> bool {
    url.strip_prefix(ARCHIVE_PREFIX)
        .and_then(|rest| rest.strip_suffix(ARCHIVE_SUFFIX))
        .is_some_and(|version| {
            let parts: Vec<&str> = version.split('.').collect();
            parts.len() == 3
                && parts.iter().all(|part| {
                    (1..=4).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit())
                })
        })
}

/// The managed data directory and whether this install made it.
pub(super) struct DataDir {
    name: SiteRelativePath,
    pub(super) path: String,
    created: bool,
}

/// `<content root>/<domain>-data`, a plain directory owned by the site's UID
/// with mode 0700. One that exists must be an empty real directory.
pub(super) fn prepare_data_dir(
    content_root: &TrustedRoot,
    req: &Request,
) -> Result<(ManagedRoot, DataDir), Error> {
    let content = ManagedRoot::open(content_root).map_err(|_| Error::RootUnavailable)?;
    let leaf = format!("{}-data", req.domain.as_str());
    let name = rel(&leaf)?;
    let path = content_root
        .as_path()
        .join(&leaf)
        .to_str()
        .ok_or(Error::RootUnavailable)?
        .to_owned();
    let created = match content.create_dir(&name) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(Error::Io(error)),
    };
    let data = DataDir {
        name,
        path,
        created,
    };
    let dir = match content.open_child_dir_nofollow(&data.name) {
        Ok(dir) => dir,
        Err(_) if !created => return Err(Error::DataDirNotEmpty),
        Err(error) => return Err(Error::Io(error)),
    };
    if !created && !dir.child_entries_bounded(1).map_err(Error::Io)?.is_empty() {
        return Err(Error::DataDirNotEmpty);
    }
    let owned = dir
        .chown_self(req.uid, req.gid)
        .and_then(|()| dir.set_own_mode(0o700));
    if let Err(error) = owned {
        undo_data_dir(&content, &data);
        return Err(Error::Io(error));
    }
    Ok((content, data))
}

/// Removes the data directory this install created, or empties the one that
/// was already there.
pub(super) fn undo_data_dir(content: &ManagedRoot, data: &DataDir) {
    if data.created {
        let _ = content.remove_dir_all(&data.name);
        return;
    }
    let Ok(dir) = content.open_child_dir_nofollow(&data.name) else {
        return;
    };
    for entry in dir.child_entries().unwrap_or_default() {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        if let Ok(path) = SiteRelativePath::parse(name) {
            let _ = if entry.is_dir {
                dir.remove_dir_all(&path)
            } else {
                dir.remove_file(&path)
            };
        }
    }
}

/// Downloads and verifies the archive into the engine's state directory,
/// unpacks it as `<staging>/public` and gives the tree to the site's UID.
pub(super) fn stage(
    ctx: &Context<'_>,
    req: &Request,
    scope: &ManagedRoot,
    root: &ManagedRoot,
    staging: &str,
) -> Result<(), Error> {
    let archive = req.archive.as_ref().ok_or(Error::Unverified)?;
    let download = rel(format!("download-{}.tar.bz2", req.request_id))?;
    let file = pinned_download::download(
        ctx.fetch,
        &archive.url,
        &archive.sha256,
        MAX_ARCHIVE_BYTES,
        DOWNLOAD_TIMEOUT,
        scope,
        &download,
    )
    .map_err(|error| match error {
        pinned_download::Error::DigestMismatch => Error::ArchiveDigest,
        pinned_download::Error::Fetch(crate::engine::fetch::Error::Timeout) => {
            Error::ArchiveFetch(crate::error::ErrorCode::Timeout)
        }
        _ => Error::ArchiveFetch(crate::error::ErrorCode::ArtifactFetchFailed),
    })?;
    let unpacked = unpack(file, root, staging);
    let _ = scope.remove_file(&download);
    unpacked?;
    let staged = root
        .open_child_dir_nofollow(&rel(staging)?)
        .map_err(Error::Io)?;
    crate::permissions::execute::repair_open_directory(
        &staged.try_clone_fd().map_err(Error::Io)?,
        req.uid,
        req.gid,
        &[],
    )
    .map_err(Error::Io)?;
    Ok(())
}

pub(crate) fn unpack(file: std::fs::File, root: &ManagedRoot, staging: &str) -> Result<(), Error> {
    root.create_dir(&rel(staging)?).map_err(Error::Io)?;
    let staged = root
        .open_child_dir_nofollow(&rel(staging)?)
        .map_err(Error::Io)?;
    tar_extract::extract(
        bzip2::read::BzDecoder::new(BufReader::new(file)),
        &staged,
        EXTRACT_LIMITS,
    )
    .map_err(|_| Error::ArchiveUnsafe)?;
    // Exactly one top-level directory, `nextcloud/`, with Nextcloud's
    // version file in it.
    let entries = staged.child_entries().map_err(Error::Io)?;
    if entries.len() != 1 || entries[0].name != "nextcloud" || !entries[0].is_dir {
        return Err(Error::ArchiveInvalid);
    }
    let inner = staged
        .open_child_dir_nofollow(&rel("nextcloud")?)
        .map_err(Error::Io)?;
    if !inner
        .symlink_metadata(&rel("version.php")?)
        .is_ok_and(|meta| meta.is_file())
    {
        return Err(Error::ArchiveInvalid);
    }
    match inner.symlink_metadata(&rel(".user.ini")?) {
        Ok(meta) if meta.is_file() => inner.remove_file(&rel(".user.ini")?).map_err(Error::Io)?,
        Ok(_) => return Err(Error::ArchiveInvalid),
        Err(_) => {}
    }
    staged
        .rename(&rel("nextcloud")?, &rel("public")?)
        .map_err(Error::Io)
}

/// `occ maintenance:install`, then the site's address in the system config,
/// then `occ status` must say it is installed.
pub(super) fn setup(
    ctx: &Context<'_>,
    req: &Request,
    docroot: &str,
    data: &DataDir,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let db = req.database.as_ref().ok_or(Error::Unverified)?;
    let (email, password) = req.admin()?;
    let db_type = match db.driver {
        super::DatabaseDriver::Mariadb => "mysql",
        super::DatabaseDriver::Postgres => "pgsql",
    };
    let port = db.port.to_string();
    let install = exec(
        ctx,
        req,
        docroot,
        &[],
        &[
            (DB_PASSWORD_ENV, &db.password),
            (ADMIN_PASSWORD_ENV, password),
        ],
        &[
            "php",
            "-r",
            INSTALL_SCRIPT,
            "--",
            db_type,
            db.host.as_str(),
            &port,
            db.name.as_str(),
            db.user.as_str(),
            email,
            &data.path,
        ],
        INSTALL_TIMEOUT,
        cancel,
    )?;
    if process::error_code(&install.termination).is_some() {
        return Ok(install);
    }
    let domain = req.domain.as_str();
    let url = format!("https://{domain}");
    for (key, index, value) in [
        ("trusted_domains", Some("1"), domain),
        ("overwrite.cli.url", None, url.as_str()),
        ("overwriteprotocol", None, "https"),
        // The runtime pool rewrites Host for its private hop; Nextcloud builds
        // its redirects from `overwritehost` for web requests.
        ("overwritehost", None, domain),
        // The site's own FrankenPHP is reached from the pool's Caddy over the
        // loopback, which is the proxy Nextcloud sees.
        ("trusted_proxies", Some("0"), "127.0.0.1"),
    ] {
        let value = format!("--value={value}");
        let mut args = vec!["php", "occ", "--no-warnings", "config:system:set", key];
        args.extend(index);
        args.push(&value);
        let output = exec(
            ctx,
            req,
            docroot,
            &[],
            &[],
            &args,
            super::SETUP_TIMEOUT,
            cancel,
        )?;
        if process::error_code(&output.termination).is_some() {
            return Ok(output);
        }
    }
    let status = exec(
        ctx,
        req,
        docroot,
        &[],
        &[],
        &["php", "occ", "--no-warnings", "status", "--output=json"],
        super::SETUP_TIMEOUT,
        cancel,
    )?;
    if process::error_code(&status.termination).is_none() && !installed(&status.stdout.text()) {
        return Err(Error::Unverified);
    }
    Ok(status)
}

/// `occ status --output=json` reports `"installed": true`.
pub(crate) fn installed(stdout: &str) -> bool {
    stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
        .is_some_and(|value| value["installed"] == true)
}

/// `$OC_VersionString` of the docroot's `version.php`, read as text.
pub(crate) fn version(root: &ManagedRoot, docroot: &str) -> Result<String, Error> {
    let text = root
        .read_to_string(&rel(format!("{docroot}/version.php"))?)
        .map_err(|_| Error::Unverified)?;
    text.lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix("$OC_VersionString")?;
            let rest = rest.trim_start().strip_prefix('=')?.trim();
            let rest = rest.strip_suffix(';')?.trim();
            rest.strip_prefix('\'')?
                .strip_suffix('\'')
                .map(str::to_owned)
        })
        .filter(|version| crate::joomla_update::plain_version(version))
        .ok_or(Error::Unverified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_url_table() {
        for good in [
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.3.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-100.10.1000.tar.bz2",
        ] {
            assert!(archive_url_ok(good), "{good}");
        }
        for bad in [
            "",
            "http://download.nextcloud.com/server/releases/nextcloud-35.0.3.tar.bz2",
            "https://download.nextcloud.com.evil.org/server/releases/nextcloud-35.0.3.tar.bz2",
            "https://evil.org/server/releases/nextcloud-35.0.3.tar.bz2",
            "https://user@download.nextcloud.com/server/releases/nextcloud-35.0.3.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.3.zip",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.3.1.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-latest.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.3.tar.bz2?x=1",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.3.tar.bz2#y",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.3/../x.tar.bz2",
            "https://download.nextcloud.com/server/prereleases/nextcloud-35.0.3.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.a.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-35..3.tar.bz2",
            "https://download.nextcloud.com/server/releases/nextcloud-35.0.12345.tar.bz2",
            " https://download.nextcloud.com/server/releases/nextcloud-35.0.3.tar.bz2",
        ] {
            assert!(!archive_url_ok(bad), "{bad}");
        }
    }

    #[test]
    fn installed_is_read_from_the_last_json_line() {
        assert!(installed(
            "{\"installed\":true,\"version\":\"35.0.3.2\",\"maintenance\":false}\n"
        ));
        assert!(installed("a warning\n{\"installed\":true}"));
        for bad in [
            "",
            "{\"installed\":false}",
            "installed: true",
            "{\"installed\":\"true\"}",
        ] {
            assert!(!installed(bad), "{bad}");
        }
    }
}
