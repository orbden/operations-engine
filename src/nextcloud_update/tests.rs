//! `nextcloud.updateCore` / `nextcloud.restoreUpdate` through `execute` with a
//! fake `docker` that keeps state (the version in `version.php`, the
//! maintenance flag in `config/`, the database in a file), the system `tar`
//! and a small release archive.
use super::steps::DIE_AFTER;
use super::*;
use std::{
    cell::{Cell, RefCell},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

const A: &str = "123e4567-e89b-12d3-a456-426614174001";
const B: &str = "123e4567-e89b-12d3-a456-426614174002";
const C: &str = "123e4567-e89b-12d3-a456-426614174003";
const DB_PASSWORD: &str = "p@ss-secret-1";

/// State lives in `@S@`; `-w` of `docker exec` is the code directory.
const FAKE_DOCKER: &str = r#"#!/bin/sh
S='@S@'
printf '%s\n' "$*" >> "$S/calls.log"
[ -n "${MYSQL_PWD:-}" ] && printf '%s\n' "$MYSQL_PWD" >> "$S/env.log"
w=
prev=
for a in "$@"; do [ "$prev" = "-w" ] && w=$a; prev=$a; done
case "$*" in
  *"occ --no-warnings status"*)
    [ -e "$S/status-fail" ] && exit 1
    if [ -e "$S/status-garbage" ]; then echo "not json"; exit 0; fi
    ver=$(sed -n "s/.*OC_VersionString = '\(.*\)';.*/\1/p" "$w/version.php")
    if [ -e "$w/config/maint.flag" ]; then m=true; else m=false; fi
    if [ -e "$S/pending" ]; then p=true; else p=false; fi
    echo "{\"installed\":true,\"version\":\"$ver.2\",\"versionstring\":\"$ver\",\"maintenance\":$m,\"needsDbUpgrade\":$p}"
    exit 0;;
  *"maintenance:mode --on"*) touch "$w/config/maint.flag"; exit 0;;
  *"maintenance:mode --off"*) [ -e "$S/maint-stuck" ] || rm -f "$w/config/maint.flag"; exit 0;;
  *"occ --no-warnings upgrade"*)
    if [ -e "$S/fail-upgrade" ]; then echo partial > "$S/db"; exit 1; fi
    echo upgraded > "$S/db"; exit 0;;
  *mariadb-dump*) cat "$S/db"; exit 0;;
  *" mariadb "*)
    case "$*" in *"SELECT table_name"*) printf 'oc_a\tBASE TABLE\n'; exit 0;; esac
    cat > "$S/stdin.last"
    if grep -q DROP "$S/stdin.last"; then rm -f "$S/db"; exit 0; fi
    [ -e "$S/fail-import" ] && exit 1
    mv "$S/stdin.last" "$S/db"; exit 0;;
esac
exit 0
"#;

fn managed(directory: &Path) -> ManagedRoot {
    ManagedRoot::open(&TrustedRoot::parse(directory).unwrap()).unwrap()
}

const CONFIG: &str = "<?php\n$CONFIG = array (\n  'instanceid' => 'oc1',\n  'trusted_domains' => \n  array (\n    0 => 'localhost',\n    1 => 'example.com',\n  ),\n  'datadirectory' => '@DATA@',\n  'dbtype' => 'mysql',\n  'version' => '35.0.3.2',\n  'dbname' => 'nc',\n  'dbhost' => 'wcp-db:3306',\n  'dbuser' => 'ncuser',\n  'dbpassword' => 'p@ss-secret-1',\n  'installed' => true,\n);\n";

struct Fx {
    dir: tempfile::TempDir,
    project: PathBuf,
    docroot: PathBuf,
    data: PathBuf,
    target: String,
    archive: RefCell<Vec<u8>>,
    sha: RefCell<String>,
    fetched: Cell<u32>,
    fetch_fails: Cell<bool>,
    tar: RefCell<String>,
}

fn version_php(version: &str) -> String {
    format!("<?php \n$OC_Version = array(35,0,3,2);\n$OC_VersionString = '{version}';\n")
}

impl Fx {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn flag(&self, name: &str) {
        fs::write(self.path(name), "").unwrap();
    }

    /// A site at `installed` and a pinned release `target`.
    fn new(installed: &str, target: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("content/example.com");
        let docroot = project.join("public");
        let data = dir.path().join("content/example.com-data");
        for sub in [
            "public/config",
            "public/lib",
            "public/custom_apps/myapp",
            "public/themes/mytheme",
        ] {
            fs::create_dir_all(project.join(sub)).unwrap();
        }
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("file.txt"), "user data").unwrap();
        fs::write(docroot.join("version.php"), version_php(installed)).unwrap();
        fs::write(docroot.join("occ"), "<?php").unwrap();
        fs::write(docroot.join("index.php"), "<?php // old").unwrap();
        fs::write(docroot.join("old-only.php"), "gone after the update").unwrap();
        fs::write(docroot.join("lib/base.php"), "OLD").unwrap();
        fs::write(docroot.join(".user.ini"), "site-ini").unwrap();
        fs::write(docroot.join("custom_apps/myapp/app.php"), "mine").unwrap();
        fs::write(docroot.join("themes/mytheme/t.css"), "mine").unwrap();
        fs::write(
            docroot.join("config/config.php"),
            CONFIG.replace("@DATA@", data.to_str().unwrap()),
        )
        .unwrap();
        fs::write(dir.path().join("db"), "orig-db\n").unwrap();
        let docker = dir.path().join("docker");
        fs::write(
            &docker,
            FAKE_DOCKER.replace("@S@", dir.path().to_str().unwrap()),
        )
        .unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(dir.path().join("state")).unwrap();
        fs::create_dir_all(dir.path().join("backups")).unwrap();
        let fx = Self {
            dir,
            project,
            docroot,
            data,
            target: target.to_owned(),
            archive: Default::default(),
            sha: Default::default(),
            fetched: Cell::new(0),
            fetch_fails: Cell::new(false),
            tar: RefCell::new("tar".into()),
        };
        fx.build_archive("nextcloud", target);
        fx
    }

    /// The release archive: `top/` with `version.php` of `version`.
    fn build_archive(&self, top: &str, version: &str) {
        let src = self.path("src");
        let _ = fs::remove_dir_all(&src);
        let tree = src.join(top);
        fs::create_dir_all(tree.join("lib")).unwrap();
        fs::create_dir_all(tree.join("config")).unwrap();
        fs::write(tree.join("version.php"), version_php(version)).unwrap();
        fs::write(tree.join("index.php"), "<?php // new").unwrap();
        fs::write(tree.join("occ"), "<?php // new").unwrap();
        fs::write(tree.join(".user.ini"), "nextcloud-ini").unwrap();
        fs::write(tree.join("lib/base.php"), "NEW").unwrap();
        fs::write(tree.join("config/config.sample.php"), "<?php").unwrap();
        let out = std::process::Command::new("tar")
            .env("COPYFILE_DISABLE", "1")
            .arg("-cjf")
            .arg(self.path("archive"))
            .arg("-C")
            .arg(&src)
            .arg(top)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let bytes = fs::read(self.path("archive")).unwrap();
        *self.sha.borrow_mut() = crate::util::sha256_hex(&bytes);
        *self.archive.borrow_mut() = bytes;
    }

    fn url(&self) -> String {
        format!(
            "https://download.nextcloud.com/server/releases/nextcloud-{}.tar.bz2",
            self.target
        )
    }

    fn plan(&self, extra: &str) -> String {
        let meta = fs::metadata(&self.project).unwrap();
        format!(
            r#"{{"container":"runtime-1","projectRoot":"{}","documentRoot":"{}","uid":{},"gid":{}{extra}}}"#,
            self.project.display(),
            self.docroot.display(),
            meta.uid(),
            meta.gid()
        )
    }

    fn archive_extra(&self) -> String {
        format!(
            r#","archive":{{"url":"{}","sha256":"{}"}}"#,
            self.url(),
            self.sha.borrow()
        )
    }

    fn update(&self, id: &str) -> Result<UpdateResult, Error> {
        self.update_keyed(id, None)
    }

    fn update_keyed(&self, id: &str, key: Option<&str>) -> Result<UpdateResult, Error> {
        let req =
            Request::parse("update-core", &self.plan(&self.archive_extra()), id, key).unwrap();
        self.execute(&req)
    }

    fn restore(&self, id: &str, recovery: &str) -> Result<UpdateResult, Error> {
        let extra = format!(r#","recoveryId":"{recovery}""#);
        let req = Request::parse("restore-update", &self.plan(&extra), id, None).unwrap();
        self.execute(&req)
    }

    fn execute(&self, req: &Request) -> Result<UpdateResult, Error> {
        let state = managed(&self.path("state"));
        let backups = managed(&self.path("backups"));
        let docker = self.path("docker");
        let tar = self.tar.borrow().clone();
        let fetch = |_: &str, max: u64, _: Duration| {
            self.fetched.set(self.fetched.get() + 1);
            if self.fetch_fails.get() {
                return Err(crate::engine::fetch::Error::Status(404));
            }
            let bytes = std::io::Cursor::new(self.archive.borrow().clone());
            Ok(Box::new(std::io::Read::take(bytes, max)) as Box<dyn std::io::Read>)
        };
        execute(
            &Context {
                engine_state: &state,
                docker_program: docker.to_str().unwrap(),
                tar_program: &tar,
                tools_dir: self.dir.path(),
                backup_root: &backups,
                backup_path: &self.path("backups"),
                fetch: &fetch,
            },
            req,
            &CancellationToken::default(),
        )
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.path("calls.log")).unwrap_or_default()
    }

    fn db(&self) -> String {
        fs::read_to_string(self.path("db")).unwrap_or_default()
    }

    fn installed(&self) -> String {
        let text = fs::read_to_string(self.docroot.join("version.php")).unwrap();
        text.split('\'').nth(1).unwrap().to_owned()
    }

    fn maintenance(&self) -> bool {
        self.docroot.join("config/maint.flag").exists()
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.docroot.join(relative)).unwrap_or_else(|_| "<missing>".into())
    }

    fn steps(&self, id: &str) -> Vec<Step> {
        let text = fs::read_to_string(
            self.path("backups")
                .join(BUNDLES_DIR)
                .join(id)
                .join("steps.json"),
        )
        .unwrap_or_default();
        steps::Journal::parse(&text)
            .map(|journal| journal.steps.iter().map(|entry| entry.step).collect())
            .unwrap_or_default()
    }

    fn bundle_dir(&self, id: &str) -> PathBuf {
        self.path("backups").join(BUNDLES_DIR).join(id)
    }

    fn staging_left(&self) -> Vec<String> {
        fs::read_dir(&self.project)
            .unwrap()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.starts_with(STAGING_PREFIX))
            .collect()
    }

    /// The site is exactly as the fixture made it.
    fn assert_untouched(&self, installed: &str) {
        assert_eq!(self.installed(), installed);
        assert_eq!(self.read("lib/base.php"), "OLD");
        assert_eq!(self.read("old-only.php"), "gone after the update");
        assert_eq!(self.read(".user.ini"), "site-ini");
        assert_eq!(self.read("custom_apps/myapp/app.php"), "mine");
        assert_eq!(self.read("themes/mytheme/t.css"), "mine");
        assert!(self.read("config/config.php").contains(DB_PASSWORD));
        assert_eq!(self.db(), "orig-db\n");
        assert!(!self.maintenance());
        assert_eq!(
            fs::read_to_string(self.data.join("file.txt")).unwrap(),
            "user data"
        );
        assert!(self.staging_left().is_empty(), "{:?}", self.staging_left());
    }

    /// Nothing was changed and no bundle exists.
    fn assert_refused_early(&self, installed: &str) {
        self.assert_untouched(installed);
        assert!(!self.path("backups").join(BUNDLES_DIR).exists());
        let calls = self.calls();
        assert!(!calls.contains("maintenance:mode"), "{calls}");
        assert!(!calls.contains("upgrade"), "{calls}");
        assert!(!calls.contains("mariadb-dump"), "{calls}");
    }
}

fn config_replace(fx: &Fx, from: &str, to: &str) {
    let path = fx.docroot.join("config/config.php");
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains(from), "{from}");
    fs::write(path, text.replace(from, to)).unwrap();
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

// ── Requests ─────────────────────────────────────────────────────────────

#[test]
fn requests_have_exactly_one_shape_per_kind() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let archive = fx.archive_extra();
    let recovery = format!(r#","recoveryId":"{A}""#);
    assert!(Request::parse("update-core", &fx.plan(&archive), A, None).is_ok());
    let restore = Request::parse("restore-update", &fx.plan(&recovery), B, None).unwrap();
    assert_eq!(restore.operation(), RESTORE);
    assert_eq!(restore.root(), fx.project);
    for (kind, extra) in [
        ("update-core", String::new()),
        ("update-core", format!("{archive}{recovery}")),
        ("restore-update", String::new()),
        ("restore-update", format!("{recovery}{archive}")),
        ("restore-update", r#","recoveryId":"../x""#.to_owned()),
        ("update-extensions", archive.clone()),
        ("update-core", format!(r#"{archive},"version":"36.0.0""#)),
    ] {
        assert!(
            Request::parse(kind, &fx.plan(&extra), A, None).is_err(),
            "{kind} {extra}"
        );
    }
}

#[test]
fn only_a_nextcloud_release_archive_with_a_sha256_is_accepted() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let sha = "a".repeat(64);
    let good = "https://download.nextcloud.com/server/releases/nextcloud-35.0.4.tar.bz2";
    let parse = |url: &str, sha: &str| {
        Request::parse(
            "update-core",
            &fx.plan(&format!(r#","archive":{{"url":"{url}","sha256":"{sha}"}}"#)),
            A,
            None,
        )
    };
    assert!(parse(good, &sha).is_ok());
    for (url, digest) in [
        (good, "A".repeat(64)),
        (good, "a".repeat(63)),
        (good, String::new()),
        (
            "https://evil.org/server/releases/nextcloud-35.0.4.tar.bz2",
            sha.clone(),
        ),
        (
            "https://download.nextcloud.com/server/releases/nextcloud-latest.tar.bz2",
            sha.clone(),
        ),
        (
            "http://download.nextcloud.com/server/releases/nextcloud-35.0.4.tar.bz2",
            sha.clone(),
        ),
    ] {
        assert_eq!(
            parse(url, &digest).err(),
            Some(RequestError::InvalidArchive),
            "{url} {digest}"
        );
    }
    assert_eq!(archive_version(good).as_deref(), Some("35.0.4"));
}

#[test]
fn the_code_directory_must_be_one_directory_below_the_project() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let plan = |project: &str, docroot: &str| {
        format!(
            r#"{{"container":"runtime-1","projectRoot":"{project}","documentRoot":"{docroot}","uid":1,"gid":1{}}}"#,
            fx.archive_extra()
        )
    };
    assert!(
        Request::parse(
            "update-core",
            &plan("/var/www/s", "/var/www/s/public"),
            A,
            None
        )
        .is_ok()
    );
    for (project, docroot) in [
        ("/var/www/s", "/var/www/s"),
        ("/var/www/s", "/var/www/s/a/b"),
        ("/var/www/s", "/var/www/other/public"),
        ("/var/www/s", "/var/www/s/../public"),
        ("/var/www/s", "public"),
        ("var/www/s", "/var/www/s/public"),
    ] {
        assert!(
            Request::parse("update-core", &plan(project, docroot), A, None).is_err(),
            "{project} {docroot}"
        );
    }
}

// ── Reading config.php, status and versions ──────────────────────────────

fn config_with(extra: &str) -> String {
    format!(
        "<?php\n$CONFIG = array (\n  'datadirectory' => '/srv/data',\n  'dbtype' => 'mysql',\n  \
         'dbname' => 'nc',\n  'dbhost' => 'wcp-db',\n  'dbuser' => 'u',\n  'dbpassword' => \
         'p\\'w',\n{extra});\n"
    )
}

#[test]
fn the_database_comes_from_config_php_and_only_a_container_mariadb_is_accepted() {
    let db = db_connection(&config_with("")).unwrap();
    assert_eq!(
        (db.host.as_str(), db.user.as_str(), db.password.as_str()),
        ("wcp-db", "u", "p'w")
    );
    assert_eq!(db.database, "nc");
    let port = db_connection(&config_with("").replace("'wcp-db'", "'wcp-db:3306'")).unwrap();
    assert_eq!(port.host, "wcp-db");
    for (from, to) in [
        ("'mysql'", "'pgsql'"),
        ("'mysql'", "'sqlite3'"),
        ("'mysql'", "'oci'"),
        ("'wcp-db'", "'localhost'"),
        ("'wcp-db'", "'localhost:/var/run/mysqld.sock'"),
        ("'wcp-db'", "'wcp-db:port'"),
        ("'wcp-db'", "'wcp-db:123456'"),
        ("'wcp-db'", "'10.0.0.1:3306'"),
        ("'wcp-db'", "''"),
        ("'u'", "'-x'"),
        ("'u'", "''"),
        ("'nc'", "'-x'"),
        ("  'dbtype' => 'mysql',\n", ""),
        ("  'dbname' => 'nc',\n", ""),
    ] {
        let text = config_with("").replace(from, to);
        assert!(
            matches!(db_connection(&text), Err(Error::UnsupportedDatabase)),
            "{from} -> {to}"
        );
    }
    // A key twice is not guessed at.
    assert!(db_connection(&config_with("  'dbtype' => 'mysql',\n")).is_err());
}

#[test]
fn only_top_level_keys_of_config_php_are_read() {
    let text = "<?php\n$CONFIG = array (\n  'a' => 'x',\n  'nested' => \n  array (\n    'a' => 'y',\n  ),\n  'b' => true,\n  'c' => 'with, comma',\n);\n";
    assert_eq!(config_raw(text, "a"), Some("'x'"));
    assert_eq!(config_raw(text, "b"), Some("true"));
    assert_eq!(config_string(text, "c").as_deref(), Some("with, comma"));
    assert_eq!(config_raw(text, "missing"), None);
    assert_eq!(config_string(text, "b"), None, "not a string");
}

#[test]
fn the_data_directory_must_lie_outside_the_code_directory() {
    let docroot = Path::new("/var/www/s/public");
    let with = |dir: &str| format!("  'datadirectory' => '{dir}',\n");
    assert!(data_dir_outside(&with("/var/www/s-data"), docroot).is_ok());
    assert!(
        data_dir_outside(&with("/var/www/s"), docroot).is_err(),
        "parent"
    );
    assert!(data_dir_outside(&with("/var/www/s/public/data"), docroot).is_err());
    assert!(data_dir_outside(&with("/var/www/s/public"), docroot).is_err());
    assert!(
        data_dir_outside(&with("data"), docroot).is_err(),
        "relative"
    );
    assert!(data_dir_outside(&with("/var/www/../s/public/x"), docroot).is_err());
    assert!(data_dir_outside("", docroot).is_err(), "unnamed");
}

#[test]
fn a_status_is_read_only_from_an_installed_site_with_clear_fields() {
    let ok = r#"{"installed":true,"version":"35.0.3.2","versionstring":"35.0.3","maintenance":false,"needsDbUpgrade":false}"#;
    assert_eq!(
        parse_status(&format!("note\n{ok}\n")),
        Some(Status {
            version: "35.0.3".into(),
            maintenance: false,
            upgrade_pending: Some(false)
        })
    );
    assert_eq!(
        parse_status(r#"{"installed":true,"versionstring":"35.0.3","maintenance":true}"#),
        Some(Status {
            version: "35.0.3".into(),
            maintenance: true,
            upgrade_pending: None
        })
    );
    for bad in [
        "",
        "installed",
        r#"{"installed":false,"versionstring":"35.0.3","maintenance":false}"#,
        r#"{"installed":true,"maintenance":false}"#,
        r#"{"installed":true,"versionstring":"35.0.3"}"#,
        r#"{"installed":true,"versionstring":"35.0.3","maintenance":"no"}"#,
        r#"{"installed":true,"versionstring":"x; ls","maintenance":false}"#,
        r#"{"installed":true,"versionstring":"35.0.3","maintenance":false,"needsDbUpgrade":"?"}"#,
    ] {
        assert_eq!(parse_status(bad), None, "{bad}");
    }
}

#[test]
fn only_a_newer_version_of_this_or_the_next_major_is_a_target() {
    for (installed, target, ok) in [
        ("35.0.3", "35.0.4", true),
        ("35.0.3", "35.1.0", true),
        ("35.0.3", "36.0.0", true),
        ("35.0.3", "36.2.7", true),
        ("9.0.9", "10.0.0", true),
        ("35.0.3", "35.0.3", false),
        ("35.0.3", "35.0.2", false),
        ("35.1.0", "35.0.9", false),
        ("35.0.3", "34.9.9", false),
        ("35.0.3", "37.0.0", false),
        ("35.0.3", "38.0.0", false),
        ("33.0.9", "35.0.0", false),
    ] {
        let verdict = check_target(installed, target);
        assert_eq!(verdict.is_ok(), ok, "{installed} -> {target}: {verdict:?}");
    }
    assert!(matches!(
        check_target("35.0.3", "35.0.3"),
        Err(Error::NothingToUpdate)
    ));
    assert!(matches!(
        check_target("35.0.3", "35.0.2"),
        Err(Error::Downgrade)
    ));
    assert!(matches!(
        check_target("35.0.3", "37.0.0"),
        Err(Error::MajorSkip)
    ));
    assert!(matches!(
        check_target("x", "35.0.3"),
        Err(Error::VersionUnreadable)
    ));
    assert_eq!(numbers("35.0.3-rc1"), Some([35, 0, 3, 0]));
    assert_eq!(numbers("35"), None);
    assert_eq!(numbers("1.2.3.4.5"), None);
}

// ── Updates ──────────────────────────────────────────────────────────────

#[test]
fn an_update_replaces_the_code_keeps_what_the_site_owns_and_leaves_no_secret() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let result = fx.update(A).unwrap();
    assert_eq!(result.outcome, "updated");
    assert_eq!(result.recovery_id, A);
    assert_eq!(result.reason, None);
    assert_eq!(
        (
            result.version_before.as_str(),
            result.version_after.as_str()
        ),
        ("35.0.3", "35.0.4")
    );
    assert_eq!(fx.installed(), "35.0.4");
    assert_eq!(fx.read("lib/base.php"), "NEW");
    assert_eq!(fx.read("index.php"), "<?php // new");
    assert_eq!(fx.read("old-only.php"), "<missing>");
    // The site's own: config, custom apps, themes, `.user.ini` (not the release's).
    assert_eq!(fx.read(".user.ini"), "site-ini");
    assert_eq!(fx.read("custom_apps/myapp/app.php"), "mine");
    assert_eq!(fx.read("themes/mytheme/t.css"), "mine");
    assert_eq!(fx.read("config/config.sample.php"), "<missing>");
    assert!(fx.read("config/config.php").contains(DB_PASSWORD));
    assert!(!fx.maintenance());
    assert_eq!(fx.db(), "upgraded\n");
    assert_eq!(
        fs::read_to_string(fx.data.join("file.txt")).unwrap(),
        "user data"
    );
    assert!(fx.staging_left().is_empty());
    assert_eq!(fx.fetched.get(), 1);
    assert_eq!(
        fx.steps(A),
        [
            Step::Bundled,
            Step::MaintenanceOn,
            Step::CodeReplaced,
            Step::Updated,
            Step::Probed,
            Step::Finished
        ]
    );
    // The order of the commands: dump, maintenance on, upgrade, maintenance off.
    let calls = fx.calls();
    let at = |needle: &str| {
        calls
            .find(needle)
            .unwrap_or_else(|| panic!("{needle}\n{calls}"))
    };
    assert!(at("mariadb-dump") < at("maintenance:mode --on"));
    assert!(at("maintenance:mode --on") < at("occ --no-warnings upgrade"));
    assert!(at("occ --no-warnings upgrade") < at("maintenance:mode --off"));
    // The database password travelled only in the environment of the dump.
    assert_eq!(
        fs::read_to_string(fx.path("env.log")).unwrap().trim(),
        DB_PASSWORD
    );
    assert!(!calls.contains(DB_PASSWORD));
    // It is in no state, journal, audit or result file either.
    for root in ["state", "backups"] {
        for entry in walk(&fx.path(root)) {
            if entry.ends_with("files.tar.gz") {
                continue;
            }
            let text = fs::read_to_string(&entry).unwrap_or_default();
            assert!(!text.contains(DB_PASSWORD), "{}", entry.display());
        }
    }
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains(DB_PASSWORD)
    );
    // The bundle holds what the rollback needs.
    for file in [
        "files.tar.gz",
        "database.sql",
        "manifest.json",
        "steps.json",
    ] {
        assert!(fx.bundle_dir(A).join(file).is_file(), "{file}");
    }
}

#[test]
fn a_site_that_was_in_maintenance_stays_there() {
    let fx = Fx::new("35.0.3", "35.0.4");
    fs::write(fx.docroot.join("config/maint.flag"), "").unwrap();
    let result = fx.update(A).unwrap();
    assert_eq!(result.outcome, "updated");
    assert!(fx.maintenance(), "still in maintenance");
    let calls = fx.calls();
    assert!(!calls.contains("maintenance:mode"), "{calls}");
    assert_eq!(fx.installed(), "35.0.4");
}

#[test]
fn a_failing_upgrade_is_rolled_back_to_the_old_site_and_database() {
    let fx = Fx::new("35.0.3", "35.0.4");
    fx.flag("fail-upgrade");
    let result = fx.update(A).unwrap();
    assert_eq!(result.outcome, "rolledBack");
    assert_eq!(
        result.reason.as_deref(),
        Some("occ upgrade: Nextcloud reported an error")
    );
    assert_eq!(result.version_after, "35.0.3");
    fx.assert_untouched("35.0.3");
    assert_eq!(
        fx.steps(A),
        [
            Step::Bundled,
            Step::MaintenanceOn,
            Step::CodeReplaced,
            Step::RollbackStarted,
            Step::FilesRestored,
            Step::DatabaseRestored,
            Step::RolledBack
        ]
    );
    // The result and the reason carry no tool output and no secret.
    let text = serde_json::to_string(&result).unwrap();
    assert!(
        !text.contains(DB_PASSWORD) && !text.contains("partial"),
        "{text}"
    );
}

#[test]
fn a_maintenance_mode_that_will_not_go_off_rolls_the_update_back() {
    let fx = Fx::new("35.0.3", "35.0.4");
    fx.flag("maint-stuck");
    let result = fx.update(A).unwrap();
    assert_eq!(result.outcome, "rolledBack");
    assert_eq!(
        result.reason.as_deref(),
        Some("the maintenance mode could not be set")
    );
    // The restored config.php has the site out of maintenance again.
    fx.assert_untouched("35.0.3");
}

#[test]
fn a_rollback_that_cannot_be_proved_is_recovery_required_and_the_bundle_stays() {
    let fx = Fx::new("35.0.3", "35.0.4");
    fx.flag("fail-upgrade");
    fx.flag("fail-import");
    let error = fx.update(A).unwrap_err();
    let (code, message) = error.protocol();
    assert_eq!(code, ErrorCode::SubprocessFailed);
    assert!(message.starts_with("recovery required:"), "{message}");
    assert!(message.contains(A), "names the recovery id: {message}");
    assert!(!message.contains(DB_PASSWORD));
    assert!(fx.bundle_dir(A).join("manifest.json").is_file());
    assert_eq!(fx.steps(A).last(), Some(&Step::FilesRestored));
    // Hands (or a later `restoreUpdate`) finish it.
    fs::remove_file(fx.path("fail-import")).unwrap();
    fs::remove_file(fx.path("fail-upgrade")).unwrap();
    let restored = fx.restore(B, A).unwrap();
    assert_eq!(restored.outcome, "restored");
    assert_eq!(restored.recovery_id, A);
    fx.assert_untouched("35.0.3");
    assert_eq!(fx.steps(A).last(), Some(&Step::RolledBack));
}

#[test]
fn a_rollback_whose_probe_fails_is_recovery_required() {
    let fx = Fx::new("35.0.3", "35.0.4");
    assert_eq!(fx.update(A).unwrap().outcome, "updated");
    // After the restore the status is not usable: nothing is "fine" by default.
    fx.flag("status-garbage");
    let error = fx.restore(B, A).unwrap_err();
    let (_, message) = error.protocol();
    assert!(
        message.contains("after restoring: Nextcloud did not report a usable status"),
        "{message}"
    );
    assert_eq!(fx.steps(A).last(), Some(&Step::DatabaseRestored));
}

#[test]
fn restoring_a_kept_bundle_puts_the_old_site_back() {
    let fx = Fx::new("35.0.3", "35.0.4");
    assert_eq!(fx.update(A).unwrap().outcome, "updated");
    let restored = fx.restore(B, A).unwrap();
    assert_eq!(restored.outcome, "restored");
    assert_eq!(restored.version_after, "35.0.3");
    fx.assert_untouched("35.0.3");
}

#[test]
fn a_missing_or_tampered_bundle_changes_nothing() {
    let fx = Fx::new("35.0.3", "35.0.4");
    assert!(matches!(
        fx.restore(B, A).unwrap_err(),
        Error::BundleMissing
    ));
    assert_eq!(fx.update(A).unwrap().outcome, "updated");
    for (n, file) in ["files.tar.gz", "database.sql"].into_iter().enumerate() {
        let path = fx.bundle_dir(A).join(file);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"tampered").unwrap();
        let id = format!("123e4567-e89b-12d3-a456-4266141741{n:02}");
        assert!(
            matches!(fx.restore(&id, A).unwrap_err(), Error::BundleCorrupt),
            "{file}"
        );
        assert_eq!(fx.read("lib/base.php"), "NEW", "{file}: files untouched");
        assert_eq!(fx.db(), "upgraded\n", "{file}: database untouched");
        fs::write(&path, original).unwrap();
    }
    // A bundle of another code directory is not restored here.
    let manifest_path = fx.bundle_dir(A).join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    fs::write(
        &manifest_path,
        manifest.replace(&fx.docroot.display().to_string(), "/var/www/else/public"),
    )
    .unwrap();
    assert!(matches!(
        fx.restore(C, A).unwrap_err(),
        Error::BundleCorrupt
    ));
}

// ── Refused before anything changes ──────────────────────────────────────

#[test]
fn a_database_that_cannot_be_backed_up_is_refused_before_anything_changes() {
    for (from, to) in [
        ("'mysql'", "'pgsql'"),
        ("'wcp-db:3306'", "'localhost'"),
        ("'wcp-db:3306'", "'wcp-db:/sock'"),
    ] {
        let fx = Fx::new("35.0.3", "35.0.4");
        config_replace(&fx, from, to);
        let error = fx.update(A).unwrap_err();
        assert!(
            matches!(error, Error::UnsupportedDatabase),
            "{to}: {error:?}"
        );
        assert!(error.protocol().1.contains("nothing was changed"));
        assert_eq!(fx.fetched.get(), 0, "{to}: nothing downloaded");
        fx.assert_refused_early("35.0.3");
        assert!(!fx.calls().contains("occ"), "{to}");
    }
}

#[test]
fn a_data_directory_inside_the_code_directory_is_refused() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let inside = format!("{}/data", fx.docroot.display());
    config_replace(&fx, fx.data.to_str().unwrap(), &inside);
    assert!(matches!(
        fx.update(A).unwrap_err(),
        Error::UnsupportedDataDir
    ));
    assert_eq!(fx.fetched.get(), 0);
}

#[test]
fn a_directory_that_is_not_nextcloud_is_refused() {
    for missing in ["occ", "version.php", "config/config.php"] {
        let fx = Fx::new("35.0.3", "35.0.4");
        fs::remove_file(fx.docroot.join(missing)).unwrap();
        assert!(
            matches!(fx.update(A).unwrap_err(), Error::NotNextcloud),
            "{missing}"
        );
        assert_eq!(fx.fetched.get(), 0);
    }
    let fx = Fx::new("35.0.3", "35.0.4");
    fs::write(fx.docroot.join("version.php"), "<?php // no version").unwrap();
    assert!(matches!(
        fx.update(A).unwrap_err(),
        Error::VersionUnreadable
    ));
}

#[test]
fn a_status_that_is_not_clear_is_unknown_and_refused() {
    for flag in ["status-fail", "status-garbage", "pending"] {
        let fx = Fx::new("35.0.3", "35.0.4");
        fx.flag(flag);
        let error = fx.update(A).unwrap_err();
        assert!(matches!(error, Error::StatusUnclear), "{flag}: {error:?}");
        assert_eq!(fx.fetched.get(), 0, "{flag}");
        fx.assert_refused_early("35.0.3");
    }
}

#[test]
fn the_same_an_older_and_a_skipped_major_version_are_refused_before_the_download() {
    for (installed, target, expected) in [
        ("35.0.4", "35.0.4", "already at the pinned version"),
        ("35.0.5", "35.0.4", "older than the installed one"),
        ("34.0.1", "36.0.0", "skips a major version"),
    ] {
        let fx = Fx::new(installed, target);
        let error = fx.update(A).unwrap_err();
        assert!(error.protocol().1.contains(expected), "{target}: {error:?}");
        assert_eq!(fx.fetched.get(), 0, "{target}: nothing downloaded");
        fx.assert_refused_early(installed);
    }
    // One major ahead is fine.
    let fx = Fx::new("34.0.1", "35.0.0");
    assert_eq!(fx.update(A).unwrap().outcome, "updated");
}

#[test]
fn a_bad_archive_is_refused_before_the_site_is_touched() {
    // The download does not hash to the pin.
    let fx = Fx::new("35.0.3", "35.0.4");
    *fx.sha.borrow_mut() = "0".repeat(64);
    assert!(matches!(fx.update(A).unwrap_err(), Error::ArchiveDigest));
    fx.assert_refused_early("35.0.3");
    let leftovers: Vec<_> = walk(&fx.path("state"))
        .into_iter()
        .filter(|path| path.to_string_lossy().contains("download-nc-update"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // The server does not answer.
    let fx = Fx::new("35.0.3", "35.0.4");
    fx.fetch_fails.set(true);
    assert!(matches!(
        fx.update(A).unwrap_err(),
        Error::ArchiveFetch(ErrorCode::ArtifactFetchFailed)
    ));
    fx.assert_refused_early("35.0.3");

    // Not a `nextcloud/` tree, or not the release the URL names.
    let fx = Fx::new("35.0.3", "35.0.4");
    fx.build_archive("elsewhere", "35.0.4");
    assert!(matches!(fx.update(A).unwrap_err(), Error::ArchiveInvalid));
    fx.assert_refused_early("35.0.3");
    let fx = Fx::new("35.0.3", "35.0.4");
    fx.build_archive("nextcloud", "35.0.9");
    assert!(matches!(fx.update(A).unwrap_err(), Error::ArchiveInvalid));
    fx.assert_refused_early("35.0.3");
    // Garbage that hashes to its pin.
    let fx = Fx::new("35.0.3", "35.0.4");
    *fx.archive.borrow_mut() = b"not an archive".to_vec();
    *fx.sha.borrow_mut() = crate::util::sha256_hex(b"not an archive");
    assert!(matches!(fx.update(A).unwrap_err(), Error::ArchiveUnsafe));
    fx.assert_refused_early("35.0.3");
}

#[test]
fn a_bundle_that_cannot_be_written_changes_nothing() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let tar = fx.path("tar-broken");
    fs::write(&tar, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&tar, fs::Permissions::from_mode(0o755)).unwrap();
    *fx.tar.borrow_mut() = tar.display().to_string();
    assert!(matches!(fx.update(A).unwrap_err(), Error::BundleFailed));
    fx.assert_untouched("35.0.3");
    let calls = fx.calls();
    assert!(!calls.contains("maintenance:mode"), "{calls}");
    assert!(!fx.bundle_dir(A).join("manifest.json").exists());
}

// ── Replay ───────────────────────────────────────────────────────────────

#[test]
fn a_key_that_was_used_gives_the_same_answer_without_running_again() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let first = fx.update_keyed(A, Some("update-key-1")).unwrap();
    let calls = fx.calls();
    let again = fx.update_keyed(B, Some("update-key-1")).unwrap();
    assert_eq!(again.recovery_id, first.recovery_id);
    assert_eq!(again.outcome, "updated");
    assert_eq!(fx.fetched.get(), 1, "downloaded once");
    assert_eq!(fx.calls(), calls, "nothing ran the second time");
    assert!(!fx.bundle_dir(B).exists());
}

#[test]
fn a_failed_request_is_replayed_as_the_same_failure() {
    let fx = Fx::new("35.0.4", "35.0.4");
    let first = fx.update_keyed(A, Some("update-key-2")).unwrap_err();
    assert!(matches!(first, Error::NothingToUpdate));
    let again = fx.update_keyed(B, Some("update-key-2")).unwrap_err();
    match again {
        Error::Replayed { code, message } => {
            assert_eq!(code, ErrorCode::InvalidInput);
            assert!(message.contains("already at the pinned version"));
        }
        other => panic!("{other:?}"),
    }
}

// ── Interrupted updates ──────────────────────────────────────────────────

/// Runs the update until the "process" dies right after `step` is written.
fn die_after(fx: &Fx, id: &str, step: Step) {
    DIE_AFTER.with(|die| die.set(Some(step)));
    let died = catch_unwind(AssertUnwindSafe(|| fx.update(id)));
    DIE_AFTER.with(|die| die.set(None));
    assert!(died.is_err(), "the update should have died after {step:?}");
    assert_eq!(fx.steps(id).last(), Some(&step));
}

/// The next request of the project: the release cannot be fetched, so it ends
/// after the reconciliation and shows only what that did.
fn next_request(fx: &Fx, id: &str) -> Error {
    fx.fetch_fails.set(true);
    let error = fx.update(id).unwrap_err();
    fx.fetch_fails.set(false);
    error
}

#[test]
fn the_next_request_rolls_back_an_update_that_died_after_any_step() {
    for step in [
        Step::Bundled,
        Step::MaintenanceOn,
        Step::CodeReplaced,
        Step::Updated,
        Step::Probed,
    ] {
        let fx = Fx::new("35.0.3", "35.0.4");
        die_after(&fx, A, step);
        // Maintenance is on between its step and the `--off` before the probe.
        let on = matches!(
            step,
            Step::MaintenanceOn | Step::CodeReplaced | Step::Updated
        );
        assert_eq!(fx.maintenance(), on, "{step:?}");
        let error = next_request(&fx, B);
        assert!(
            matches!(error, Error::ArchiveFetch(_)),
            "{step:?}: {error:?}"
        );
        fx.assert_untouched("35.0.3");
        assert_eq!(fx.steps(A).last(), Some(&Step::RolledBack), "{step:?}");
        // The dead request no longer shows as running.
        let record = walk(&fx.path("state/nextcloud-update"))
            .into_iter()
            .find(|path| path.ends_with(format!("transactions/{A}.json")))
            .map(|path| fs::read_to_string(path).unwrap())
            .unwrap();
        assert!(record.contains("\"FAILED\""), "{step:?}: {record}");
    }
}

#[test]
fn the_next_request_finishes_a_rollback_that_died_half_way() {
    for step in [
        Step::RollbackStarted,
        Step::FilesRestored,
        Step::DatabaseRestored,
    ] {
        let fx = Fx::new("35.0.3", "35.0.4");
        fx.flag("fail-upgrade");
        die_after(&fx, A, step);
        fs::remove_file(fx.path("fail-upgrade")).unwrap();
        let error = next_request(&fx, B);
        assert!(
            matches!(error, Error::ArchiveFetch(_)),
            "{step:?}: {error:?}"
        );
        fx.assert_untouched("35.0.3");
        assert_eq!(fx.steps(A).last(), Some(&Step::RolledBack), "{step:?}");
    }
}

#[test]
fn a_finished_update_is_left_alone() {
    let fx = Fx::new("35.0.3", "35.0.4");
    die_after(&fx, A, Step::Finished);
    assert_eq!(fx.installed(), "35.0.4");
    // The pinned release is now the installed one; the old bundle is not used.
    assert!(matches!(fx.update(B).unwrap_err(), Error::NothingToUpdate));
    assert_eq!(fx.installed(), "35.0.4");
    assert_eq!(fx.steps(A).last(), Some(&Step::Finished));
    assert_eq!(fx.db(), "upgraded\n");
}

#[test]
fn an_unreadable_journal_falls_back_to_the_transaction_record() {
    let fx = Fx::new("35.0.3", "35.0.4");
    die_after(&fx, A, Step::CodeReplaced);
    fs::remove_file(fx.bundle_dir(A).join("steps.json")).unwrap();
    let error = next_request(&fx, B);
    assert!(matches!(error, Error::ArchiveFetch(_)), "{error:?}");
    fx.assert_untouched("35.0.3");
}

#[test]
fn a_bundle_that_cannot_be_rolled_back_stops_the_next_request() {
    let fx = Fx::new("35.0.3", "35.0.4");
    die_after(&fx, A, Step::CodeReplaced);
    fs::write(fx.bundle_dir(A).join("files.tar.gz"), "broken").unwrap();
    let before = fx.read("lib/base.php");
    let error = next_request(&fx, B);
    let (_, message) = error.protocol();
    assert!(message.starts_with("recovery required:"), "{message}");
    assert!(message.contains(A), "{message}");
    assert_eq!(fx.read("lib/base.php"), before, "nothing else was changed");
    assert_eq!(fx.fetched.get(), 1, "it stopped before the download");
}

#[test]
fn a_bundle_of_another_code_directory_is_not_touched() {
    let fx = Fx::new("35.0.3", "35.0.4");
    die_after(&fx, A, Step::CodeReplaced);
    let manifest_path = fx.bundle_dir(A).join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    fs::write(
        &manifest_path,
        manifest.replace(&fx.docroot.display().to_string(), "/var/www/else/public"),
    )
    .unwrap();
    // Not rolled back: the site stays as the dead update left it, and the
    // request sees the new version.
    assert!(matches!(next_request(&fx, B), Error::NothingToUpdate));
    assert_eq!(
        fx.read("lib/base.php"),
        "NEW",
        "not rolled back by another site's request"
    );
}

#[test]
fn stale_unpacked_releases_are_removed_by_the_next_request_only() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let stale = fx.project.join(format!("{STAGING_PREFIX}{A}"));
    fs::create_dir_all(stale.join("public")).unwrap();
    fs::create_dir_all(fx.project.join("logs")).unwrap();
    let error = next_request(&fx, B);
    assert!(matches!(error, Error::ArchiveFetch(_)), "{error:?}");
    assert!(!stale.exists());
    assert!(fx.project.join("logs").is_dir(), "other directories stay");
    assert!(fx.project.join("public").is_dir());
}

#[test]
fn a_request_cancelled_before_it_starts_changes_nothing() {
    let fx = Fx::new("35.0.3", "35.0.4");
    let token = CancellationToken::default();
    token.cancel();
    let state = managed(&fx.path("state"));
    let backups = managed(&fx.path("backups"));
    let docker = fx.path("docker");
    let fetch = |_: &str, _: u64, _: Duration| -> Result<Box<dyn std::io::Read>, _> {
        Err(crate::engine::fetch::Error::Status(500))
    };
    let req = Request::parse("update-core", &fx.plan(&fx.archive_extra()), A, None).unwrap();
    let error = execute(
        &Context {
            engine_state: &state,
            docker_program: docker.to_str().unwrap(),
            tar_program: "tar",
            tools_dir: fx.dir.path(),
            backup_root: &backups,
            backup_path: &fx.path("backups"),
            fetch: &fetch,
        },
        &req,
        &token,
    )
    .unwrap_err();
    assert!(matches!(error, Error::Cancelled));
    fx.assert_refused_early("35.0.3");
}
