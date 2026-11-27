//! Recovery-first Nextcloud updates: `nextcloud.updateCore` and
//! `nextcloud.restoreUpdate`, each one lock/idempotency/transaction/audit
//! backed request on a single-site Nextcloud installed by `application.install`
//! (code in `<project>/<document root>`, data directory beside the project).
//!
//! Flow: preflight (no change) -> the pinned release archive is downloaded,
//! verified and unpacked beside the site -> recovery bundle (the code
//! directory with `config/`, a database dump, a manifest with SHA-256 sums,
//! under `nextcloud-updates/<request id>/` in the backup root) -> `occ
//! maintenance:mode --on` -> the code is replaced from the archive (the site's
//! `config/`, `custom_apps/`, `themes/` and `.user.ini` stay) -> `occ upgrade`
//! -> `occ maintenance:mode --off` (only when the site was not in maintenance
//! before) -> probe (`occ status` reports the new version, installed, the
//! earlier maintenance mode and no pending upgrade). A failing step after the
//! bundle is rolled back by the engine itself: the code directory is replaced
//! from the bundle, the database is emptied and re-imported, then the probe
//! runs for the old version. Only a probe that passes after the rollback
//! reports `rolledBack`; anything else is a `recovery required` failure with
//! the bundle kept. `restoreUpdate` runs the same rollback from a kept bundle.
//!
//! What is not touched: the data directory (it has to lie outside the code
//! directory, which is checked before anything changes) and everything outside
//! the code directory. Only MariaDB/MySQL sites are updated; PostgreSQL is
//! refused up front. Secrets: the database password is read from `config.php`
//! only to be put in the environment of one `docker exec` (dump, restore); it
//! is in no argument, journal or result.
//!
//! The recovery shape follows `joomla_update` (same bundle layout, journal
//! and interrupted-update handling, shared database steps in `update_db`).
//! Recorded divergence: the code comes from a pinned archive that the engine
//! downloads (`pinned_download`) instead of the application's own updater;
//! the bundle covers the code directory only (the site root may hold more).
//! The bundle is taken just before maintenance mode goes on, so a change made
//! to the database in that short window is not in the bundle.

use crate::clock::unix_now_secs;
use crate::{
    application_install::{Error as InstallError, nextcloud as install},
    db_restore::{ContainerName, RestoreRequestError},
    drupal_action::{
        self, DbConnection, MAX_OUTPUT, READ_TIMEOUT, RUN_TIMEOUT, UPDATE_TIMEOUT, container_exec,
        exited_ok,
    },
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    pinned_download,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
    site::{SiteRelativePath, TrustedRoot},
    tar_extract,
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
    update_db,
    wordpress_migrate_export::sha256_file,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const CORE: &str = "nextcloud.updateCore";
pub const RESTORE: &str = "nextcloud.restoreUpdate";

/// Recovery bundles are kept this long.
const RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
/// A real `config.php` is a few KiB; anything bigger is not one.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const BUNDLES_DIR: &str = "nextcloud-updates";
/// Directory of the unpacked release, beside the code directory. A leftover
/// of a request that died is removed by the next update of the project.
const STAGING_PREFIX: &str = ".wcp-nc-update-";
/// What stays of the site when the code is replaced.
/// A code directory with a few apps is about 35 000 entries and 800 MB.
const EXTRACT_LIMITS: tar_extract::Limits = tar_extract::Limits {
    max_entries: 500_000,
    max_file_bytes: 4 * 1024 * 1024 * 1024,
};
const KEEP: [&str; 4] = ["config", "custom_apps", "themes", ".user.ini"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Core,
    Restore,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    project_root: String,
    /// The Nextcloud code directory: one directory directly below the project.
    document_root: String,
    uid: u32,
    gid: u32,
    /// `restoreUpdate` only: the request id of the update to undo.
    recovery_id: Option<String>,
    /// `updateCore` only: the pinned release archive.
    archive: Option<ArchivePlan>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchivePlan {
    url: String,
    sha256: String,
}

struct Archive {
    url: String,
    sha256: String,
    /// `X.Y.Z` from the file name of the URL.
    version: String,
}

pub struct Request {
    kind: Kind,
    recovery_id: Option<RequestId>,
    archive: Option<Archive>,
    project_root: PathBuf,
    /// Name of the code directory below the project.
    docroot_name: String,
    uid: u32,
    gid: u32,
    /// The shared container/user request shape of `drupal_action`, with the
    /// Nextcloud code directory as its root (`occ` runs there).
    base: drupal_action::Request,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidRecoveryId,
    InvalidShape,
    InvalidArchive,
    Base(drupal_action::RequestError),
}

impl Request {
    /// `kind` is `update-core` or `restore-update`, as named by the CLI.
    pub fn parse(
        kind: &str,
        json: &str,
        request_id: &str,
        key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let (kind, recovery_id, archive) = match (kind, plan.recovery_id, plan.archive) {
            ("update-core", None, Some(pin)) => {
                let version = install::archive_url_ok(&pin.url)
                    .then(|| archive_version(&pin.url))
                    .flatten()
                    .filter(|_| pinned_download::is_sha256_hex(&pin.sha256))
                    .ok_or(RequestError::InvalidArchive)?;
                (
                    Kind::Core,
                    None,
                    Some(Archive {
                        url: pin.url,
                        sha256: pin.sha256,
                        version,
                    }),
                )
            }
            ("restore-update", Some(id), None) => (
                Kind::Restore,
                Some(RequestId::parse(&id).map_err(|_| RequestError::InvalidRecoveryId)?),
                None,
            ),
            _ => return Err(RequestError::InvalidShape),
        };
        let shape = |project: &str| {
            serde_json::json!({
                "container": plan.container,
                "projectRoot": project,
                "documentRoot": plan.document_root,
                "uid": plan.uid,
                "gid": plan.gid,
            })
            .to_string()
        };
        let parse_base = |project: &str| {
            drupal_action::Request::parse("cache-rebuild", &shape(project), request_id, key)
                .map_err(RequestError::Base)
        };
        // The project validates the document root as being below it; the
        // code directory then is the root of the request `occ` runs in.
        let project = parse_base(&plan.project_root)?;
        let base = parse_base(&plan.document_root)?;
        let docroot = base.root();
        let docroot_name = docroot
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|_| docroot.parent() == Some(project.root()))
            .ok_or(RequestError::Base(drupal_action::RequestError::InvalidRoot))?
            .to_owned();
        let _: ContainerName =
            ContainerName::parse(&plan.container).map_err(|_: RestoreRequestError| {
                RequestError::Base(drupal_action::RequestError::InvalidContainer)
            })?;
        Ok(Self {
            kind,
            recovery_id,
            archive,
            project_root: project.root().to_path_buf(),
            docroot_name,
            uid: plan.uid,
            gid: plan.gid,
            base,
            request_id: RequestId::parse(request_id)
                .map_err(|_| RequestError::Base(drupal_action::RequestError::InvalidRequestId))?,
            idempotency_key: key.map(IdempotencyKey::parse).transpose().map_err(|_| {
                RequestError::Base(drupal_action::RequestError::InvalidIdempotencyKey)
            })?,
        })
    }

    /// The project root: what the request locks and the content-root check
    /// is made against.
    pub fn root(&self) -> &Path {
        &self.project_root
    }

    pub const fn operation(&self) -> &'static str {
        match self.kind {
            Kind::Core => CORE,
            Kind::Restore => RESTORE,
        }
    }
}

/// `35.0.3` of `…/nextcloud-35.0.3.tar.bz2` (the URL already passed
/// `archive_url_ok`).
fn archive_version(url: &str) -> Option<String> {
    url.strip_prefix(install::ARCHIVE_PREFIX)?
        .strip_suffix(".tar.bz2")
        .map(str::to_owned)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResult {
    /// `updated`, `rolledBack` or (restore) `restored`.
    pub outcome: String,
    /// Request id of the update whose bundle holds the recovery data.
    pub recovery_id: String,
    /// Why the update was rolled back (engine-written, no tool output).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub version_before: String,
    pub version_after: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
    pub tar_program: &'a str,
    pub tools_dir: &'a Path,
    pub backup_root: &'a ManagedRoot,
    /// Host path of `backup_root`, for `tar` and checksums.
    pub backup_path: &'a Path,
    /// Streams the pinned archive (`engine::fetch::fetch_reader_bounded`).
    pub fetch: pinned_download::Fetch<'a>,
}

impl<'a> Context<'a> {
    fn action(&self) -> drupal_action::Context<'a> {
        drupal_action::Context {
            engine_state: self.engine_state,
            docker_program: self.docker_program,
            tools_dir: self.tools_dir,
            backup_root: self.backup_root,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    ResourceBusy,
    Cancelled,
    Action(drupal_action::Error),
    Run(process::ProcessRunError),
    /// No `occ`, `version.php` or `config/config.php` in the code directory.
    NotNextcloud,
    UnsupportedDatabase,
    /// The data directory is not named, or lies inside the code directory.
    UnsupportedDataDir,
    VersionUnreadable,
    /// `occ status` did not report an installed, consistent site.
    StatusUnclear,
    /// The pinned release is the installed version.
    NothingToUpdate,
    /// The pinned release is older than the installed version.
    Downgrade,
    /// The pinned release is more than one major version ahead.
    MajorSkip,
    ArchiveFetch(ErrorCode),
    ArchiveDigest,
    ArchiveUnsafe,
    ArchiveInvalid,
    /// The bundle could not be written; nothing was changed.
    BundleFailed,
    BundleMissing,
    BundleCorrupt,
    /// Rolling back did not work out: the site needs `restoreUpdate`, or hands.
    RecoveryRequired(String),
    PostCommit {
        result: Box<UpdateResult>,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        let invalid = |message: &str| (ErrorCode::InvalidInput, message.to_owned());
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (ErrorCode::Cancelled, "cancelled".into()),
            Self::Action(error) => error.protocol(),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run an update step".into(),
            ),
            Self::NotNextcloud => invalid(
                "the code directory has no occ, version.php and config/config.php; nothing was \
                 changed",
            ),
            Self::UnsupportedDatabase => invalid(
                "the site database is not a MySQL/MariaDB one reachable by container name, so a \
                 restorable backup cannot be taken; nothing was changed",
            ),
            Self::UnsupportedDataDir => invalid(
                "the data directory is not named in config.php or lies inside the code \
                 directory; nothing was changed",
            ),
            Self::VersionUnreadable => {
                invalid("the installed Nextcloud version could not be read; nothing was changed")
            }
            Self::StatusUnclear => invalid(
                "Nextcloud did not report an installed site with a clear status (version, \
                 maintenance mode, no pending upgrade); nothing was changed",
            ),
            Self::NothingToUpdate => {
                invalid("Nextcloud is already at the pinned version; nothing was changed")
            }
            Self::Downgrade => invalid(
                "the pinned Nextcloud version is older than the installed one; nothing was \
                 changed",
            ),
            Self::MajorSkip => invalid(
                "the pinned Nextcloud version skips a major version; update one major version at \
                 a time, nothing was changed",
            ),
            Self::ArchiveFetch(code) => (
                *code,
                "the Nextcloud archive could not be downloaded; nothing was changed".into(),
            ),
            Self::ArchiveDigest => invalid(
                "the downloaded Nextcloud archive does not match the pinned checksum; nothing \
                 was changed",
            ),
            Self::ArchiveUnsafe => {
                invalid("the Nextcloud archive was refused as unsafe; nothing was changed")
            }
            Self::ArchiveInvalid => {
                invalid("the Nextcloud archive is not the pinned release; nothing was changed")
            }
            Self::BundleFailed => (
                ErrorCode::Internal,
                "the recovery bundle could not be written; nothing was changed".into(),
            ),
            Self::BundleMissing => (
                ErrorCode::NotFound,
                "no recovery bundle exists for this update (it may have expired)".into(),
            ),
            Self::BundleCorrupt => {
                invalid("the recovery bundle does not match its manifest; nothing was changed")
            }
            Self::RecoveryRequired(why) => (
                ErrorCode::SubprocessFailed,
                format!(
                    "recovery required: {why}. The recovery bundle is kept; run restoreUpdate \
                     with the recovery id of this update"
                ),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal Nextcloud update error".into(),
            ),
        }
    }
}

impl From<drupal_action::Error> for Error {
    fn from(error: drupal_action::Error) -> Self {
        match error {
            drupal_action::Error::Cancelled => Self::Cancelled,
            other => Self::Action(other),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: u32,
    operation: String,
    request_id: String,
    project_root: String,
    document_root: String,
    created_at_unix_secs: u64,
    previous_maintenance: bool,
    version_before: String,
    files_sha256: String,
    database_sha256: String,
}

fn rel(path: impl AsRef<Path>) -> SiteRelativePath {
    SiteRelativePath::parse(path).unwrap()
}

// ── Reading the project ───────────────────────────────────────────────────

/// `config/config.php` of the code directory, read through the open
/// directory (no path is followed): a regular file of bounded size.
fn read_config(doc: &ManagedRoot) -> Result<String, Error> {
    let path = rel("config/config.php");
    let regular = doc
        .symlink_metadata(&path)
        .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_CONFIG_BYTES);
    if !regular {
        return Err(Error::NotNextcloud);
    }
    doc.read_to_string(&path).map_err(|_| Error::NotNextcloud)
}

/// The code directory of the site as an open directory: a real directory
/// directly below the project, never a symlink a tenant swapped in.
fn open_code_dir(project: &ManagedRoot, name: &str) -> Result<ManagedRoot, Error> {
    project
        .open_child_dir_nofollow(&rel(name))
        .map_err(|_| Error::NotNextcloud)
}

fn open_project(req: &Request) -> Result<ManagedRoot, Error> {
    TrustedRoot::parse(&req.project_root)
        .ok()
        .and_then(|root| ManagedRoot::open(&root).ok())
        .ok_or(Error::NotNextcloud)
}

/// The raw text of a top-level `'key' => value,` line of `config.php` (the
/// two-space indent Nextcloud writes). A key that is missing or appears twice
/// is `None`: the file is not read by guessing.
fn config_raw<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let head = format!("  '{key}' => ");
    let mut found = text
        .lines()
        .filter_map(|line| line.strip_prefix(head.as_str()))
        .map(|rest| rest.trim_end().strip_suffix(',').unwrap_or(rest.trim_end()));
    let raw = found.next()?;
    found.next().is_none().then_some(raw)
}

fn config_string(text: &str, key: &str) -> Option<String> {
    crate::joomla_clone::php_string(config_raw(text, key)?)
}

/// The MySQL/MariaDB connection `config.php` names. The host must be the
/// database container's name (a port after a colon is allowed); a socket or
/// an address gives nothing to `docker exec` into.
fn db_connection(config: &str) -> Result<DbConnection, Error> {
    if config_string(config, "dbtype").as_deref() != Some("mysql") {
        return Err(Error::UnsupportedDatabase);
    }
    let read = |key: &str| config_string(config, key).ok_or(Error::UnsupportedDatabase);
    let dbhost = read("dbhost")?;
    let host = match dbhost.rsplit_once(':') {
        Some((host, port))
            if (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            host.to_owned()
        }
        Some(_) => return Err(Error::UnsupportedDatabase),
        None => dbhost,
    };
    let (user, database) = (read("dbuser")?, read("dbname")?);
    let password = read("dbpassword").unwrap_or_default();
    if ContainerName::parse(&host).is_err()
        || host == "localhost"
        || host.parse::<std::net::IpAddr>().is_ok()
        || user.is_empty()
        || database.is_empty()
        || user.starts_with('-')
        || database.starts_with('-')
        || user.chars().chain(database.chars()).any(char::is_control)
    {
        return Err(Error::UnsupportedDatabase);
    }
    Ok(DbConnection {
        host,
        user,
        password,
        database,
    })
}

/// The data directory must be named and outside the code directory: the
/// bundle holds the code directory, and replacing or restoring it must never
/// reach the data.
fn data_dir_outside(config: &str, docroot: &Path) -> Result<(), Error> {
    let data = config_string(config, "datadirectory")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && !path.components().any(|c| c.as_os_str() == ".."))
        .ok_or(Error::UnsupportedDataDir)?;
    if data.starts_with(docroot) || docroot.starts_with(&data) {
        return Err(Error::UnsupportedDataDir);
    }
    Ok(())
}

/// What `occ status --output=json` says, with nothing assumed.
#[derive(Debug, PartialEq, Eq)]
struct Status {
    version: String,
    maintenance: bool,
    /// `needsDbUpgrade`; `None` when this Nextcloud does not report it.
    upgrade_pending: Option<bool>,
}

/// An installed site with a plain version and a boolean maintenance flag; any
/// other answer is `None` (unknown, never "fine").
fn parse_status(stdout: &str) -> Option<Status> {
    if !install::installed(stdout) {
        return None;
    }
    let value = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())?;
    let version = value["versionstring"].as_str()?;
    Some(Status {
        version: crate::joomla_update::plain_version(version).then(|| version.to_owned())?,
        maintenance: value["maintenance"].as_bool()?,
        upgrade_pending: match &value["needsDbUpgrade"] {
            serde_json::Value::Null => None,
            other => Some(other.as_bool()?),
        },
    })
}

/// `35.0.3` -> `[35, 0, 3, 0]`; a suffix after `-` is ignored.
fn numbers(version: &str) -> Option<[u32; 4]> {
    let core = version.split('-').next()?;
    let mut out = [0u32; 4];
    let mut count = 0;
    for part in core.split('.') {
        *out.get_mut(count)? = part.parse().ok()?;
        count += 1;
    }
    (count >= 2).then_some(out)
}

/// The pinned release must be newer than the installed version, in the same
/// major or the next one.
fn check_target(installed: &str, target: &str) -> Result<(), Error> {
    let (from, to) = numbers(installed)
        .zip(numbers(target))
        .ok_or(Error::VersionUnreadable)?;
    match to.cmp(&from) {
        std::cmp::Ordering::Equal => Err(Error::NothingToUpdate),
        std::cmp::Ordering::Less => Err(Error::Downgrade),
        std::cmp::Ordering::Greater if to[0] > from[0].saturating_add(1) => Err(Error::MajorSkip),
        std::cmp::Ordering::Greater => Ok(()),
    }
}

fn occ(
    ctx: &Context<'_>,
    req: &drupal_action::Request,
    args: &[&str],
    timeout: std::time::Duration,
    cancel: &CancellationToken,
) -> Result<process::ProcessOutput, Error> {
    let mut command = vec!["php", "occ", "--no-warnings"];
    command.extend_from_slice(args);
    Ok(container_exec(
        &ctx.action(),
        req,
        &[],
        &command,
        timeout,
        cancel,
    )?)
}

fn read_status(
    ctx: &Context<'_>,
    req: &drupal_action::Request,
    cancel: &CancellationToken,
) -> Option<Status> {
    let output = occ(ctx, req, &["status", "--output=json"], READ_TIMEOUT, cancel).ok()?;
    exited_ok(&output)
        .then(|| parse_status(&output.stdout.text()))
        .flatten()
}

// ── Journal ──────────────────────────────────────────────────────────────

mod steps {
    //! The journal of how far one update got (see `update_steps`). Step names
    //! only: no paths, tool output or secrets. Writing it is best effort; it
    //! is not the recovery data (the bundle is).
    //! `WCP_FAILPOINT=nextcloud-update-after-<step>` kills the process after
    //! a step is written (failpoints feature, tests only).

    use super::{Context, rel};
    use crate::clock::unix_now_secs;
    use crate::transaction::RequestId;
    pub use crate::update_steps::{Journal, Step};

    #[cfg(test)]
    thread_local! {
        /// Unit tests: the "process" dies (panics) once this step is written.
        pub(super) static DIE_AFTER: std::cell::Cell<Option<Step>> =
            const { std::cell::Cell::new(None) };
    }

    fn path(id: RequestId) -> crate::site::SiteRelativePath {
        rel(format!("{}/{id}/steps.json", super::BUNDLES_DIR))
    }

    /// The journal of an update; an absent or unreadable one is `None`.
    pub(super) fn load(ctx: &Context<'_>, id: RequestId) -> Option<Journal> {
        Journal::parse(&ctx.backup_root.read_to_string(&path(id)).ok()?)
    }

    /// Appends `step` to the journal of update `id`, then hits the step's
    /// failpoint. Errors are ignored: the journal is diagnostic.
    pub fn record(ctx: &Context<'_>, id: RequestId, step: Step) {
        let journal = load(ctx, id).unwrap_or_default();
        if let Some(bytes) = journal.with_step(step, unix_now_secs()) {
            let _ = ctx.backup_root.write_atomic(&path(id), &bytes);
        }
        #[cfg(test)]
        if DIE_AFTER.with(|die| die.get()) == Some(step) {
            panic!("the process died after {step:?}");
        }
        crate::failpoint::hit(&step.failpoint("nextcloud"));
    }
}
use steps::{Step, record};

// ── Bundle ───────────────────────────────────────────────────────────────

fn limits() -> ProcessLimits {
    ProcessLimits {
        timeout: UPDATE_TIMEOUT,
        max_stdout_bytes: 0,
        max_stderr_bytes: MAX_OUTPUT,
    }
}

/// The code directory as `tar -C` should open it. On Linux that is the open
/// descriptor itself (`/proc/<pid>/fd/<n>`), so no path is resolved a second
/// time and a tenant cannot swap the directory for a link between the check
/// and tar's start. Elsewhere (development hosts) it is the path, which is
/// refused when it is a link.
fn anchored_dir(
    project: &ManagedRoot,
    req: &Request,
) -> Result<(std::os::fd::OwnedFd, PathBuf), Error> {
    let doc = open_code_dir(project, &req.docroot_name).map_err(|_| Error::BundleFailed)?;
    let fd = doc.try_clone_fd().map_err(|_| Error::BundleFailed)?;
    #[cfg(target_os = "linux")]
    let path = {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            fd.as_raw_fd()
        ))
    };
    #[cfg(not(target_os = "linux"))]
    let path = {
        if !std::fs::symlink_metadata(req.base.root()).is_ok_and(|meta| meta.is_dir()) {
            return Err(Error::BundleFailed);
        }
        req.base.root().to_path_buf()
    };
    Ok((fd, path))
}

fn tar_bundle(
    ctx: &Context<'_>,
    req: &Request,
    project: &ManagedRoot,
    dir: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    // `fd` stays open until tar has finished.
    let (fd, from) = anchored_dir(project, req)?;
    let file = ctx
        .backup_root
        .create_new_file(&rel(format!("{dir}/files.tar.gz")))
        .map_err(|_| Error::BundleFailed)?;
    let output = process::run_with_stdout_file(
        &ProcessRequest::new(ctx.tar_program).args([
            "-C".to_owned(),
            from.display().to_string(),
            "-czpf".into(),
            "-".into(),
            "--numeric-owner".into(),
            ".".into(),
        ]),
        file,
        &limits(),
        cancel,
    )
    .map_err(Error::Run)?;
    drop(fd);
    if !exited_ok(&output) {
        return Err(Error::BundleFailed);
    }
    Ok(())
}

fn bundle(
    ctx: &Context<'_>,
    req: &Request,
    project: &ManagedRoot,
    connection: &DbConnection,
    previous_maintenance: bool,
    version_before: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let dir = format!("{BUNDLES_DIR}/{}", req.request_id);
    ctx.backup_root
        .create_dir_all(&rel(&dir))
        .map_err(|_| Error::BundleFailed)?;
    tar_bundle(ctx, req, project, &dir, cancel)?;
    let file = ctx
        .backup_root
        .create_new_file(&rel(format!("{dir}/database.sql")))
        .map_err(|_| Error::BundleFailed)?;
    update_db::dump(ctx.docker_program, connection, file, &limits(), cancel).map_err(|error| {
        match error {
            update_db::DbError::Run(error) => Error::Run(error),
            update_db::DbError::Failed(_) => Error::BundleFailed,
        }
    })?;
    let bundle_dir = ctx.backup_path.join(&dir);
    let (_, files_sha256) = sha256_file(&bundle_dir.join("files.tar.gz")).map_err(Error::Io)?;
    let (_, database_sha256) = sha256_file(&bundle_dir.join("database.sql")).map_err(Error::Io)?;
    let manifest = Manifest {
        version: 1,
        operation: req.operation().into(),
        request_id: req.request_id.to_string(),
        project_root: req.project_root.display().to_string(),
        document_root: req.base.root().display().to_string(),
        created_at_unix_secs: unix_now_secs(),
        previous_maintenance,
        version_before: version_before.to_owned(),
        files_sha256,
        database_sha256,
    };
    ctx.backup_root
        .create_new(
            &rel(format!("{dir}/manifest.json")),
            &serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .map_err(|_| Error::BundleFailed)?;
    record(ctx, req.request_id, Step::Bundled);
    Ok(())
}

/// Removes bundles older than the retention window. Best effort: a bundle
/// that cannot be removed stays for the next run, and the one belonging to
/// this request is never touched.
fn prune_bundles(ctx: &Context<'_>, keep: RequestId) {
    let Ok(parent) = ctx.backup_root.open_managed_dir(&rel(BUNDLES_DIR)) else {
        return;
    };
    let Ok(children) = parent.child_entries() else {
        return;
    };
    for child in children {
        let Some(name) = child.name.to_str().filter(|n| *n != keep.to_string()) else {
            continue;
        };
        let path = rel(name);
        let old = child.is_dir
            && parent
                .modified(&path)
                .ok()
                .and_then(|time| time.elapsed().ok())
                .is_some_and(|age| age.as_secs() > RETENTION_SECS);
        if old {
            let _ = parent.remove_dir_all(&path);
        }
    }
}

// ── The new code ─────────────────────────────────────────────────────────

fn stage_name(id: RequestId) -> String {
    format!("{STAGING_PREFIX}{id}")
}

/// Downloads and verifies the pinned archive, unpacks it as
/// `<project>/<staging>/public`, checks that it is the pinned version and
/// gives the tree to the site's UID. Nothing of the site is touched; on any
/// failure the staging directory is gone.
fn stage(
    ctx: &Context<'_>,
    req: &Request,
    scope: &ManagedRoot,
    project: &ManagedRoot,
) -> Result<(), Error> {
    let archive = req.archive.as_ref().ok_or(Error::ArchiveInvalid)?;
    let staging = stage_name(req.request_id);
    let download = rel(format!("download-nc-update-{}.tar.bz2", req.request_id));
    let file = pinned_download::download(
        ctx.fetch,
        &archive.url,
        &archive.sha256,
        install::MAX_ARCHIVE_BYTES,
        install::DOWNLOAD_TIMEOUT,
        scope,
        &download,
    )
    .map_err(|error| match error {
        pinned_download::Error::DigestMismatch => Error::ArchiveDigest,
        pinned_download::Error::Fetch(crate::engine::fetch::Error::Timeout) => {
            Error::ArchiveFetch(ErrorCode::Timeout)
        }
        _ => Error::ArchiveFetch(ErrorCode::ArtifactFetchFailed),
    })?;
    let staged = (|| -> Result<(), InstallError> {
        install::unpack(file, project, &staging)?;
        let tree = project
            .open_child_dir_nofollow(&rel(&staging))
            .map_err(InstallError::Io)?;
        if install::version(project, &format!("{staging}/public"))? != archive.version {
            return Err(InstallError::ArchiveInvalid);
        }
        crate::permissions::execute::repair_open_directory(
            &tree.try_clone_fd().map_err(InstallError::Io)?,
            req.uid,
            req.gid,
            &[],
        )
        .map_err(InstallError::Io)?;
        Ok(())
    })()
    .map_err(|error| match error {
        InstallError::ArchiveUnsafe => Error::ArchiveUnsafe,
        InstallError::Io(error) => Error::Io(error),
        _ => Error::ArchiveInvalid,
    });
    let _ = scope.remove_file(&download);
    if staged.is_err() {
        remove_staging(project, &staging);
    }
    staged
}

fn remove_staging(project: &ManagedRoot, staging: &str) {
    let _ = project.remove_dir_all(&rel(staging));
}

/// Replaces the code directory's content with the unpacked release's. What the
/// site owns (`KEEP`) stays; everything else is removed (links are removed,
/// never followed) and the release's entries are moved in. They are already
/// the site user's.
fn replace_code(project: &ManagedRoot, docroot_name: &str, staging: &str) -> Result<(), Error> {
    let doc = project
        .open_child_dir_nofollow(&rel(docroot_name))
        .map_err(Error::Io)?;
    let release = project
        .open_child_dir_nofollow(&rel(staging))
        .and_then(|tree| tree.open_child_dir_nofollow(&rel("public")))
        .map_err(Error::Io)?;
    let kept = |name: &std::ffi::OsStr| KEEP.iter().any(|keep| name == *keep);
    for entry in doc.child_entries().map_err(Error::Io)? {
        if kept(&entry.name) {
            continue;
        }
        let path = rel(&entry.name);
        if entry.is_dir {
            doc.remove_dir_all(&path)
        } else {
            doc.remove_file(&path)
        }
        .map_err(Error::Io)?;
    }
    for entry in release.child_entries().map_err(Error::Io)? {
        if kept(&entry.name) {
            continue;
        }
        let path = rel(&entry.name);
        release.rename_to(&path, &doc, &path).map_err(Error::Io)?;
    }
    Ok(())
}

// ── Update, probe, rollback ──────────────────────────────────────────────

/// The site must report `expected` and the maintenance mode it should be in,
/// installed, with no upgrade pending.
fn probe(
    ctx: &Context<'_>,
    req: &drupal_action::Request,
    expected: &str,
    maintenance: bool,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let status = read_status(ctx, req, cancel)
        .ok_or_else(|| "Nextcloud did not report a usable status".to_owned())?;
    if status.version != expected {
        return Err("the site reports another Nextcloud version".into());
    }
    if status.maintenance != maintenance {
        return Err("the site is not in the expected maintenance mode".into());
    }
    if status.upgrade_pending == Some(true) {
        return Err("the site still waits for its upgrade".into());
    }
    Ok(())
}

fn set_maintenance(
    ctx: &Context<'_>,
    req: &drupal_action::Request,
    on: bool,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let flag = if on { "--on" } else { "--off" };
    let ran = occ(ctx, req, &["maintenance:mode", flag], RUN_TIMEOUT, cancel)
        .map(|output| exited_ok(&output))
        .unwrap_or(false);
    match read_status(ctx, req, cancel) {
        Some(status) if ran && status.maintenance == on => Ok(()),
        _ => Err("the maintenance mode could not be set".into()),
    }
}

/// Everything after the bundle; an `Err` is the reason for the rollback.
fn apply(
    ctx: &Context<'_>,
    req: &Request,
    project: &ManagedRoot,
    target: &str,
    previous_maintenance: bool,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let id = req.request_id;
    if !previous_maintenance {
        set_maintenance(ctx, &req.base, true, cancel)?;
    }
    record(ctx, id, Step::MaintenanceOn);
    replace_code(project, &req.docroot_name, &stage_name(id))
        .map_err(|_| "the code could not be replaced".to_owned())?;
    record(ctx, id, Step::CodeReplaced);
    let output = occ(
        ctx,
        &req.base,
        &["upgrade", "--no-interaction"],
        UPDATE_TIMEOUT,
        cancel,
    )
    .map_err(|error| format!("occ upgrade: {}", error.protocol().1))?;
    if !exited_ok(&output) {
        return Err(
            if matches!(output.termination, process::ProcessTermination::TimedOut) {
                "occ upgrade: Nextcloud took too long".into()
            } else {
                "occ upgrade: Nextcloud reported an error".into()
            },
        );
    }
    record(ctx, id, Step::Updated);
    if !previous_maintenance {
        set_maintenance(ctx, &req.base, false, cancel)?;
    }
    probe(ctx, &req.base, target, previous_maintenance, cancel)?;
    record(ctx, id, Step::Probed);
    Ok(())
}

/// Replaces the code directory and the database with the bundle's. The bundle
/// is verified (checksums, readable archive) before anything is removed.
fn rollback(
    ctx: &Context<'_>,
    req: &Request,
    project: &ManagedRoot,
    id: RequestId,
) -> Result<Manifest, Error> {
    let base = &req.base;
    let cancel = CancellationToken::default();
    let dir = format!("{BUNDLES_DIR}/{id}");
    let manifest: Manifest = serde_json::from_str(
        &ctx.backup_root
            .read_to_string(&rel(format!("{dir}/manifest.json")))
            .map_err(|_| Error::BundleMissing)?,
    )
    .map_err(|_| Error::BundleCorrupt)?;
    if manifest.document_root != base.root().display().to_string() {
        return Err(Error::BundleCorrupt);
    }
    let bundle_dir = ctx.backup_path.join(&dir);
    let files = bundle_dir.join("files.tar.gz");
    let database = bundle_dir.join("database.sql");
    for (path, expected) in [
        (&files, &manifest.files_sha256),
        (&database, &manifest.database_sha256),
    ] {
        match sha256_file(path) {
            Ok((_, sum)) if &sum == expected => {}
            _ => return Err(Error::BundleCorrupt),
        }
    }
    let limits = limits();
    let sink = || std::fs::File::create("/dev/null").map_err(Error::Io);
    let listing = process::run_with_stdout_file(
        &ProcessRequest::new(ctx.tar_program)
            .args(["-tzf".to_owned(), files.display().to_string()]),
        sink()?,
        &limits,
        &cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&listing) {
        return Err(Error::BundleCorrupt);
    }

    // The code directory is opened once, without following a link, and
    // everything below goes through that descriptor: a tenant cannot swap the
    // directory for a link and have this (root) process empty or fill another
    // tree.
    let doc = open_code_dir(project, &req.docroot_name)?;
    record(ctx, id, Step::RollbackStarted);
    // Files: empty the code directory (links are removed, never followed),
    // then extract the bundle into it.
    for entry in doc.child_entries().map_err(Error::Io)? {
        let path = rel(&entry.name);
        if entry.is_dir {
            doc.remove_dir_all(&path)
        } else {
            doc.remove_file(&path)
        }
        .map_err(Error::Io)?;
    }
    let archive = ctx
        .backup_root
        .open_regular_read(&rel(format!("{dir}/files.tar.gz")))
        .map_err(Error::Io)?;
    tar_extract::extract(
        flate2::read::GzDecoder::new(std::io::BufReader::new(archive)),
        &doc,
        EXTRACT_LIMITS,
    )
    .map_err(|_| Error::RecoveryRequired("the files could not be extracted".into()))?;
    // Ownership is not archived by the extractor: the whole tree is the site's.
    crate::permissions::execute::repair_open_directory(
        &doc.try_clone_fd().map_err(Error::Io)?,
        req.uid,
        req.gid,
        &[],
    )
    .map_err(|_| Error::RecoveryRequired("the files could not be given back to the site".into()))?;

    record(ctx, id, Step::FilesRestored);
    // Database: the restored config.php names the connection.
    let connection = db_connection(&read_config(&doc)?)?;
    update_db::empty_database(ctx.docker_program, &connection, &limits, &cancel).map_err(
        |error| match error {
            update_db::DbError::Run(error) => Error::Run(error),
            update_db::DbError::Failed(why) => Error::RecoveryRequired(why.into()),
        },
    )?;
    let dump = ctx
        .backup_root
        .open_regular_read(&rel(format!("{dir}/database.sql")))
        .map_err(Error::Io)?;
    let imported = process::run_with_stdin_handle(
        &update_db::db_client(ctx.docker_program, &connection),
        dump,
        &limits,
        &cancel,
    )
    .map_err(Error::Run)?;
    if !exited_ok(&imported) {
        return Err(Error::RecoveryRequired("the database import failed".into()));
    }
    record(ctx, id, Step::DatabaseRestored);
    probe(
        ctx,
        base,
        &manifest.version_before,
        manifest.previous_maintenance,
        &cancel,
    )
    .map_err(|why| Error::RecoveryRequired(format!("after restoring: {why}")))?;
    record(ctx, id, Step::RolledBack);
    Ok(manifest)
}

// ── Interrupted updates ──────────────────────────────────────────────────

mod reconcile {
    //! Completing an update that was interrupted (the engine was killed, the
    //! host rebooted, the SSH session dropped). There is no daemon: the next
    //! Nextcloud update request for the same project does it, under the
    //! project's resource lock, so no live update can be mistaken for an
    //! interrupted one. Every bundle of this project whose journal did not
    //! end in `finished` or `rolledBack` is rolled back from its bundle,
    //! oldest first, whole (every part of the rollback is safe to repeat).
    //! A bundle that cannot be rolled back stops the new request with
    //! `recovery required` and stays for a manual `restoreUpdate`. An update
    //! that died before its bundle was complete changed nothing; the
    //! unpacked release it left beside the site is removed.

    use super::{
        BUNDLES_DIR, CORE, Context, Error, Manifest, RESTORE, Request, STAGING_PREFIX, rel,
        rollback, steps,
    };
    use crate::{
        drupal_action,
        error::ErrorCode,
        filesystem::ManagedRoot,
        site::SiteRelativePath,
        transaction::{
            RequestId,
            audit::{self, AuditRecord},
            state::{self, TransactionStatus},
        },
    };

    /// More bundles than this in the directory are not scanned.
    const MAX_BUNDLES: usize = 512;

    pub(super) fn reconcile(
        ctx: &Context<'_>,
        req: &Request,
        project: &ManagedRoot,
        scope: &ManagedRoot,
        current: RequestId,
        leave: Option<RequestId>,
    ) -> Result<(), Error> {
        for id in incomplete(ctx, &req.base, scope, current, leave) {
            rollback(ctx, req, project, id).map_err(|error| {
                Error::RecoveryRequired(format!(
                    "an earlier update was interrupted and rolling it back failed ({}); its \
                     recovery bundle {id} is kept",
                    error.protocol().1
                ))
            })?;
        }
        close_interrupted(scope, current, leave);
        remove_stale_staging(project, current);
        Ok(())
    }

    /// Unpacked releases of requests other than this one: the project lock is
    /// held, so none of them belongs to a live update.
    fn remove_stale_staging(project: &ManagedRoot, current: RequestId) {
        let own = super::stage_name(current);
        for entry in project.child_entries().unwrap_or_default() {
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            if entry.is_dir && name.starts_with(STAGING_PREFIX) && name != own {
                let _ = project.remove_dir_all(&rel(name));
            }
        }
    }

    fn incomplete(
        ctx: &Context<'_>,
        base: &drupal_action::Request,
        scope: &ManagedRoot,
        current: RequestId,
        leave: Option<RequestId>,
    ) -> Vec<RequestId> {
        let Ok(entries) = std::fs::read_dir(ctx.backup_path.join(BUNDLES_DIR)) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in entries.flatten().take(MAX_BUNDLES) {
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|name| RequestId::parse(name).ok())
            else {
                continue;
            };
            if id == current || Some(id) == leave {
                continue;
            }
            let Some(manifest) = ctx
                .backup_root
                .read_to_string(&rel(format!("{BUNDLES_DIR}/{id}/manifest.json")))
                .ok()
                .and_then(|text| serde_json::from_str::<Manifest>(&text).ok())
            else {
                continue;
            };
            if manifest.document_root != base.root().display().to_string() {
                continue;
            }
            let needs_rollback = match crate::update_steps::needs_rollback(
                steps::load(ctx, id).and_then(|journal| journal.last()),
            ) {
                Some(interrupted) => interrupted,
                None => transaction_in_progress(scope, id),
            };
            if needs_rollback {
                found.push((manifest.created_at_unix_secs, id));
            }
        }
        found.sort_by_key(|(created, _)| *created);
        found.into_iter().map(|(_, id)| id).collect()
    }

    fn transaction_path(id: RequestId) -> SiteRelativePath {
        SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap()
    }

    fn transaction_in_progress(scope: &ManagedRoot, id: RequestId) -> bool {
        state::load(scope, &transaction_path(id))
            .is_ok_and(|record| record.status == TransactionStatus::InProgress)
    }

    /// Finishes the records of requests that died, so they stop showing as
    /// running and a retry with their key gets a plain answer.
    fn close_interrupted(scope: &ManagedRoot, current: RequestId, leave: Option<RequestId>) {
        let Ok(dir) = scope.open_managed_dir(&SiteRelativePath::parse("transactions").unwrap())
        else {
            return;
        };
        let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();
        for name in dir.file_names().unwrap_or_default() {
            let Some(id) = name
                .strip_suffix(".json")
                .and_then(|stem| RequestId::parse(stem).ok())
            else {
                continue;
            };
            if id == current || Some(id) == leave {
                continue;
            }
            let Ok(mut record) = state::load(scope, &transaction_path(id)) else {
                continue;
            };
            let ours = [CORE, RESTORE].contains(&record.operation.as_str());
            if record.status != TransactionStatus::InProgress || !ours {
                continue;
            }
            let _ = record.mark_failed(
                ErrorCode::Internal,
                "the request was interrupted; a later request brought the site back to a \
                 consistent state",
            );
            let _ = state::save(scope, &transaction_path(id), &record);
            let _ = audit::append(
                scope,
                &audit_path,
                &AuditRecord::result(id, false, Some(ErrorCode::Internal)),
            );
        }
    }
}

// ── Run ──────────────────────────────────────────────────────────────────

fn run(
    ctx: &Context<'_>,
    req: &Request,
    scope: &ManagedRoot,
    cancel: &CancellationToken,
) -> Result<UpdateResult, Error> {
    let project = open_project(req)?;
    if req.kind == Kind::Restore {
        let id = req.recovery_id.unwrap();
        let manifest = rollback(ctx, req, &project, id)?;
        return Ok(UpdateResult {
            outcome: "restored".into(),
            recovery_id: id.to_string(),
            reason: None,
            version_after: manifest.version_before.clone(),
            version_before: manifest.version_before,
            completed_at_unix_secs: unix_now_secs(),
        });
    }

    // Preflight: nothing is changed until all of this holds. The code
    // directory is read through one open descriptor.
    let docroot = req.base.root();
    let doc = open_code_dir(&project, &req.docroot_name)?;
    for file in ["occ", "version.php"] {
        if !doc
            .symlink_metadata(&rel(file))
            .is_ok_and(|meta| meta.is_file())
        {
            return Err(Error::NotNextcloud);
        }
    }
    let config = read_config(&doc)?;
    let connection = db_connection(&config)?;
    data_dir_outside(&config, docroot)?;
    let installed =
        install::version(&project, &req.docroot_name).map_err(|_| Error::VersionUnreadable)?;
    let status = read_status(ctx, &req.base, cancel).ok_or(Error::StatusUnclear)?;
    if status.version != installed || status.upgrade_pending == Some(true) {
        return Err(Error::StatusUnclear);
    }
    let previous_maintenance = status.maintenance;
    let archive = req.archive.as_ref().ok_or(Error::ArchiveInvalid)?;
    let target = archive.version.clone();
    check_target(&installed, &target)?;
    // The release is fetched, checked and unpacked before the site is touched.
    stage(ctx, req, scope, &project)?;
    let staging = stage_name(req.request_id);

    let result = (|| {
        prune_bundles(ctx, req.request_id);
        bundle(
            ctx,
            req,
            &project,
            &connection,
            previous_maintenance,
            &installed,
            cancel,
        )?;
        // From here a failure is rolled back by the engine.
        let attempt = apply(ctx, req, &project, &target, previous_maintenance, cancel);
        match attempt {
            Ok(()) => {
                record(ctx, req.request_id, Step::Finished);
                Ok(UpdateResult {
                    outcome: "updated".into(),
                    recovery_id: req.request_id.to_string(),
                    reason: None,
                    version_before: installed.clone(),
                    version_after: target.clone(),
                    completed_at_unix_secs: unix_now_secs(),
                })
            }
            Err(reason) => {
                rollback(ctx, req, &project, req.request_id).map_err(|error| {
                    Error::RecoveryRequired(format!(
                        "the update failed ({reason}) and rolling back failed ({})",
                        error.protocol().1
                    ))
                })?;
                Ok(UpdateResult {
                    outcome: "rolledBack".into(),
                    recovery_id: req.request_id.to_string(),
                    reason: Some(reason),
                    version_before: installed.clone(),
                    version_after: installed.clone(),
                    completed_at_unix_secs: unix_now_secs(),
                })
            }
        }
    })();
    remove_staging(&project, &staging);
    result
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<UpdateResult, Error> {
    let hash = resource_lock::canonical_hash(req.root());
    let scope_path = SiteRelativePath::parse(format!("nextcloud-update/{hash}")).unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
    // The project's resource lock: no other operation runs against a
    // half-updated site.
    let _resource_lock = resource_lock::acquire(ctx.engine_state, req.root(), req.request_id)
        .map_err(|_| Error::ResourceBusy)?;

    let operation = req.operation();
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        operation,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id, operation),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    if cancel.is_cancelled() {
        return Err(fail(
            &scope,
            &state_path,
            &audit_path,
            state,
            Error::Cancelled,
        ));
    }
    // An earlier update of this project that died half way is rolled back
    // first, so this request starts from a consistent site.
    let project = TrustedRoot::parse(&req.project_root)
        .ok()
        .and_then(|root| ManagedRoot::open(&root).ok());
    let reconciled = match &project {
        Some(project) => {
            reconcile::reconcile(ctx, req, project, &scope, req.request_id, req.recovery_id)
        }
        None => Err(Error::NotNextcloud),
    };
    if let Err(error) = reconciled {
        return Err(fail(&scope, &state_path, &audit_path, state, error));
    }
    let result = match run(ctx, req, &scope, cancel) {
        Ok(value) => value,
        Err(Error::RecoveryRequired(why)) => {
            let id = req.recovery_id.unwrap_or(req.request_id);
            let error = Error::RecoveryRequired(format!("{why} (recovery id {id})"));
            return Err(fail(&scope, &state_path, &audit_path, state, error));
        }
        Err(error) => return Err(fail(&scope, &state_path, &audit_path, state, error)),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit {
            result: Box::new(result),
        });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<UpdateResult, Error> {
    let path = SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap();
    let loaded = state::load(scope, &path)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(std::io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(all(test, unix))]
mod tests;
