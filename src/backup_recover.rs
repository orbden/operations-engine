//! `backup.discardPartial`: closes a backup operation whose process died: a
//! database backup (`backup.createDatabase`, which the scheduled run uses
//! too), a remote import (`backup.importRemote`), an immediate agent run
//! (`backup.triggerNow`) or a deletion (`backup.delete`).
//!
//! Neither operation can be resumed: each streams into a file named after its
//! own request id (`<database>_<time>.sql.partial-<request id>` in the backup
//! root, `<request id>_<name>.partial` in the imports directory) and publishes
//! it only by a final rename, so a crash leaves a file nobody lists as a
//! backup, which still takes disk space, and a transaction that stays
//! `IN_PROGRESS` with nothing that finishes it. This removes exactly the
//! interrupted request's partial file(s) and marks the transaction failed. It
//! never starts a backup and never touches a finished one. Taking the scope
//! lock is the proof that the original process is gone.
//!
//! A trigger or a deletion leaves no partial output of its own: the agent has
//! its own lock and cleanup, and a deletion removes one file in one step. For
//! those the record is closed without claiming what happened (the outcome is
//! not confirmed), and nothing is removed. The agent's own work is not stopped:
//! stopping a backup half-way is worse than letting it finish. The result says
//! whether an agent still holds the backup lock (`agentRunning`), so the
//! operator knows the run the closed record started may still be going.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    backup_create, backup_delete, backup_import_remote, backup_trigger,
    db_restore::{DatabaseName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::SiteRelativePath,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        lock,
        state::{self, TransactionState, TransactionStatus},
    },
};

pub const OPERATION: &str = "backup.discardPartial";
const IMPORT_SCOPE: &str = "backup-import-remote";
const TRIGGER_SCOPE: &str = "backup-trigger";

/// Which interrupted backup to close.
#[derive(Debug, Clone)]
pub enum Target {
    Database(DatabaseName),
    Import,
    /// `backup.triggerNow`: the immediate run of the backup agent.
    Trigger,
    /// `backup.delete`: the scope is the SHA-256 (64 lowercase hex) of the file path.
    Delete(String),
}

#[derive(Debug, Clone, Copy)]
pub enum RequestError {
    /// Exactly one of `--database`, `--import`, `--trigger` and `--delete-scope` is required.
    TargetRequired,
    InvalidDeleteScope,
    InvalidDatabase(RestoreRequestError),
    InvalidRequestId,
}

pub struct Request {
    pub target: Target,
    pub interrupted: RequestId,
    pub request_id: RequestId,
}

impl Request {
    pub fn parse(
        database: Option<&str>,
        import: bool,
        trigger: bool,
        delete_scope: Option<&str>,
        interrupted: &str,
        request_id: &str,
    ) -> Result<Self, RequestError> {
        let chosen = usize::from(database.is_some())
            + usize::from(import)
            + usize::from(trigger)
            + usize::from(delete_scope.is_some());
        if chosen != 1 {
            return Err(RequestError::TargetRequired);
        }
        let target = if let Some(name) = database {
            Target::Database(DatabaseName::parse(name).map_err(RequestError::InvalidDatabase)?)
        } else if import {
            Target::Import
        } else if trigger {
            Target::Trigger
        } else {
            let hash = delete_scope.unwrap_or_default();
            let hex = hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            if hash.len() != 64 || !hex {
                return Err(RequestError::InvalidDeleteScope);
            }
            Target::Delete(hash.to_owned())
        };
        Ok(Self {
            target,
            interrupted: RequestId::parse(interrupted)
                .map_err(|_| RequestError::InvalidRequestId)?,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
        })
    }
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// `/root/db-backups`: where database dumps are written.
    pub backup_root: &'a ManagedRoot,
    /// `/root/db-backups/imports`: where remote imports are downloaded.
    pub import_root: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscardResult {
    /// False when the transaction was not in progress (already closed).
    pub closed: bool,
    pub files_removed: u32,
    /// For a closed trigger: whether a process still holds the backup agent's
    /// lock (its run goes on by itself). `None` when that could not be read
    /// or the target is not a trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_running: Option<bool>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Another backup operation of this scope holds the lock: the original may
    /// still be running.
    LockHeld,
    NotFound,
    /// The record belongs to another operation than the target's backup.
    WrongOperation,
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::Io(_) => (ErrorCode::Internal, "could not discard the partial backup"),
            Self::LockHeld => (
                ErrorCode::Conflict,
                "another backup operation of this scope is running",
            ),
            Self::NotFound => (ErrorCode::NotFound, "the backup transaction was not found"),
            Self::WrongOperation => (
                ErrorCode::Conflict,
                "the request is not an interrupted backup of this kind",
            ),
        }
    }
}

fn rel(path: impl AsRef<str>) -> SiteRelativePath {
    SiteRelativePath::parse(path.as_ref()).expect("a fixed or validated relative path")
}

fn scope_path(target: &Target) -> SiteRelativePath {
    match target {
        Target::Database(database) => rel(format!("db-backup/{}", database.as_str())),
        Target::Import => rel(IMPORT_SCOPE),
        Target::Trigger => rel(TRIGGER_SCOPE),
        Target::Delete(hash) => rel(format!("backup-delete/{hash}")),
    }
}

fn operation_of(target: &Target) -> &'static str {
    match target {
        Target::Database(_) => backup_create::OPERATION,
        Target::Import => backup_import_remote::OPERATION,
        Target::Trigger => backup_trigger::OPERATION,
        Target::Delete(_) => backup_delete::OPERATION,
    }
}

/// Whether `record` is a backup that died in progress, so the scope's lock is
/// the only thing left to check.
pub fn available(record: &TransactionState) -> bool {
    record.status == TransactionStatus::InProgress
        && matches!(
            record.operation.as_str(),
            backup_create::OPERATION
                | backup_import_remote::OPERATION
                | backup_trigger::OPERATION
                | backup_delete::OPERATION
        )
}

pub fn execute(ctx: &Context<'_>, req: &Request) -> Result<DiscardResult, Error> {
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path(&req.target))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound
            } else {
                Error::Io(error)
            }
        })?;
    let _lock = lock::acquire(&scope, &preflight::lock_path(), req.request_id)
        .map_err(|_| Error::LockHeld)?;
    let state_path = rel(format!("transactions/{}.json", req.interrupted));
    let mut record = state::load(&scope, &state_path).map_err(|error| match error {
        state::StateError::NotFound => Error::NotFound,
        other => Error::Io(std::io::Error::other(format!("{other:?}"))),
    })?;
    if record.request_id != req.interrupted || record.operation != operation_of(&req.target) {
        return Err(Error::WrongOperation);
    }
    if record.status != TransactionStatus::InProgress {
        return Ok(DiscardResult {
            closed: false,
            files_removed: 0,
            agent_running: None,
        });
    }
    let files_removed = match &req.target {
        Target::Database(database) => {
            remove_dump_partials(ctx.backup_root, database, req.interrupted)?
        }
        Target::Import => remove_import_partials(ctx.import_root, req.interrupted)?,
        // No partial output of their own; see the module documentation.
        Target::Trigger | Target::Delete(_) => 0,
    };
    let message = match req.target {
        Target::Trigger | Target::Delete(_) => {
            "interrupted; closed by backup.discardPartial, the outcome was not confirmed"
        }
        _ => "interrupted; the partial output was discarded",
    };
    record
        .mark_failed(ErrorCode::Cancelled, message)
        .map_err(|_| Error::WrongOperation)?;
    state::save(&scope, &state_path, &record)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    let _ = audit::append(
        &scope,
        &rel("audit/events.jsonl"),
        &AuditRecord::result(req.interrupted, false, Some(ErrorCode::Cancelled)),
    );
    let agent_running = matches!(req.target, Target::Trigger)
        .then(|| ctx.import_root.parent().map(|dir| dir.join(AGENT_LOCK)))
        .flatten()
        .and_then(|lock| lock_held_by_a_process(&lock));
    Ok(DiscardResult {
        closed: true,
        files_removed,
        agent_running,
    })
}

/// The backup agent's lock file inside the backup root.
const AGENT_LOCK: &str = ".lock";

/// Whether some process has `path` open (the agent keeps its `flock` on an
/// open descriptor of it for the whole run). `None` when `/proc` cannot be
/// read; an unreadable single process is skipped, never counted as "no".
fn lock_held_by_a_process(path: &Path) -> Option<bool> {
    let mut readable = false;
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        readable = true;
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|target| target == path) {
                return Some(true);
            }
        }
    }
    readable.then_some(false)
}

/// `<database>_<time>.sql.partial-<request id>`: only plain files, only this
/// request's, only this database's.
fn remove_dump_partials(
    backup_root: &ManagedRoot,
    database: &DatabaseName,
    id: RequestId,
) -> Result<u32, Error> {
    let suffix = format!(".sql.partial-{id}");
    let prefix = format!("{}_", database.as_str());
    let mut removed = 0;
    for name in backup_root.file_names().map_err(Error::Io)? {
        if !(name.starts_with(&prefix) && name.ends_with(&suffix)) {
            continue;
        }
        let Ok(path) = SiteRelativePath::parse(&name) else {
            continue;
        };
        if backup_root
            .symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_file())
        {
            backup_root.remove_file(&path).map_err(Error::Io)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// `<request id>_<name>.partial` in the imports directory.
fn remove_import_partials(import_root: &Path, id: RequestId) -> Result<u32, Error> {
    let prefix = format!("{id}_");
    let entries = match std::fs::read_dir(import_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(Error::Io(error)),
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(&prefix) && name.ends_with(".partial")) {
            continue;
        }
        let path = entry.path();
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_file())
        {
            std::fs::remove_file(&path).map_err(Error::Io)?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;

    const DB_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "223e4567-e89b-12d3-a456-426614174000";
    const HOLDER: &str = "323e4567-e89b-12d3-a456-426614174000";

    struct Fixture {
        _dir: tempfile::TempDir,
        state: ManagedRoot,
        backups: ManagedRoot,
        imports: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["state", "backups", "backups/imports"] {
                std::fs::create_dir_all(dir.path().join(sub)).unwrap();
            }
            let open = |sub: &str| {
                ManagedRoot::open(&TrustedRoot::parse(dir.path().join(sub)).unwrap()).unwrap()
            };
            Self {
                state: open("state"),
                backups: open("backups"),
                imports: dir.path().join("backups/imports"),
                _dir: dir,
            }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                backup_root: &self.backups,
                import_root: &self.imports,
            }
        }

        /// A scope with one in-progress transaction of `operation`.
        fn interrupted(&self, scope: &str, id: &str, operation: &str) -> ManagedRoot {
            self.state.create_dir_all(&rel(scope)).unwrap();
            let dir = self.state.open_managed_dir(&rel(scope)).unwrap();
            for child in ["locks", "transactions", "audit"] {
                dir.create_dir_all(&rel(child)).unwrap();
            }
            let id = RequestId::parse(id).unwrap();
            state::create(
                &dir,
                &rel(format!("transactions/{id}.json")),
                &TransactionState::start(id, None, operation),
            )
            .unwrap();
            dir
        }

        fn status(&self, scope: &ManagedRoot, id: &str) -> TransactionStatus {
            state::load(scope, &rel(format!("transactions/{id}.json")))
                .unwrap()
                .status
        }
    }

    fn database(id: &str) -> Request {
        Request::parse(Some("shop"), false, false, None, id, HOLDER).unwrap()
    }

    #[test]
    fn a_dump_that_died_loses_only_its_own_partial_and_is_closed() {
        let fx = Fixture::new();
        let scope = fx.interrupted("db-backup/shop", DB_ID, backup_create::OPERATION);
        let own = format!("shop_1700000000.sql.partial-{DB_ID}");
        let other_request = format!("shop_1700000000.sql.partial-{OTHER_ID}");
        let other_database = format!("blog_1700000000.sql.partial-{DB_ID}");
        for name in [
            own.as_str(),
            other_request.as_str(),
            other_database.as_str(),
            "shop_1700000000.sql",
        ] {
            std::fs::write(fx._dir.path().join("backups").join(name), "dump").unwrap();
        }

        let result = execute(&fx.ctx(), &database(DB_ID)).unwrap();
        assert_eq!(
            result,
            DiscardResult {
                closed: true,
                files_removed: 1,
                agent_running: None,
            }
        );
        let left: Vec<String> = {
            let mut names = fx.backups.file_names().unwrap();
            names.retain(|name| name != "imports");
            names.sort();
            names
        };
        assert_eq!(
            left,
            [
                "blog_1700000000.sql.partial-123e4567-e89b-12d3-a456-426614174000",
                "shop_1700000000.sql",
                "shop_1700000000.sql.partial-223e4567-e89b-12d3-a456-426614174000",
            ],
            "a finished backup, another request's partial and another database's partial stay"
        );
        assert_eq!(fx.status(&scope, DB_ID), TransactionStatus::Failed);
        assert!(!available(
            &state::load(&scope, &rel(format!("transactions/{DB_ID}.json"))).unwrap()
        ));

        // Nothing left to do the second time.
        assert_eq!(
            execute(&fx.ctx(), &database(DB_ID)).unwrap(),
            DiscardResult {
                closed: false,
                files_removed: 0,
                agent_running: None,
            }
        );
    }

    #[test]
    fn an_import_that_died_loses_its_partial_in_the_imports_directory() {
        let fx = Fixture::new();
        let scope = fx.interrupted(IMPORT_SCOPE, DB_ID, backup_import_remote::OPERATION);
        let own = fx.imports.join(format!("{DB_ID}_site.sql.gz.partial"));
        let finished = fx.imports.join(format!("{DB_ID}_site.sql.gz"));
        let foreign = fx.imports.join(format!("{OTHER_ID}_site.sql.gz.partial"));
        for path in [&own, &finished, &foreign] {
            std::fs::write(path, "x").unwrap();
        }
        let request = Request::parse(None, true, false, None, DB_ID, HOLDER).unwrap();
        let result = execute(&fx.ctx(), &request).unwrap();
        assert_eq!(
            result,
            DiscardResult {
                closed: true,
                files_removed: 1,
                agent_running: None,
            }
        );
        assert!(!own.exists() && finished.exists() && foreign.exists());
        assert_eq!(fx.status(&scope, DB_ID), TransactionStatus::Failed);
    }

    #[test]
    fn a_running_original_a_foreign_operation_and_a_symlink_are_left_alone() {
        let fx = Fixture::new();
        let scope = fx.interrupted("db-backup/shop", DB_ID, backup_create::OPERATION);
        let partial = format!("shop_1700000000.sql.partial-{DB_ID}");
        let outside = fx._dir.path().join("precious");
        std::fs::write(&outside, "keep").unwrap();
        std::os::unix::fs::symlink(&outside, fx._dir.path().join("backups").join(&partial))
            .unwrap();

        // The original still holds the scope lock: refused, nothing touched.
        let guard = lock::acquire(
            &scope,
            &preflight::lock_path(),
            RequestId::parse(DB_ID).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            execute(&fx.ctx(), &database(DB_ID)),
            Err(Error::LockHeld)
        ));
        drop(guard);

        // A symlink is never followed or removed.
        let result = execute(&fx.ctx(), &database(DB_ID)).unwrap();
        assert_eq!(result.files_removed, 0);
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");

        // The id of a different operation in the same scope is refused.
        let other = fx.interrupted("db-backup/shop", OTHER_ID, "backup.scheduleDatabase");
        let _ = other;
        assert!(matches!(
            execute(&fx.ctx(), &database(OTHER_ID)),
            Err(Error::WrongOperation)
        ));
        assert!(matches!(
            execute(
                &fx.ctx(),
                &Request::parse(Some("shop"), false, false, None, HOLDER, HOLDER).unwrap()
            ),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn a_trigger_or_a_deletion_that_died_is_closed_without_removing_anything() {
        let fx = Fixture::new();
        let hash = "ab".repeat(32);
        let trigger = fx.interrupted("backup-trigger", DB_ID, backup_trigger::OPERATION);
        let delete = fx.interrupted(
            &format!("backup-delete/{hash}"),
            OTHER_ID,
            backup_delete::OPERATION,
        );
        // Files beside them are not theirs to touch.
        std::fs::write(fx._dir.path().join("backups/shop_1.sql"), "dump").unwrap();

        let trigger_request = Request::parse(None, false, true, None, DB_ID, HOLDER).unwrap();
        assert_eq!(
            execute(&fx.ctx(), &trigger_request).unwrap(),
            DiscardResult {
                closed: true,
                files_removed: 0,
                // Nobody holds the agent's lock file here (`None` where there
                // is no /proc to ask).
                agent_running: cfg!(target_os = "linux").then_some(false),
            }
        );
        assert_eq!(fx.status(&trigger, DB_ID), TransactionStatus::Failed);
        let closed = state::load(&trigger, &rel(format!("transactions/{DB_ID}.json"))).unwrap();
        let message = closed.outcome.and_then(|outcome| outcome.error_message);
        assert!(
            message.is_some_and(|text| text.contains("outcome was not confirmed")),
            "the record must not claim what happened"
        );

        let delete_request =
            Request::parse(None, false, false, Some(&hash), OTHER_ID, HOLDER).unwrap();
        assert_eq!(
            execute(&fx.ctx(), &delete_request).unwrap(),
            DiscardResult {
                closed: true,
                files_removed: 0,
                agent_running: None,
            }
        );
        assert_eq!(fx.status(&delete, OTHER_ID), TransactionStatus::Failed);
        assert!(fx._dir.path().join("backups/shop_1.sql").exists());

        // A trigger record is not a deletion's, and vice versa.
        let wrong = Request::parse(None, false, false, Some(&hash), DB_ID, HOLDER).unwrap();
        assert!(matches!(
            execute(&fx.ctx(), &wrong),
            Err(Error::NotFound) | Err(Error::WrongOperation)
        ));
    }

    #[test]
    fn a_closed_trigger_says_whether_the_agent_still_holds_its_lock() {
        let fx = Fixture::new();
        fx.interrupted("backup-trigger", DB_ID, backup_trigger::OPERATION);
        // The agent keeps an open descriptor of its lock file for the whole run.
        let lock_file = fx._dir.path().join("backups/.lock");
        let held = std::fs::File::create(&lock_file).unwrap();
        let request = Request::parse(None, false, true, None, DB_ID, HOLDER).unwrap();
        let result = execute(&fx.ctx(), &request).unwrap();
        assert_eq!(
            result.agent_running,
            cfg!(target_os = "linux").then_some(true),
            "{result:?}"
        );
        // Nothing was stopped: the file and the process side are untouched.
        assert!(lock_file.exists());
        drop(held);
        assert_eq!(
            lock_held_by_a_process(&lock_file),
            cfg!(target_os = "linux").then_some(false)
        );
    }

    #[test]
    fn the_delete_scope_must_be_a_sha256_in_lowercase_hex() {
        for bad in [
            "",
            "abc",
            &"AB".repeat(32),
            &"zz".repeat(32),
            &"ab".repeat(33),
        ] {
            assert!(matches!(
                Request::parse(None, false, false, Some(bad), DB_ID, HOLDER),
                Err(RequestError::InvalidDeleteScope)
            ));
        }
        assert!(matches!(
            Request::parse(None, true, true, None, DB_ID, HOLDER),
            Err(RequestError::TargetRequired)
        ));
    }

    #[test]
    fn exactly_one_target_is_required() {
        assert!(matches!(
            Request::parse(None, false, false, None, DB_ID, HOLDER),
            Err(RequestError::TargetRequired)
        ));
        assert!(matches!(
            Request::parse(Some("shop"), true, false, None, DB_ID, HOLDER),
            Err(RequestError::TargetRequired)
        ));
        assert!(matches!(
            Request::parse(Some("a b;"), false, false, None, DB_ID, HOLDER),
            Err(RequestError::InvalidDatabase(_))
        ));
    }
}
