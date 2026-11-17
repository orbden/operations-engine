//! `backup.discardPartial`: closes a database backup (`backup.createDatabase`)
//! or a remote import (`backup.importRemote`) whose process died mid-write.
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

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    backup_create, backup_import_remote,
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

/// Which interrupted backup to close.
#[derive(Debug, Clone)]
pub enum Target {
    Database(DatabaseName),
    Import,
}

#[derive(Debug, Clone, Copy)]
pub enum RequestError {
    /// Exactly one of `--database` and `--import` is required.
    TargetRequired,
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
        interrupted: &str,
        request_id: &str,
    ) -> Result<Self, RequestError> {
        let target = match (database, import) {
            (Some(name), false) => {
                Target::Database(DatabaseName::parse(name).map_err(RequestError::InvalidDatabase)?)
            }
            (None, true) => Target::Import,
            _ => return Err(RequestError::TargetRequired),
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
    }
}

fn operation_of(target: &Target) -> &'static str {
    match target {
        Target::Database(_) => backup_create::OPERATION,
        Target::Import => backup_import_remote::OPERATION,
    }
}

/// Whether `record` is a backup that died in progress, so the scope's lock is
/// the only thing left to check.
pub fn available(record: &TransactionState) -> bool {
    record.status == TransactionStatus::InProgress
        && matches!(
            record.operation.as_str(),
            backup_create::OPERATION | backup_import_remote::OPERATION
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
        });
    }
    let files_removed = match &req.target {
        Target::Database(database) => {
            remove_dump_partials(ctx.backup_root, database, req.interrupted)?
        }
        Target::Import => remove_import_partials(ctx.import_root, req.interrupted)?,
    };
    record
        .mark_failed(
            ErrorCode::Cancelled,
            "interrupted; the partial output was discarded",
        )
        .map_err(|_| Error::WrongOperation)?;
    state::save(&scope, &state_path, &record)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    let _ = audit::append(
        &scope,
        &rel("audit/events.jsonl"),
        &AuditRecord::result(req.interrupted, false, Some(ErrorCode::Cancelled)),
    );
    Ok(DiscardResult {
        closed: true,
        files_removed,
    })
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
        Request::parse(Some("shop"), false, id, HOLDER).unwrap()
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
                files_removed: 1
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
                files_removed: 0
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
        let request = Request::parse(None, true, DB_ID, HOLDER).unwrap();
        let result = execute(&fx.ctx(), &request).unwrap();
        assert_eq!(
            result,
            DiscardResult {
                closed: true,
                files_removed: 1
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
                &Request::parse(Some("shop"), false, HOLDER, HOLDER).unwrap()
            ),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn exactly_one_target_is_required() {
        assert!(matches!(
            Request::parse(None, false, DB_ID, HOLDER),
            Err(RequestError::TargetRequired)
        ));
        assert!(matches!(
            Request::parse(Some("shop"), true, DB_ID, HOLDER),
            Err(RequestError::TargetRequired)
        ));
        assert!(matches!(
            Request::parse(Some("a b;"), false, DB_ID, HOLDER),
            Err(RequestError::InvalidDatabase(_))
        ));
    }
}
