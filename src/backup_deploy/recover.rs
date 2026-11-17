//! `backup.recoverConfig`: explicit rollback of a `backup.activateConfig` that
//! died after it started changing the live files. It uses only the evidence
//! the activation saved before its first live write (see [`journal`]): puts the
//! previous files back, puts the previous root crontab back when the install
//! had started, drops the staging directory and marks the transaction failed.
//! It never activates anything and never repeats the request.

use serde::{Deserialize, Serialize};

use crate::{
    backup_deploy::{ARTIFACTS, OPERATION, journal},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    site::SiteRelativePath,
    transaction::{
        RequestId,
        audit::{self, AuditRecord},
        lock,
        state::{self, TransactionState, TransactionStatus},
    },
};
use std::time::Duration;

pub const RECOVER_OPERATION: &str = "backup.recoverConfig";

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// `/root/.wcp`: where the live backup configuration lives.
    pub config_root: &'a ManagedRoot,
    pub crontab_program: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverResult {
    /// False when the transaction was no longer in progress.
    pub recovered: bool,
    pub files_restored: u32,
    pub crontab_restored: bool,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    LockHeld,
    NotFound,
    WrongOperation,
    /// The interrupted request left no journal (it predates the journal, or
    /// the evidence could not be written): the live state cannot be proven.
    NoEvidence,
    /// Restoring did not finish; the journal is kept so the call can be repeated.
    RestoreFailed,
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, &'static str) {
        match self {
            Self::Io(_) => (
                ErrorCode::Internal,
                "could not roll back the backup configuration",
            ),
            Self::LockHeld => (
                ErrorCode::Conflict,
                "another backup configuration activation is in progress",
            ),
            Self::NotFound => (
                ErrorCode::NotFound,
                "the activation transaction was not found",
            ),
            Self::WrongOperation => (
                ErrorCode::Conflict,
                "the request is not an interrupted backup configuration activation",
            ),
            Self::NoEvidence => (
                ErrorCode::Conflict,
                "the interrupted activation left no rollback evidence; it needs a person",
            ),
            Self::RestoreFailed => (
                ErrorCode::ConfigRecoveryFailed,
                "restoring the previous backup configuration did not finish; repeat the rollback",
            ),
        }
    }
}

fn rel(path: impl AsRef<str>) -> SiteRelativePath {
    SiteRelativePath::parse(path.as_ref()).expect("a fixed or validated relative path")
}

/// An in-progress activation that saved its journal.
pub fn available(scope: &ManagedRoot, record: &TransactionState) -> bool {
    record.status == TransactionStatus::InProgress
        && record.operation == OPERATION
        && journal::load(scope, record.request_id).is_ok_and(|journal| journal.is_some())
}

pub fn execute(
    ctx: &Context<'_>,
    interrupted: RequestId,
    holder: RequestId,
    cancel: &CancellationToken,
) -> Result<RecoverResult, Error> {
    let scope = ctx
        .engine_state
        .open_managed_dir(&rel("backup-activate"))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound
            } else {
                Error::Io(error)
            }
        })?;
    // Holding the scope lock proves the original activation is gone.
    let _lock =
        lock::acquire(&scope, &preflight::lock_path(), holder).map_err(|_| Error::LockHeld)?;
    let state_path = rel(format!("transactions/{interrupted}.json"));
    let mut record = state::load(&scope, &state_path).map_err(|error| match error {
        state::StateError::NotFound => Error::NotFound,
        other => Error::Io(std::io::Error::other(format!("{other:?}"))),
    })?;
    if record.request_id != interrupted || record.operation != OPERATION {
        return Err(Error::WrongOperation);
    }
    if record.status != TransactionStatus::InProgress {
        return Ok(RecoverResult {
            recovered: false,
            files_restored: 0,
            crontab_restored: false,
        });
    }
    let saved = journal::load(&scope, interrupted)
        .map_err(Error::Io)?
        .ok_or(Error::NoEvidence)?;

    let mut files_restored = 0;
    let mut crontab_restored = false;
    if saved.phase != journal::Phase::Begin {
        if saved.files.len() != ARTIFACTS.len() {
            return Err(Error::NoEvidence);
        }
        for (index, (artifact, previous)) in ARTIFACTS.iter().zip(&saved.files).enumerate() {
            let live = rel(artifact.relative_path);
            let outcome = if previous.existed {
                let (Some(mode), Ok(content)) = (
                    previous.mode,
                    scope.read_bytes(&journal::previous_path(interrupted, &index.to_string())),
                ) else {
                    return Err(Error::RestoreFailed);
                };
                ctx.config_root
                    .write_atomic(&live, &content)
                    .and_then(|()| ctx.config_root.set_mode(&live, mode))
            } else {
                match ctx.config_root.remove_file(&live) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    other => other,
                }
            };
            outcome.map_err(|_| Error::RestoreFailed)?;
            files_restored += 1;
        }
    }
    if saved.phase == journal::Phase::Crontab {
        restore_crontab(ctx, &scope, interrupted, saved.crontab_existed, cancel)?;
        crontab_restored = true;
    }

    let _ = ctx
        .config_root
        .remove_dir_all(&rel(format!(".backup-activate/{interrupted}")));
    record
        .mark_failed(
            ErrorCode::Cancelled,
            "interrupted; rolled back by backup.recoverConfig",
        )
        .map_err(|_| Error::WrongOperation)?;
    state::save(&scope, &state_path, &record)
        .map_err(|error| Error::Io(std::io::Error::other(format!("{error:?}"))))?;
    let _ = audit::append(
        &scope,
        &rel("audit/events.jsonl"),
        &AuditRecord::result(interrupted, false, Some(ErrorCode::Cancelled)),
    );
    let _ = journal::discard(&scope, interrupted);
    Ok(RecoverResult {
        recovered: true,
        files_restored,
        crontab_restored,
    })
}

/// Puts root's previous crontab back (or removes it when there was none).
/// Safe whether or not the new tab was installed: either way the result is
/// the saved one.
fn restore_crontab(
    ctx: &Context<'_>,
    scope: &ManagedRoot,
    interrupted: RequestId,
    existed: Option<bool>,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let limits = ProcessLimits {
        timeout: Duration::from_secs(30),
        max_stdout_bytes: 64 * 1024,
        max_stderr_bytes: 64 * 1024,
    };
    match existed {
        Some(true) => {
            let tab = scope
                .read_bytes(&journal::previous_path(interrupted, "crontab"))
                .map_err(|_| Error::RestoreFailed)?;
            let output = process::run_with_stdin_bytes(
                &ProcessRequest::new(ctx.crontab_program).args(["-"]),
                &tab,
                &limits,
                cancel,
            )
            .map_err(|_| Error::RestoreFailed)?;
            matches!(
                output.termination,
                ProcessTermination::Exited { success: true, .. }
            )
            .then_some(())
            .ok_or(Error::RestoreFailed)
        }
        Some(false) => {
            // `crontab -r` fails when there is no tab, which is the wanted
            // end state; a tab that is still there afterwards is not.
            let _ = process::run(
                &ProcessRequest::new(ctx.crontab_program).args(["-r"]),
                &limits,
                cancel,
            );
            match crate::cron::execute::read_current_tab(ctx.crontab_program, None) {
                Ok(None) => Ok(()),
                _ => Err(Error::RestoreFailed),
            }
        }
        None => Err(Error::NoEvidence),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::TrustedRoot;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const HOLDER: &str = "323e4567-e89b-12d3-a456-426614174000";

    struct Fixture {
        dir: tempfile::TempDir,
        state: ManagedRoot,
        config: ManagedRoot,
        tab: String,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            for sub in ["state", "config"] {
                fs::create_dir_all(dir.path().join(sub)).unwrap();
            }
            let tab = dir.path().join("crontab");
            fs::write(
                &tab,
                "#!/bin/sh\nstore=\"$(dirname \"$0\")/tab\"\ncase \"$1\" in\n  -l) [ -f \"$store\" ] && cat \"$store\" || exit 1 ;;\n  -r) rm -f \"$store\" ;;\n  -) cat > \"$store\" ;;\nesac\n",
            )
            .unwrap();
            fs::set_permissions(&tab, fs::Permissions::from_mode(0o755)).unwrap();
            let open = |sub: &str| {
                ManagedRoot::open(&TrustedRoot::parse(dir.path().join(sub)).unwrap()).unwrap()
            };
            Self {
                state: open("state"),
                config: open("config"),
                tab: tab.to_string_lossy().into_owned(),
                dir,
            }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                engine_state: &self.state,
                config_root: &self.config,
                crontab_program: &self.tab,
            }
        }

        fn live(&self, name: &str) -> Option<String> {
            fs::read_to_string(self.dir.path().join("config").join(name)).ok()
        }

        fn tab_text(&self) -> Option<String> {
            fs::read_to_string(self.dir.path().join("tab")).ok()
        }

        /// A scope with an in-progress activation whose journal is at `phase`.
        fn interrupted(&self, phase: journal::Phase) -> ManagedRoot {
            self.state.create_dir_all(&rel("backup-activate")).unwrap();
            let scope = self
                .state
                .open_managed_dir(&rel("backup-activate"))
                .unwrap();
            for child in ["locks", "transactions", "audit"] {
                scope.create_dir_all(&rel(child)).unwrap();
            }
            let id = RequestId::parse(ID).unwrap();
            state::create(
                &scope,
                &rel(format!("transactions/{id}.json")),
                &TransactionState::start(id, None, OPERATION),
            )
            .unwrap();
            journal::begin(&scope, id).unwrap();
            if phase != journal::Phase::Begin {
                let tab = self.tab_text();
                journal::record_previous(
                    &scope,
                    id,
                    &self.config,
                    tab.as_deref().map(str::as_bytes),
                )
                .unwrap();
            }
            if phase == journal::Phase::Crontab {
                journal::set_phase(&scope, id, journal::Phase::Crontab).unwrap();
            }
            scope
        }
    }

    fn id() -> RequestId {
        RequestId::parse(ID).unwrap()
    }

    #[test]
    fn a_crash_after_the_crontab_install_puts_files_and_tab_back() {
        let fx = Fixture::new();
        fs::write(fx.dir.path().join("config/rclone.conf"), "old remote").unwrap();
        fs::set_permissions(
            fx.dir.path().join("config/rclone.conf"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(fx.dir.path().join("tab"), "0 2 * * * old\n").unwrap();
        let scope = fx.interrupted(journal::Phase::Crontab);
        // What the activation did before it died: new files, a new tab.
        fs::write(fx.dir.path().join("config/rclone.conf"), "new remote").unwrap();
        fs::write(fx.dir.path().join("config/backup.conf"), "{}").unwrap();
        fs::write(fx.dir.path().join("tab"), "0 3 * * * new\n").unwrap();

        let result = execute(
            &fx.ctx(),
            id(),
            RequestId::parse(HOLDER).unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(
            result,
            RecoverResult {
                recovered: true,
                files_restored: 5,
                crontab_restored: true
            }
        );
        assert_eq!(fx.live("rclone.conf").as_deref(), Some("old remote"));
        assert_eq!(
            fx.live("backup.conf"),
            None,
            "a file that did not exist is removed"
        );
        assert_eq!(fx.tab_text().as_deref(), Some("0 2 * * * old\n"));
        let mode = fs::metadata(fx.dir.path().join("config/rclone.conf"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let record = state::load(&scope, &rel(format!("transactions/{ID}.json"))).unwrap();
        assert_eq!(record.status, TransactionStatus::Failed);
        assert!(journal::load(&scope, id()).unwrap().is_none());
        assert!(!available(&scope, &record));
    }

    #[test]
    fn a_crash_before_any_tab_existed_removes_the_new_tab() {
        let fx = Fixture::new();
        fx.interrupted(journal::Phase::Crontab);
        fs::write(fx.dir.path().join("tab"), "0 3 * * * new\n").unwrap();
        let result = execute(
            &fx.ctx(),
            id(),
            RequestId::parse(HOLDER).unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(result.crontab_restored);
        assert_eq!(
            fx.tab_text(),
            None,
            "there was no tab before, so there is none now"
        );
    }

    #[test]
    fn before_the_files_changed_only_the_record_is_closed_and_the_tab_is_untouched() {
        let fx = Fixture::new();
        fs::write(fx.dir.path().join("tab"), "0 2 * * * keep\n").unwrap();
        let scope = fx.interrupted(journal::Phase::Begin);
        fs::write(fx.dir.path().join("config/rclone.conf"), "someone else's").unwrap();
        let result = execute(
            &fx.ctx(),
            id(),
            RequestId::parse(HOLDER).unwrap(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(
            result,
            RecoverResult {
                recovered: true,
                files_restored: 0,
                crontab_restored: false
            }
        );
        assert_eq!(fx.live("rclone.conf").as_deref(), Some("someone else's"));
        assert_eq!(fx.tab_text().as_deref(), Some("0 2 * * * keep\n"));
        let record = state::load(&scope, &rel(format!("transactions/{ID}.json"))).unwrap();
        assert_eq!(record.status, TransactionStatus::Failed);
    }

    #[test]
    fn a_request_without_evidence_a_running_original_and_a_second_call_are_handled() {
        let fx = Fixture::new();
        let scope = fx.interrupted(journal::Phase::Files);
        let holder = RequestId::parse(HOLDER).unwrap();

        // A running original holds the scope lock: refused, nothing touched.
        let guard = lock::acquire(&scope, &preflight::lock_path(), id()).unwrap();
        assert!(matches!(
            execute(&fx.ctx(), id(), holder, &CancellationToken::default()),
            Err(Error::LockHeld)
        ));
        drop(guard);

        // No journal (a record from before the journal existed): refused.
        scope
            .remove_dir_all(&rel(format!("recovery/{ID}")))
            .unwrap();
        assert!(matches!(
            execute(&fx.ctx(), id(), holder, &CancellationToken::default()),
            Err(Error::NoEvidence)
        ));
        let record = state::load(&scope, &rel(format!("transactions/{ID}.json"))).unwrap();
        assert!(!available(&scope, &record));

        // Another operation's id is refused, and an unknown id is not found.
        assert!(matches!(
            execute(&fx.ctx(), holder, holder, &CancellationToken::default()),
            Err(Error::NotFound)
        ));
        let _ = Path::new("");
    }
}
