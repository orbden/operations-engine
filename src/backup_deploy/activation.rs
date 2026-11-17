use crate::{
    backup_deploy::{
        Request, journal,
        staging::{self, ActivationResult},
    },
    filesystem::ManagedRoot,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    transaction::RequestId,
};
use std::time::Duration;

#[derive(Debug)]
pub enum Error {
    Files(staging::Error),
    Crontab(process::ProcessRunError),
    CrontabRejected,
    RollbackFailed,
}

/// Activates the file bundle first and installs the complete root crontab as
/// the final commit step. `crontab -` is atomic from the caller's perspective:
/// a rejected input leaves the prior tab installed, so only the file bundle
/// needs explicit rollback on failure.
///
/// Before the first live write the previous files and the previous crontab
/// are saved in `evidence` (the engine state, see [`journal`]), so a crash at
/// any later point can be rolled back by `backup.recoverConfig`. A failure
/// that this call rolls back itself removes the evidence again; one whose
/// rollback failed keeps it for the explicit recovery.
pub fn activate(
    root: &ManagedRoot,
    evidence: &ManagedRoot,
    request: &Request,
    request_id: &str,
    crontab_program: &str,
    cancellation: &CancellationToken,
) -> Result<ActivationResult, Error> {
    let id =
        RequestId::parse(request_id).map_err(|_| Error::Files(staging::Error::InvalidRequestId))?;
    let files_error = |error: std::io::Error| Error::Files(staging::Error::Io(error));
    let drop_evidence = || {
        let _ = journal::discard(evidence, id);
    };
    journal::begin(evidence, id).map_err(files_error)?;
    let staged = match staging::stage(root, request, request_id) {
        Ok(value) => value,
        Err(error) => {
            drop_evidence();
            return Err(Error::Files(error));
        }
    };
    let previous_tab = match crate::cron::execute::read_current_tab(crontab_program, None) {
        Ok(value) => value,
        Err(error) => {
            let _ = staged.discard();
            drop_evidence();
            return Err(Error::Crontab(error));
        }
    };
    if let Err(error) = journal::record_previous(evidence, id, root, previous_tab.as_deref()) {
        let _ = staged.discard();
        drop_evidence();
        return Err(files_error(error));
    }
    let activated = match staged.activate_files() {
        Ok(value) => value,
        // `activate_files` rolled the files back itself, unless that failed.
        Err(error) => {
            if !matches!(error, staging::Error::RollbackFailed) {
                drop_evidence();
            }
            return Err(Error::Files(error));
        }
    };
    crate::failpoint::hit("backup.activate.afterFiles");
    if let Err(error) = journal::set_phase(evidence, id, journal::Phase::Crontab) {
        return Err(rolled_back(activated, evidence, id, files_error(error)));
    }
    crate::failpoint::hit("backup.activate.beforeCrontab");
    let output = match process::run_with_stdin_bytes(
        &ProcessRequest::new(crontab_program).args(["-"]),
        request.crontab.as_bytes(),
        &ProcessLimits {
            timeout: Duration::from_secs(30),
            max_stdout_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        cancellation,
    ) {
        Ok(value) => value,
        Err(error) => return Err(rolled_back(activated, evidence, id, Error::Crontab(error))),
    };
    if !matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    ) {
        return Err(rolled_back(activated, evidence, id, Error::CrontabRejected));
    }
    crate::failpoint::hit("backup.activate.afterCrontab");
    let result = activated.commit();
    drop_evidence();
    Ok(result)
}

/// Rolls the activated files back and, when that worked, drops the evidence;
/// a rollback that failed keeps it and reports `RollbackFailed`.
fn rolled_back(
    activated: staging::ActivatedConfig<'_>,
    evidence: &ManagedRoot,
    id: RequestId,
    cause: Error,
) -> Error {
    match activated.rollback() {
        Ok(()) => {
            let _ = journal::discard(evidence, id);
            cause
        }
        Err(_) => Error::RollbackFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn request() -> Request {
        Request::parse(r##"{"rcloneConfig":"new","backupConfig":"{}","notifyConfig":"{}","agentScript":"#!/bin/sh\nexit 0","crontab":"0 2 * * * true\n"}"##).unwrap()
    }

    fn script(directory: &std::path::Path, exit: i32) -> String {
        let path = directory.join(format!("fake-crontab-{exit}"));
        fs::write(&path, format!("#!/bin/sh\ncat >/dev/null\nexit {exit}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn rejected_crontab_rolls_back_the_file_bundle() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("rclone.conf"), "old").unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let state = tempfile::tempdir().unwrap();
        let evidence =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(state.path()).unwrap()).unwrap();
        let result = activate(
            &root,
            &evidence,
            &request(),
            ID,
            &script(directory.path(), 1),
            &CancellationToken::default(),
        );
        assert!(matches!(result, Err(Error::CrontabRejected)));
        assert_eq!(
            fs::read_to_string(directory.path().join("rclone.conf")).unwrap(),
            "old"
        );
        assert!(!directory.path().join("backup.conf").exists());
    }

    #[test]
    fn accepted_crontab_commits_files_and_cleans_staging() {
        let directory = tempfile::tempdir().unwrap();
        let root =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(directory.path()).unwrap()).unwrap();
        let state = tempfile::tempdir().unwrap();
        let evidence =
            ManagedRoot::open(&crate::site::TrustedRoot::parse(state.path()).unwrap()).unwrap();
        let result = activate(
            &root,
            &evidence,
            &request(),
            ID,
            &script(directory.path(), 0),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(!result.staging_cleanup_incomplete);
        assert_eq!(
            fs::read_to_string(directory.path().join("rclone.conf")).unwrap(),
            "new"
        );
        assert!(!directory.path().join(".backup-activate").join(ID).exists());
    }
}
