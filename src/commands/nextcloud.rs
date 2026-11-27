use crate::{
    cli::NextcloudCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    nextcloud_update,
    protocol::{Response, ResponseBuildError},
};

pub fn run(command: NextcloudCommand) -> Result<Response, ResponseBuildError> {
    match command {
        NextcloudCommand::UpdateCore {
            request_file,
            request_id,
            idempotency_key,
        } => update(
            "update-core",
            nextcloud_update::CORE,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        NextcloudCommand::RestoreUpdate {
            request_file,
            request_id,
            idempotency_key,
        } => update(
            "restore-update",
            nextcloud_update::RESTORE,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
    }
}

fn update(
    kind: &str,
    operation: &'static str,
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
        use crate::{backup_delete::BACKUP_ROOT, filesystem::ManagedRoot, site::TrustedRoot};
        let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
            "/etc/operations-engine/config.json",
        )) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
                ));
            }
        };
        let json = match read_root_owned_content_file(path) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    "request-file must be a root-owned regular file",
                ));
            }
        };
        let request =
            match nextcloud_update::Request::parse(kind, &json, request_id, idempotency_key) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(Response::failure(
                        operation,
                        ErrorCode::InvalidInput,
                        "request-file is not a valid Nextcloud update plan",
                    ));
                }
            };
        if !config
            .content_roots
            .iter()
            .any(|root| request.root().starts_with(root.as_path()))
        {
            return Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                "Nextcloud root is outside configured content roots",
            ));
        }
        let state = match ManagedRoot::open(&config.state_root) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    "engine state root is unavailable",
                ));
            }
        };
        let _ = std::fs::create_dir_all(BACKUP_ROOT);
        let backups = match TrustedRoot::parse(std::path::Path::new(BACKUP_ROOT)).and_then(|root| {
            ManagedRoot::open(&root).map_err(|_| crate::site::ValidationError::PathResolutionFailed)
        }) {
            Ok(v) => v,
            Err(_) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::Internal,
                    "backup root is unavailable",
                ));
            }
        };
        let context = nextcloud_update::Context {
            engine_state: &state,
            docker_program: "docker",
            tar_program: "tar",
            tools_dir: std::path::Path::new(crate::tool_manage::TOOLS_DIR),
            backup_root: &backups,
            backup_path: std::path::Path::new(BACKUP_ROOT),
            fetch: &crate::engine::fetch::fetch_reader_bounded,
        };
        match nextcloud_update::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) => Response::success(operation, v),
            Err(nextcloud_update::Error::PostCommit { result }) => {
                Response::success(operation, *result)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(operation, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (kind, path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "Nextcloud updates require a Unix host",
        ))
    }
}
