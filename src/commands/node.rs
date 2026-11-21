use crate::{
    cli::NodeCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    node_build,
    protocol::{Response, ResponseBuildError},
};

pub fn run(command: NodeCommand) -> Result<Response, ResponseBuildError> {
    match command {
        NodeCommand::Build {
            request_file,
            request_id,
            idempotency_key,
        } => build(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn build(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = node_build::OPERATION;
    #[cfg(unix)]
    {
        use crate::filesystem::ManagedRoot;
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
        let request = match node_build::Request::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(error) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    request_error_message(error),
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
                "project root is outside configured content roots",
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
        let context = node_build::Context {
            engine_state: &state,
            state_path: config.state_root.as_path(),
            docker_program: "docker",
        };
        match node_build::execute(
            &context,
            &request,
            &crate::process::CancellationToken::default(),
        ) {
            Ok(v) | Err(node_build::Error::PostCommit { result: v }) => {
                Response::success(operation, v)
            }
            Err(e) => {
                let (code, message) = e.protocol();
                Ok(Response::failure(operation, code, &message))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "node.build requires a Unix host",
        ))
    }
}

fn request_error_message(error: node_build::RequestError) -> &'static str {
    use node_build::RequestError as E;
    match error {
        E::InvalidJson => "request-file is not a valid Node build plan",
        E::InvalidRoot => "project root is invalid",
        E::InvalidImage => "image must be an allowed registry reference pinned by sha256 digest",
        E::InvalidIdentity => "uid and gid must be non-zero",
        E::InvalidScript => "script is invalid",
        E::InvalidOutputDir => "output directory is invalid",
        E::InvalidLimit => "memory or timeout is outside the allowed range",
        E::InvalidRequestId => "request-id is not a canonical UUID",
        E::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}
