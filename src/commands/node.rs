use crate::{
    cli::NodeCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    node_app, node_build,
    protocol::{Response, ResponseBuildError},
};

pub fn run(command: NodeCommand) -> Result<Response, ResponseBuildError> {
    match command {
        NodeCommand::Build {
            request_file,
            request_id,
            idempotency_key,
        } => build(&request_file, &request_id, idempotency_key.as_deref()),
        NodeCommand::DeployApp {
            request_file,
            request_id,
            idempotency_key,
        } => deploy_app(&request_file, &request_id, idempotency_key.as_deref()),
        NodeCommand::AppStatus { domain } => app_status(&domain),
        NodeCommand::RestartApp {
            request_file,
            request_id,
            idempotency_key,
        } => domain_action(
            node_app::RESTART,
            false,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
        NodeCommand::RemoveApp {
            request_file,
            request_id,
            idempotency_key,
        } => domain_action(
            node_app::REMOVE,
            true,
            &request_file,
            &request_id,
            idempotency_key.as_deref(),
        ),
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

fn app_request_error(error: node_app::RequestError) -> &'static str {
    use node_app::RequestError as E;
    match error {
        E::InvalidJson => "request-file is not a valid Node application plan",
        E::InvalidDomain => "domain is invalid",
        E::InvalidRoot => "project root is invalid",
        E::InvalidBuildId => "build id is not a canonical UUID",
        E::InvalidImage => "image must be an allowed registry reference pinned by sha256 digest",
        E::InvalidIdentity => "uid and gid must be non-zero",
        E::InvalidAdapter => "adapter is not supported",
        E::InvalidLimit => "memory is outside the allowed range",
        E::InvalidEnv => "environment names or values are not allowed",
        E::InvalidRequestId => "request-id is not a canonical UUID",
        E::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

/// The host a Node application operation works against. `lock_ingress` takes
/// the stack and ingress locks first, as every route change does.
#[cfg(unix)]
fn with_host<T: serde::Serialize>(
    operation: &'static str,
    lock_ingress: bool,
    check: impl FnOnce(&crate::config::EngineConfig) -> Result<(), &'static str>,
    action: impl FnOnce(&node_app::Context<'_>) -> Result<T, node_app::Error>,
) -> Result<Response, ResponseBuildError> {
    use crate::{filesystem::ManagedRoot, transaction::RequestId};
    let fail = |code, message: &str| Ok(Response::failure(operation, code, message));
    let config = match crate::config::EngineConfig::load_root_owned(std::path::Path::new(
        "/etc/operations-engine/config.json",
    )) {
        Ok(v) => v,
        Err(_) => {
            return fail(
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            );
        }
    };
    if let Err(message) = check(&config) {
        return fail(ErrorCode::InvalidInput, message);
    }
    let Ok(state) = ManagedRoot::open(&config.state_root) else {
        return fail(ErrorCode::Internal, "engine state root is unavailable");
    };
    let holder = RequestId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let stack_scope;
    let ingress_scope;
    let (_stack_lock, _ingress_lock);
    if lock_ingress {
        stack_scope = match crate::stack_deploy::open_scope(&state) {
            Ok(v) => v,
            Err(_) => return fail(ErrorCode::Internal, "stack lock unavailable"),
        };
        ingress_scope = match crate::ingress::execute::open_ingress_state(&state) {
            Ok(v) => v,
            Err(_) => return fail(ErrorCode::Internal, "ingress lock unavailable"),
        };
        _stack_lock = match crate::stack_deploy::acquire_stack_lock(&stack_scope, holder) {
            Ok(v) => Some(v),
            Err(_) => return fail(ErrorCode::Conflict, "the stack is busy"),
        };
        _ingress_lock = match crate::transaction::lock::acquire(
            &ingress_scope,
            &crate::mutation::preflight::lock_path(),
            holder,
        ) {
            Ok(v) => Some(v),
            Err(_) => return fail(ErrorCode::Conflict, "the ingress is busy"),
        };
    }
    let compose = crate::compose::Access::default();
    let context = node_app::Context {
        engine_state: &state,
        state_path: config.state_root.as_path(),
        ingress_root: &config.ingress_root,
        compose: &compose,
        docker_program: "docker",
        poll_interval: std::time::Duration::from_secs(2),
        health_timeout: std::time::Duration::from_secs(120),
    };
    match action(&context) {
        Ok(v) => Response::success(operation, v),
        Err(node_app::Error::PostCommit { result }) => Response::success(operation, result),
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(operation, code, &message))
        }
    }
}

fn deploy_app(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let operation = node_app::DEPLOY;
    #[cfg(unix)]
    {
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
        let request = match node_app::DeployRequest::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(error) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    app_request_error(error),
                ));
            }
        };
        with_host(
            operation,
            true,
            |config| {
                config
                    .content_roots
                    .iter()
                    .any(|root| request.root().starts_with(root.as_path()))
                    .then_some(())
                    .ok_or("project root is outside configured content roots")
            },
            |context| {
                node_app::deploy(
                    context,
                    &request,
                    &crate::process::CancellationToken::default(),
                )
            },
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "node.deployApp requires a Unix host",
        ))
    }
}

fn domain_action(
    operation: &'static str,
    lock_ingress: bool,
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    #[cfg(unix)]
    {
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
        let request = match node_app::DomainRequest::parse(&json, request_id, idempotency_key) {
            Ok(v) => v,
            Err(error) => {
                return Ok(Response::failure(
                    operation,
                    ErrorCode::InvalidInput,
                    app_request_error(error),
                ));
            }
        };
        let cancel = crate::process::CancellationToken::default();
        if operation == node_app::RESTART {
            with_host(
                operation,
                lock_ingress,
                |_| Ok(()),
                |context| node_app::restart(context, &request, &cancel),
            )
        } else {
            with_host(
                operation,
                lock_ingress,
                |_| Ok(()),
                |context| node_app::remove(context, &request, &cancel),
            )
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id, idempotency_key, lock_ingress);
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "Node applications require a Unix host",
        ))
    }
}

fn app_status(domain: &str) -> Result<Response, ResponseBuildError> {
    let operation = node_app::STATUS;
    #[cfg(unix)]
    {
        let Ok(domain) = crate::site::Domain::parse(domain) else {
            return Ok(Response::failure(
                operation,
                ErrorCode::InvalidInput,
                "domain is invalid",
            ));
        };
        with_host(
            operation,
            false,
            |_| Ok(()),
            |context| node_app::status(context, &domain),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = domain;
        Ok(Response::failure(
            operation,
            ErrorCode::UnsupportedPlatform,
            "Node applications require a Unix host",
        ))
    }
}
