use crate::{
    cli::RuntimeCommand,
    commands::{ContentFileError, read_content_file},
    error::{ErrorCode, WarningCode},
    ingress::transition::LifecycleError,
    process::CancellationToken,
    protocol::{Response, ResponseBuildError, Warning},
    runtime_config::{
        OPERATION, REMOVE_OPERATION, RuntimeActivateConfigRequest,
        RuntimeActivateConfigRequestError, RuntimeRemoveConfigRequest,
        RuntimeRemoveConfigRequestError,
        execute::{
            RuntimeActivateConfigError, RuntimeActivateContext, execute as execute_activate_config,
        },
        reconcile::{
            RECONCILE_OPERATION, RuntimeReconcileContext, RuntimeReconcileError,
            RuntimeReconcileRequest, RuntimeReconcileRequestError, execute as execute_reconcile,
        },
        remove::execute as execute_remove_config,
    },
    site::{Domain, RuntimeId},
    transaction::{IdempotencyKey, RequestId},
};

const CONFIG_PATH: &str = "/etc/operations-engine/config.json";

pub fn run(command: RuntimeCommand) -> Result<Response, ResponseBuildError> {
    match command {
        RuntimeCommand::PatchStatus { request_file } => patch_status(&request_file),
        RuntimeCommand::PatchUpdate {
            request_file,
            request_id,
            idempotency_key,
        } => patch_update(&request_file, &request_id, idempotency_key.as_deref()),
        RuntimeCommand::SetPatchWindow {
            request_file,
            request_id,
        } => set_patch_window(&request_file, &request_id),
        RuntimeCommand::RunPatchWindow { request_id } => run_patch_window(&request_id),
        RuntimeCommand::PatchWindowStatus => patch_window_status(),
        RuntimeCommand::ActivateConfig {
            runtime_id,
            domain,
            content_file,
            expected_hash,
            request_id,
            idempotency_key,
        } => activate_config(
            &runtime_id,
            &domain,
            &content_file,
            expected_hash.as_deref(),
            &request_id,
            idempotency_key.as_deref(),
        ),
        RuntimeCommand::RemoveConfig {
            runtime_id,
            domain,
            expected_hash,
            request_id,
            idempotency_key,
        } => remove_config(
            &runtime_id,
            &domain,
            &expected_hash,
            &request_id,
            idempotency_key.as_deref(),
        ),
        RuntimeCommand::Reconcile {
            runtime_id,
            request_id,
            idempotency_key,
        } => reconcile(&runtime_id, &request_id, idempotency_key.as_deref()),
    }
}

fn patch_status(path: &std::path::Path) -> Result<Response, ResponseBuildError> {
    use crate::runtime_patch_status as patch;
    #[cfg(unix)]
    {
        let Ok(json) = crate::commands::read_root_owned_content_file(path) else {
            return Ok(Response::failure(
                patch::OPERATION,
                ErrorCode::InvalidInput,
                "request-file must be a root-owned regular file",
            ));
        };
        let request = match patch::Request::parse(&json) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    patch::OPERATION,
                    ErrorCode::InvalidInput,
                    error.message(),
                ));
            }
        };
        Response::success(
            patch::OPERATION,
            patch::evaluate(
                &crate::security_affected::Docker { program: "docker" },
                &request,
            ),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Response::failure(
            patch::OPERATION,
            ErrorCode::UnsupportedPlatform,
            "runtime patch status requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn patch_update(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::{
        config::EngineConfig,
        filesystem::ManagedRoot,
        stack_deploy::{
            Context, Timing,
            patch::{self, PatchError},
        },
    };
    const OPERATION: &str = patch::OPERATION;
    let Ok(config) = EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) else {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::Internal,
            crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
        ));
    };
    let Ok(json) = crate::commands::read_root_owned_content_file(path) else {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::InvalidInput,
            "request-file must be a root-owned regular file",
        ));
    };
    let request = match patch::Request::parse(&json, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                error.message(),
            ));
        }
    };
    if !cfg!(target_os = "linux") {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "runtime patch update requires a Linux host",
        ));
    }
    let Ok(engine_state) = ManagedRoot::open(&config.state_root) else {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::Internal,
            "engine state root is unavailable",
        ));
    };
    let Some((stack_root, owner)) = crate::commands::stack::prepare_stack_root() else {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::Internal,
            "stack directory is unavailable",
        ));
    };
    let context = Context {
        engine_state: &engine_state,
        stack_root: &stack_root,
        docker: "docker",
        timing: Timing::PRODUCTION,
        owner,
    };
    match patch::execute(&context, &request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(PatchError::PostCommit { result }) => Response::success(OPERATION, result).map(|r| {
            r.with_warnings(vec![Warning {
                code: WarningCode::TransactionRecordIncomplete,
                message: "the service was updated but its transaction record could not be saved"
                    .to_owned(),
            }])
        }),
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(OPERATION, code, &message))
        }
    }
}

#[cfg(not(unix))]
fn patch_update(
    _path: &std::path::Path,
    _request_id: &str,
    _idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    Ok(Response::failure(
        "runtime.patchUpdate",
        ErrorCode::UnsupportedPlatform,
        "runtime patch update requires a Linux host",
    ))
}

fn remove_config(
    runtime_id: &str,
    domain: &str,
    expected_hash: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match RuntimeRemoveConfigRequest::parse(
        runtime_id,
        domain,
        expected_hash,
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                REMOVE_OPERATION,
                ErrorCode::InvalidInput,
                match error {
                    RuntimeRemoveConfigRequestError::InvalidRuntimeId => {
                        "runtime-id is not a valid runtime pool identifier"
                    }
                    RuntimeRemoveConfigRequestError::InvalidDomain => {
                        "domain is not a valid domain name"
                    }
                    RuntimeRemoveConfigRequestError::InvalidExpectedHash => {
                        "expected-hash is not a valid SHA-256 digest"
                    }
                    RuntimeRemoveConfigRequestError::InvalidRequestId => {
                        "request-id is not a canonical UUID"
                    }
                    RuntimeRemoveConfigRequestError::InvalidIdempotencyKey => {
                        "idempotency-key is invalid"
                    }
                },
            ));
        }
    };

    #[cfg(unix)]
    {
        run_remove_config(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            REMOVE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "runtime.removeConfig requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_remove_config(request: &RuntimeRemoveConfigRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                REMOVE_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                REMOVE_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let compose_access = compose::Access::default();
    let context = RuntimeActivateContext {
        runtime_root: &engine_config.runtime_root,
        engine_state: &engine_state,
        compose: &compose_access,
    };

    match execute_remove_config(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(REMOVE_OPERATION, result),
        Err(LifecycleError::PostCommitRecordFailed { result, .. }) => {
            Response::success(REMOVE_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the configuration was removed but its transaction record could \
                              not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(REMOVE_OPERATION, code, &message))
        }
    }
}

fn activate_config(
    runtime_id: &str,
    domain: &str,
    content_file: &std::path::Path,
    expected_hash: Option<&str>,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    // Same ordering `ingress::commands::activate_config` uses and for the
    // same reason: reject a malformed field before this root-privileged
    // process ever touches the filesystem for the content path.
    // `RuntimeActivateConfigRequest::parse` below re-validates these same
    // fields (it is the single authoritative constructor for the request),
    // but by then they are already known-good, so that is cheap string
    // work, not new I/O.
    let guard = match RuntimeActivateConfigRequest::guard_from_expected_hash(expected_hash) {
        Ok(guard) => guard,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                request_error_message(error),
            ));
        }
    };
    if let Err(error) = validate_cheap_fields(runtime_id, domain, request_id, idempotency_key) {
        return Ok(Response::failure(
            OPERATION,
            ErrorCode::InvalidInput,
            request_error_message(error),
        ));
    }

    let content = match read_content_file(content_file) {
        Ok(content) => content,
        Err(ContentFileError::TooLarge) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                request_error_message(RuntimeActivateConfigRequestError::ContentTooLarge),
            ));
        }
        Err(ContentFileError::Unreadable) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                "content-file could not be read",
            ));
        }
    };

    let request = match RuntimeActivateConfigRequest::parse(
        runtime_id,
        domain,
        content,
        guard,
        request_id,
        idempotency_key,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::InvalidInput,
                request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_activate_config(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            OPERATION,
            ErrorCode::UnsupportedPlatform,
            "runtime.activateConfig requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_activate_config(
    request: &RuntimeActivateConfigRequest,
) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{compose, config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let compose_access = compose::Access::default();
    let context = RuntimeActivateContext {
        runtime_root: &engine_config.runtime_root,
        engine_state: &engine_state,
        compose: &compose_access,
    };

    match execute_activate_config(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(OPERATION, result),
        Err(RuntimeActivateConfigError::PostCommitRecordFailed { result, .. }) => {
            Response::success(OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the configuration was activated but its transaction record could \
                              not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(OPERATION, code, &message))
        }
    }
}

/// Validates `runtime_id`, `domain`, `request_id`, and `idempotency_key` —
/// every field `RuntimeActivateConfigRequest::parse` checks that does not
/// depend on the content file's bytes — using the same underlying parsers
/// it uses, so a malformed request is rejected before `content_file` is
/// ever read. Mirrors `ingress::commands::validate_cheap_fields`.
fn validate_cheap_fields(
    runtime_id: &str,
    domain: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<(), RuntimeActivateConfigRequestError> {
    RuntimeId::parse(runtime_id)
        .map_err(|_| RuntimeActivateConfigRequestError::InvalidRuntimeId)?;
    Domain::parse(domain).map_err(|_| RuntimeActivateConfigRequestError::InvalidDomain)?;
    RequestId::parse(request_id)
        .map_err(|_| RuntimeActivateConfigRequestError::InvalidRequestId)?;
    if let Some(key) = idempotency_key {
        IdempotencyKey::parse(key)
            .map_err(|_| RuntimeActivateConfigRequestError::InvalidIdempotencyKey)?;
    }
    Ok(())
}

fn request_error_message(error: RuntimeActivateConfigRequestError) -> &'static str {
    match error {
        RuntimeActivateConfigRequestError::InvalidRuntimeId => {
            "runtime-id is not a valid runtime pool identifier"
        }
        RuntimeActivateConfigRequestError::InvalidDomain => "domain is not a valid domain name",
        RuntimeActivateConfigRequestError::ContentTooLarge => {
            "content-file exceeds the maximum allowed fragment size"
        }
        RuntimeActivateConfigRequestError::InvalidExpectedHash => {
            "expected-hash is not a valid SHA-256 digest"
        }
        RuntimeActivateConfigRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RuntimeActivateConfigRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn reconcile(
    runtime_id: &str,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let request = match RuntimeReconcileRequest::parse(runtime_id, request_id, idempotency_key) {
        Ok(request) => request,
        Err(error) => {
            return Ok(Response::failure(
                RECONCILE_OPERATION,
                ErrorCode::InvalidInput,
                reconcile_request_error_message(error),
            ));
        }
    };

    #[cfg(unix)]
    {
        run_reconcile(&request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Ok(Response::failure(
            RECONCILE_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "runtime.reconcile requires a Unix host",
        ))
    }
}

#[cfg(unix)]
fn run_reconcile(request: &RuntimeReconcileRequest) -> Result<Response, ResponseBuildError> {
    use std::path::Path;

    use crate::{config::EngineConfig, filesystem::ManagedRoot};

    let engine_config = match EngineConfig::load_root_owned(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(_) => {
            return Ok(Response::failure(
                RECONCILE_OPERATION,
                ErrorCode::Internal,
                crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
            ));
        }
    };
    let engine_state = match ManagedRoot::open(&engine_config.state_root) {
        Ok(root) => root,
        Err(_) => {
            return Ok(Response::failure(
                RECONCILE_OPERATION,
                ErrorCode::Internal,
                "engine state root is unavailable",
            ));
        }
    };
    let context = RuntimeReconcileContext {
        runtime_root: &engine_config.runtime_root,
        engine_state: &engine_state,
    };

    match execute_reconcile(&context, request, &CancellationToken::default()) {
        Ok(result) => Response::success(RECONCILE_OPERATION, result),
        Err(RuntimeReconcileError::PostCommitRecordFailed { result, .. }) => {
            Response::success(RECONCILE_OPERATION, result).map(|response| {
                response.with_warnings(vec![Warning {
                    code: WarningCode::TransactionRecordIncomplete,
                    message: "the sweep completed but its transaction record could not be saved"
                        .to_owned(),
                }])
            })
        }
        Err(error) => {
            let (code, message) = error.protocol();
            Ok(Response::failure(RECONCILE_OPERATION, code, &message))
        }
    }
}

fn reconcile_request_error_message(error: RuntimeReconcileRequestError) -> &'static str {
    match error {
        RuntimeReconcileRequestError::InvalidRuntimeId => {
            "runtime-id is not a valid runtime pool identifier"
        }
        RuntimeReconcileRequestError::InvalidRequestId => "request-id is not a canonical UUID",
        RuntimeReconcileRequestError::InvalidIdempotencyKey => "idempotency-key is invalid",
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `runtime.setPatchWindow`: stores the owner's approval and installs or
/// removes the daily timer. A timer that cannot be installed (no systemd as
/// init) is reported, never hidden: the window is then stored but does not run
/// by itself.
fn set_patch_window(
    path: &std::path::Path,
    request_id: &str,
) -> Result<Response, ResponseBuildError> {
    use crate::service_patch_window as window;
    #[cfg(unix)]
    {
        if RequestId::parse(request_id).is_err() {
            return Ok(Response::failure(
                window::SET_OPERATION,
                ErrorCode::InvalidInput,
                "request-id is not a canonical UUID",
            ));
        }
        let Ok(json) = crate::commands::read_root_owned_content_file(path) else {
            return Ok(Response::failure(
                window::SET_OPERATION,
                ErrorCode::InvalidInput,
                "request-file must be a root-owned regular file",
            ));
        };
        let request = match window::SetRequest::parse(&json) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Response::failure(
                    window::SET_OPERATION,
                    ErrorCode::InvalidInput,
                    &error.message(),
                ));
            }
        };
        let config = std::path::Path::new(window::CONFIG_PATH);
        let stored = (|| {
            if let Some(dir) = config.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let previous = window::load(config)?;
            let next = window::after_set(previous, &request, now_secs());
            window::store(config, &next)?;
            Ok::<_, std::io::Error>(next)
        })();
        let Ok(next) = stored else {
            return Ok(Response::failure(
                window::SET_OPERATION,
                ErrorCode::Internal,
                "the patch window could not be stored",
            ));
        };
        let timer = window::sync_timer(
            &next,
            std::path::Path::new(crate::security_timer::UNIT_DIR),
            std::path::Path::new(crate::security_timer::RUN_DIR),
            "systemctl",
        );
        Response::success(
            window::SET_OPERATION,
            serde_json::json!({
                "enabled": next.enabled,
                "hour": next.hour,
                "minute": next.minute,
                "targets": next.targets.len(),
                "timer": timer.name(),
            }),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (path, request_id);
        Ok(Response::failure(
            window::SET_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "the patch window requires a Linux host",
        ))
    }
}

/// `runtime.runPatchWindow`: the daily run. Every approved image goes through
/// the same patch sequence as a manual update, one service at a time.
fn run_patch_window(request_id: &str) -> Result<Response, ResponseBuildError> {
    use crate::{
        config::EngineConfig,
        filesystem::ManagedRoot,
        service_patch_window as window,
        stack_deploy::{Context, Timing, patch},
    };
    if RequestId::parse(request_id).is_err() {
        return Ok(Response::failure(
            window::RUN_OPERATION,
            ErrorCode::InvalidInput,
            "request-id is not a canonical UUID",
        ));
    }
    if !cfg!(target_os = "linux") {
        return Ok(Response::failure(
            window::RUN_OPERATION,
            ErrorCode::UnsupportedPlatform,
            "the patch window requires a Linux host",
        ));
    }
    let Ok(config) = EngineConfig::load_root_owned(std::path::Path::new(CONFIG_PATH)) else {
        return Ok(Response::failure(
            window::RUN_OPERATION,
            ErrorCode::Internal,
            crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
        ));
    };
    let Ok(engine_state) = ManagedRoot::open(&config.state_root) else {
        return Ok(Response::failure(
            window::RUN_OPERATION,
            ErrorCode::Internal,
            "engine state root is unavailable",
        ));
    };
    let Some((stack_root, owner)) = crate::commands::stack::prepare_stack_root() else {
        return Ok(Response::failure(
            window::RUN_OPERATION,
            ErrorCode::Internal,
            "stack directory is unavailable",
        ));
    };
    let context = Context {
        engine_state: &engine_state,
        stack_root: &stack_root,
        docker: "docker",
        timing: Timing::PRODUCTION,
        owner,
    };
    let cancel = CancellationToken::default();
    match window::run(
        std::path::Path::new(window::CONFIG_PATH),
        now_secs(),
        &mut |request| patch::execute(&context, request, &cancel),
    ) {
        Ok(last) => {
            // A failure is also told to the channels the agents use, from here,
            // so it reaches the owner with the panel closed. Best effort.
            if let Some((text, payload)) = window::failure_summary(&last) {
                window::notify_failure(
                    std::path::Path::new(window::NOTIFY_FILE),
                    &text,
                    &payload,
                    &mut window::curl_post,
                );
            }
            Response::success(window::RUN_OPERATION, last)
        }
        Err(window::RunError::NotEnabled) => Response::success(
            window::RUN_OPERATION,
            serde_json::json!({ "atUnixSecs": now_secs(), "results": [] }),
        ),
        Err(window::RunError::Io(_)) => Ok(Response::failure(
            window::RUN_OPERATION,
            ErrorCode::Internal,
            "the patch window could not be read or recorded",
        )),
    }
}

/// `runtime.patchWindowStatus`: read-only.
fn patch_window_status() -> Result<Response, ResponseBuildError> {
    use crate::service_patch_window as window;
    match window::load(std::path::Path::new(window::CONFIG_PATH)) {
        Ok(stored) => Response::success(
            window::STATUS_OPERATION,
            serde_json::json!({
                "configured": stored.is_some(),
                "window": stored,
                "timerInstalled": window::timer_installed(std::path::Path::new(
                    crate::security_timer::UNIT_DIR
                )),
            }),
        ),
        Err(_) => Ok(Response::failure(
            window::STATUS_OPERATION,
            ErrorCode::Internal,
            "the patch window file could not be read",
        )),
    }
}
