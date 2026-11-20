use crate::{
    application_install,
    cli::ApplicationCommand,
    commands::read_root_owned_content_file,
    error::ErrorCode,
    protocol::{Response, ResponseBuildError},
};

pub fn run(command: ApplicationCommand) -> Result<Response, ResponseBuildError> {
    match command {
        ApplicationCommand::Install {
            request_file,
            request_id,
            idempotency_key,
        } => install(&request_file, &request_id, idempotency_key.as_deref()),
    }
}

fn fail(code: ErrorCode, message: &str) -> Result<Response, ResponseBuildError> {
    Ok(Response::failure(
        application_install::OPERATION,
        code,
        message,
    ))
}

#[cfg(unix)]
fn install(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    use crate::filesystem::ManagedRoot;
    let Ok(config) = crate::config::EngineConfig::load_root_owned(std::path::Path::new(
        "/etc/operations-engine/config.json",
    )) else {
        return fail(
            ErrorCode::Internal,
            crate::commands::CONFIG_UNAVAILABLE_MESSAGE,
        );
    };
    let Ok(json) = read_root_owned_content_file(path) else {
        return fail(
            ErrorCode::InvalidInput,
            "request-file must be a root-owned regular file",
        );
    };
    let Ok(request) = application_install::Request::parse(&json, request_id, idempotency_key)
    else {
        return fail(
            ErrorCode::InvalidInput,
            "request-file is not a valid application install plan",
        );
    };
    let Some(content_root) = config
        .content_roots
        .iter()
        .find(|root| request.project_root().starts_with(root.as_path()))
    else {
        return fail(
            ErrorCode::InvalidInput,
            "the project root is outside configured content roots",
        );
    };
    let Ok(state) = ManagedRoot::open(&config.state_root) else {
        return fail(ErrorCode::Internal, "engine state root is unavailable");
    };
    let context = application_install::Context {
        engine_state: &state,
        docker_program: "docker",
    };
    match application_install::execute(
        &context,
        content_root,
        &request,
        &crate::process::CancellationToken::default(),
    ) {
        Ok(value) | Err(application_install::Error::PostCommit { result: value }) => {
            Response::success(application_install::OPERATION, value)
        }
        Err(error) => {
            let (code, message) = error.protocol();
            fail(code, &message)
        }
    }
}

#[cfg(not(unix))]
fn install(
    path: &std::path::Path,
    request_id: &str,
    idempotency_key: Option<&str>,
) -> Result<Response, ResponseBuildError> {
    let _ = (path, request_id, idempotency_key);
    fail(
        ErrorCode::UnsupportedPlatform,
        "application.install requires a Unix host",
    )
}
