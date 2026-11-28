//! Hosted Node applications: one container per application (R4).
//!
//! `node.deployApp` takes the server artifact of a `node.build` (with
//! `server: true`), installs its production dependencies from the lockfile in
//! a throw-away sandbox, starts the application in its own container on its
//! own network, waits until the container's health check passes, points the
//! domain's ingress route at it and checks that the ingress reaches it. A
//! failure at any step puts the previous container and route back; nothing
//! half-done stays. `node.appStatus` reads the container state, and
//! `node.restartApp` / `node.removeApp` act on it.
//!
//! The container runs as the site's non-root identity with all capabilities
//! dropped, `no-new-privileges`, a read-only root file system (the release is
//! mounted read-only; only `/tmp` and the application's data directory are
//! writable), memory and PID limits and bounded logs. It publishes no host
//! port and shares a network only with the ingress. The command is fixed by
//! the adapter (`node ./dist/server/entry.mjs` for `astro-node`); a request
//! never supplies a command. Secrets travel only in the request file and a
//! root-only env file that is deleted once the container exists; they are
//! never in argv, logs, the response or the journal.

use crate::{
    compose,
    docker_resource::ImageReference,
    error::ErrorCode,
    filesystem::ManagedRoot,
    ingress::{self, ConfigHash, HashGuard, RouteTarget},
    mutation::preflight,
    node_build::{
        ARTIFACT_LIMITS, Copied, CopyRules, copy_tree, exited_ok, root_owner, sandbox_run_args,
        skip_nothing,
    },
    node_ingress::{self, APP_PORT},
    node_pm::PackageManager,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest,
        SubprocessDiagnostics,
    },
    site::{Domain, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const DEPLOY: &str = "node.deployApp";
pub const STATUS: &str = "node.appStatus";
pub const RESTART: &str = "node.restartApp";
pub const REMOVE: &str = "node.removeApp";

/// The ingress container of the managed stack (also named by
/// `site.publishStatic`).
pub const INGRESS_CONTAINER: &str = "wcp-ingress-1";
/// The host directory the ingress mounts read-only as `/srv/wcp-static`.
pub const STATIC_ROOT: &str = "/var/lib/wcp-static";
const LABEL_APP: &str = "wcp.node-app";
const LABEL_RELEASE: &str = "wcp.node-release";
const DEFAULT_MEMORY_MB: u32 = 512;
const MEMORY_MB: std::ops::RangeInclusive<u32> = 256..=4096;
const MAX_ENV: usize = 32;
const MAX_ENV_VALUE: usize = 4096;
const KEEP_RELEASES: usize = 2;
const INSTALL_TIMEOUT: Duration = Duration::from_secs(900);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_GRACE: &str = "20";
const MAX_OUTPUT: usize = 64 * 1024;
/// Environment names the engine sets itself.
const RESERVED_ENV: [&str; 8] = [
    "HOST",
    "PORT",
    "NODE_ENV",
    "HOME",
    "PATH",
    "NODE_OPTIONS",
    "WCP_DATA_DIR",
    "TMPDIR",
];

/// A server layout the engine knows how to start. The entry point is fixed;
/// there is no guessed `npm start`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Adapter {
    /// `@astrojs/node` in standalone mode (EmDash and plain Astro SSR).
    AstroNode,
}

impl Adapter {
    fn parse(value: &str) -> Option<Self> {
        (value == "astro-node").then_some(Self::AstroNode)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::AstroNode => "astro-node",
        }
    }

    /// The file whose presence proves the artifact has this layout.
    const fn entry(self) -> &'static str {
        match self {
            Self::AstroNode => "dist/server/entry.mjs",
        }
    }

    const fn command(self) -> &'static [&'static str] {
        match self {
            Self::AstroNode => &["node", "./dist/server/entry.mjs"],
        }
    }
}

// ───────────────────────────── requests ─────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeployPlan {
    domain: String,
    project_root: String,
    /// A `node.build` artifact to release. Exactly one of `build_id` and
    /// `release_id` is given.
    #[serde(default)]
    build_id: Option<String>,
    /// A release this engine kept from an earlier deploy: started again
    /// without a build or an install (a manual rollback).
    #[serde(default)]
    release_id: Option<String>,
    image: String,
    uid: u32,
    gid: u32,
    adapter: String,
    #[serde(default)]
    memory_mb: Option<u32>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    secret_env: BTreeMap<String, String>,
}

/// Where a deploy takes its files from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeploySource {
    /// A new release made from the artifact of a build.
    Build(RequestId),
    /// A release that already exists on the host.
    Release(RequestId),
}

pub struct DeployRequest {
    pub domain: Domain,
    project_root: PathBuf,
    source: DeploySource,
    image: ImageReference,
    uid: u32,
    gid: u32,
    adapter: Adapter,
    memory_mb: u32,
    env: BTreeMap<String, String>,
    secret_env: BTreeMap<String, String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl std::fmt::Debug for DeployRequest {
    /// Never prints the secret values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeployRequest")
            .field("domain", &self.domain)
            .field("secret_env", &self.secret_env.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidDomain,
    InvalidRoot,
    InvalidBuildId,
    InvalidImage,
    InvalidIdentity,
    InvalidAdapter,
    InvalidLimit,
    InvalidEnv,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

fn valid_env_name(name: &str) -> bool {
    let first = |b: u8| b.is_ascii_uppercase();
    let rest = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_';
    crate::util::charset_ok(name, 64, first, rest) && !RESERVED_ENV.contains(&name)
}

fn valid_env(map: &BTreeMap<String, String>) -> bool {
    map.len() <= MAX_ENV
        && map.iter().all(|(name, value)| {
            valid_env_name(name)
                && value.len() <= MAX_ENV_VALUE
                && !value.chars().any(char::is_control)
        })
}

fn ids(
    request_id: &str,
    key: Option<&str>,
) -> Result<(RequestId, Option<IdempotencyKey>), RequestError> {
    Ok((
        RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
        key.map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?,
    ))
}

impl DeployRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: DeployPlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let domain = Domain::parse(&plan.domain).map_err(|_| RequestError::InvalidDomain)?;
        let project_root = PathBuf::from(&plan.project_root);
        if plan.project_root.len() > 4096
            || plan.project_root.chars().any(char::is_control)
            || TrustedRoot::parse(&project_root).is_err()
        {
            return Err(RequestError::InvalidRoot);
        }
        let image = ImageReference::parse(&plan.image).map_err(|_| RequestError::InvalidImage)?;
        if !image.as_str().contains("@sha256:") {
            return Err(RequestError::InvalidImage);
        }
        if plan.uid == 0 || plan.gid == 0 || plan.uid == u32::MAX || plan.gid == u32::MAX {
            return Err(RequestError::InvalidIdentity);
        }
        let memory_mb = plan.memory_mb.unwrap_or(DEFAULT_MEMORY_MB);
        if !MEMORY_MB.contains(&memory_mb) {
            return Err(RequestError::InvalidLimit);
        }
        if !valid_env(&plan.env)
            || !valid_env(&plan.secret_env)
            || plan
                .env
                .keys()
                .any(|name| plan.secret_env.contains_key(name))
        {
            return Err(RequestError::InvalidEnv);
        }
        let (request_id, idempotency_key) = ids(request_id, key)?;
        let parse_id =
            |value: &str| RequestId::parse(value).map_err(|_| RequestError::InvalidBuildId);
        let source = match (&plan.build_id, &plan.release_id) {
            (Some(build), None) => DeploySource::Build(parse_id(build)?),
            (None, Some(release)) => DeploySource::Release(parse_id(release)?),
            _ => return Err(RequestError::InvalidBuildId),
        };
        Ok(Self {
            domain,
            project_root,
            source,
            image,
            uid: plan.uid,
            gid: plan.gid,
            adapter: Adapter::parse(&plan.adapter).ok_or(RequestError::InvalidAdapter)?,
            memory_mb,
            env: plan.env,
            secret_env: plan.secret_env,
            request_id,
            idempotency_key,
        })
    }

    pub fn root(&self) -> &Path {
        &self.project_root
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DomainPlan {
    domain: String,
    #[serde(default)]
    delete_data: bool,
}

/// `node.restartApp`, `node.removeApp` and `node.appStatus` name one domain.
#[derive(Debug)]
pub struct DomainRequest {
    pub domain: Domain,
    pub delete_data: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl DomainRequest {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: DomainPlan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let (request_id, idempotency_key) = ids(request_id, key)?;
        Ok(Self {
            domain: Domain::parse(&plan.domain).map_err(|_| RequestError::InvalidDomain)?,
            delete_data: plan.delete_data,
            request_id,
            idempotency_key,
        })
    }
}

// ───────────────────────────── results ─────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployResult {
    pub domain: String,
    pub release_id: RequestId,
    pub container: String,
    pub network: String,
    pub image: String,
    pub port: u16,
    pub health: String,
    pub deployed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartResult {
    pub domain: String,
    pub health: String,
    pub restarted_at_unix_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveResult {
    pub domain: String,
    /// `false` when the domain's route was not this engine's Node route and was
    /// therefore left alone.
    pub route_removed: bool,
    pub data_deleted: bool,
    pub removed_at_unix_secs: u64,
}

/// What `node.appStatus` knows. A field the engine could not read is `None`
/// (unknown), never a guess; a missing container is `state: "absent"`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    pub domain: String,
    /// `running`, `restarting`, `paused`, `exited`, `created`, `dead` or
    /// `absent`.
    pub state: String,
    /// `healthy`, `unhealthy`, `starting` or `none` (no health check).
    pub health: Option<String>,
    pub restart_count: Option<u64>,
    pub started_at: Option<String>,
    pub image: Option<String>,
    pub release_id: Option<String>,
    /// Whether the domain's route is exactly the engine's Node route.
    pub route_managed: Option<bool>,
    /// The releases kept on the host, newest first: what a rollback can
    /// start. `None` when the directory could not be read.
    pub releases: Option<Vec<String>>,
}

// ───────────────────────────── errors ─────────────────────────────

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Host path of the engine state root (bind-mount sources).
    pub state_path: &'a Path,
    pub ingress_root: &'a TrustedRoot,
    /// The host directory the ingress serves read-only as `/srv/wcp-static`.
    pub static_root: &'a TrustedRoot,
    pub compose: &'a compose::Access,
    pub docker_program: &'a str,
    pub poll_interval: Duration,
    pub health_timeout: Duration,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Cancelled,
    Run(process::ProcessRunError),
    /// The request cannot be served as asked (missing artifact, layout).
    Project(&'static str),
    /// The host is not in a state the operation can work with (foreign
    /// route, ingress container missing).
    Conflict(&'static str),
    /// A docker step failed; `step` names it.
    Docker {
        step: &'static str,
        diagnostics: SubprocessDiagnostics,
    },
    /// The application did not become healthy.
    Unhealthy(&'static str),
    Route(String),
    /// The operation failed and undoing it also failed in part.
    RollbackIncomplete(Box<Error>),
    PostCommit {
        result: serde_json::Value,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another operation is already in progress for this application".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (ErrorCode::Cancelled, "cancelled".into()),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run docker".into(),
            ),
            Self::Project(message) => (ErrorCode::InvalidInput, (*message).into()),
            Self::Conflict(message) => (ErrorCode::Conflict, (*message).into()),
            Self::Docker { step, diagnostics } => {
                let code = if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                };
                let suffix = if diagnostics.timed_out {
                    " (timed out)".to_owned()
                } else if let Some(exit) = diagnostics.exit_code {
                    format!(" (exit code {exit})")
                } else {
                    String::new()
                };
                (code, format!("{step} failed{suffix}"))
            }
            Self::Unhealthy(message) => (ErrorCode::SubprocessFailed, (*message).into()),
            Self::Route(message) => (ErrorCode::ConfigReloadFailed, message.clone()),
            Self::RollbackIncomplete(cause) => (
                ErrorCode::RollbackIncomplete,
                format!("{}; undoing it also failed", cause.protocol().1),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => (
                ErrorCode::Internal,
                "internal Node application error".into(),
            ),
        }
    }
}

// ───────────────────────────── docker ─────────────────────────────

fn docker(
    ctx: &Context<'_>,
    args: &[String],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout,
            max_stdout_bytes: MAX_OUTPUT,
            max_stderr_bytes: MAX_OUTPUT,
        },
        cancel,
    )
    .map_err(Error::Run)
}

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

/// A docker step that must succeed.
fn docker_ok(
    ctx: &Context<'_>,
    step: &'static str,
    args: &[String],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let output = docker(ctx, args, timeout, cancel)?;
    if exited_ok(&output) {
        Ok(output)
    } else {
        Err(Error::Docker {
            step,
            diagnostics: SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        })
    }
}

/// Best effort, for undoing: failures are reported to the caller as a bool.
fn docker_quiet(ctx: &Context<'_>, args: &[String]) -> bool {
    docker(ctx, args, DOCKER_TIMEOUT, &CancellationToken::default())
        .is_ok_and(|output| exited_ok(&output))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Facts {
    status: String,
    health: String,
    restart_count: u64,
    started_at: String,
    image: String,
    release: String,
}

/// Fields only: the container's environment, which can hold secrets, is never
/// read.
const INSPECT_FORMAT: &str = "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.Config.Image}}|{{index .Config.Labels \"wcp.node-release\"}}";

fn parse_facts(text: &str) -> Option<Facts> {
    let parts: Vec<&str> = text.trim().split('|').collect();
    let [status, health, restarts, started, image, release] = parts[..] else {
        return None;
    };
    Some(Facts {
        status: status.to_owned(),
        health: health.to_owned(),
        restart_count: restarts.parse().ok()?,
        started_at: started.to_owned(),
        image: image.to_owned(),
        release: release.to_owned(),
    })
}

/// `Ok(None)`: the container does not exist. Any other failure is an error,
/// not "absent".
fn inspect(ctx: &Context<'_>, name: &str) -> Result<Option<Facts>, Error> {
    let output = docker(
        ctx,
        &argv(&["container", "inspect", "--format", INSPECT_FORMAT, name]),
        DOCKER_TIMEOUT,
        &CancellationToken::default(),
    )?;
    if exited_ok(&output) {
        return parse_facts(&output.stdout.text())
            .map(Some)
            .ok_or(Error::Io(io::Error::other("unreadable container state")));
    }
    if output.stderr.text().contains("No such") {
        return Ok(None);
    }
    Err(Error::Docker {
        step: "docker inspect",
        diagnostics: SubprocessDiagnostics::from_output(ctx.docker_program, &output),
    })
}

fn wait_healthy(ctx: &Context<'_>, name: &str, cancel: &CancellationToken) -> Result<(), Error> {
    let started = std::time::Instant::now();
    loop {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        match inspect(ctx, name)? {
            None => return Err(Error::Unhealthy("the application container disappeared")),
            Some(facts) => {
                if matches!(facts.status.as_str(), "exited" | "dead") {
                    return Err(Error::Unhealthy(
                        "the application exited before it was healthy",
                    ));
                }
                match facts.health.as_str() {
                    "healthy" => return Ok(()),
                    "unhealthy" => {
                        return Err(Error::Unhealthy("the application health check failed"));
                    }
                    _ => {}
                }
            }
        }
        if started.elapsed() >= ctx.health_timeout {
            return Err(Error::Unhealthy(
                "the application did not become healthy in time",
            ));
        }
        std::thread::sleep(ctx.poll_interval);
    }
}

// ───────────────────────────── paths ─────────────────────────────

fn rel(path: impl Into<String>) -> SiteRelativePath {
    SiteRelativePath::parse(path.into()).unwrap()
}

struct Scope {
    root: ManagedRoot,
    /// Host path of the scope directory.
    dir: PathBuf,
}

fn open_scope(ctx: &Context<'_>, domain: &Domain) -> Result<Scope, Error> {
    let scope_rel = rel(format!("node-app/{domain}"));
    ctx.engine_state
        .create_dir_all(&scope_rel)
        .map_err(Error::Io)?;
    let root = ctx
        .engine_state
        .open_managed_dir(&scope_rel)
        .map_err(Error::Io)?;
    root.set_own_mode(0o700).map_err(Error::Io)?;
    for child in [
        "locks",
        "transactions",
        "audit",
        "releases",
        "data",
        "secrets",
    ] {
        root.create_dir_all(&rel(child)).map_err(Error::Io)?;
    }
    Ok(Scope {
        root,
        dir: ctx.state_path.join("node-app").join(domain.as_str()),
    })
}

fn fresh() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn route_path(domain: &Domain) -> SiteRelativePath {
    rel(format!("{domain}.caddyfile"))
}

fn read_route(ctx: &Context<'_>, name: &SiteRelativePath) -> Result<Option<String>, Error> {
    let root = ManagedRoot::open(ctx.ingress_root).map_err(Error::Io)?;
    let file = match root.open_regular_read(name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Conflict("the ingress route cannot be read")),
    };
    let bytes = crate::util::read_bounded(file, 262_144)
        .map_err(Error::Io)?
        .ok_or(Error::Conflict("the ingress route is too large"))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| Error::Conflict("the ingress route is not valid text"))
}

fn activate_route(
    ctx: &Context<'_>,
    domain: &Domain,
    content: &str,
    previous: Option<&str>,
) -> Result<(), Error> {
    let guard = previous
        .map(|text| HashGuard::Sha256(ConfigHash::of(text.as_bytes())))
        .unwrap_or(HashGuard::Absent);
    ingress::activate::activate(
        ctx.ingress_root,
        domain,
        content,
        &guard,
        RouteTarget::Live,
        &fresh(),
        ctx.compose,
    )
    .map(|_| ())
    .map_err(|error| {
        use ingress::activate::{ComposeFailure, Error as E};
        // Which stage failed and how the command ended; never the Caddy
        // output, which can quote the route.
        let how = |failure: &ComposeFailure| match failure {
            ComposeFailure::Run(_) => "docker compose could not be run".to_owned(),
            ComposeFailure::Rejected(d) if d.timed_out => "timed out".to_owned(),
            ComposeFailure::Rejected(d) => match d.exit_code {
                Some(code) => format!("exit code {code}"),
                None => "no exit code".to_owned(),
            },
        };
        Error::Route(match error {
            E::HashGuardMismatch => {
                "the domain's route changed while the application was deployed".to_owned()
            }
            E::ValidateFailed(f) => format!(
                "the ingress validation rejected the application route ({})",
                how(&f)
            ),
            E::ReloadFailedAndRestored(f) | E::ReloadFailedUnchanged(f) => {
                format!(
                    "the ingress reload failed ({}); the previous route is live",
                    how(&f)
                )
            }
            E::RecoveryFailed { reload, .. } => format!(
                "the ingress reload failed ({}) and the previous route is not restored",
                how(&reload)
            ),
            E::Io(_) | E::Path(_) => "the route file could not be written".to_owned(),
        })
    })
}

fn remove_route(ctx: &Context<'_>, domain: &Domain, current: &str) -> Result<(), Error> {
    let request = ingress::RemoveRouteRequest::parse(
        domain.as_str(),
        ConfigHash::of(current.as_bytes()).as_str(),
        None,
        &fresh(),
        None,
    )
    .map_err(|_| Error::Route("the route cannot be removed".into()))?;
    let context = ingress::execute::ActivateContext {
        ingress_root: ctx.ingress_root,
        engine_state: ctx.engine_state,
        compose: ctx.compose,
    };
    ingress::remove::remove(&context, &request)
        .map(|_| ())
        .map_err(|_| Error::Route("the route cannot be removed".into()))
}

/// The status code the ingress itself gets for `/` of the domain.
fn probe_through_ingress(ctx: &Context<'_>, domain: &Domain) -> Result<(), Error> {
    let resolve = format!("{domain}:443:127.0.0.1");
    let url = format!("https://{domain}/");
    let output = ctx
        .compose
        .exec(
            "ingress",
            &[
                "curl",
                "--silent",
                "--insecure",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--max-time",
                "15",
                "--resolve",
                &resolve,
                &url,
            ],
        )
        .map_err(|_| Error::Route("the ingress check could not run".into()))?;
    let text = output.stdout.text();
    let code: u16 = text.trim().parse().unwrap_or(0);
    if exited_ok(&output) && (100..500).contains(&code) {
        Ok(())
    } else {
        Err(Error::Route(
            "the ingress did not reach the application".into(),
        ))
    }
}

// ───────────────────────────── transaction ─────────────────────────────

/// Preflight, one recorded transaction and audit around `action`, like every
/// other engine mutation; a replay returns the recorded result.
fn transact(
    scope: &Scope,
    operation: &'static str,
    request_id: RequestId,
    key: Option<&IdempotencyKey>,
    action: impl FnOnce() -> Result<serde_json::Value, Error>,
) -> Result<serde_json::Value, Error> {
    let admitted =
        match preflight::run(&scope.root, request_id, key, operation).map_err(Error::Preflight)? {
            preflight::Outcome::Replay(id) => return replay(&scope.root, id, operation),
            preflight::Outcome::Proceed(value) => value,
        };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = rel(format!("transactions/{request_id}.json"));
    let audit_path = rel("audit/events.jsonl");
    let outcome = action();
    match outcome {
        Err(error) => {
            let (code, message) = error.protocol();
            let _ = state.mark_failed(code, message);
            let _ = state::save(&scope.root, &state_path, &state);
            let _ = audit::append(
                &scope.root,
                &audit_path,
                &AuditRecord::result(request_id, false, Some(code)),
            );
            Err(error)
        }
        Ok(result) => {
            state.mark_committed(result.clone()).unwrap();
            if state::save(&scope.root, &state_path, &state).is_err() {
                drop(lock);
                return Err(Error::PostCommit { result });
            }
            let _ = audit::append(
                &scope.root,
                &audit_path,
                &AuditRecord::result(request_id, true, None),
            );
            drop(lock);
            Ok(result)
        }
    }
}

fn replay(
    scope: &ManagedRoot,
    id: RequestId,
    operation: &'static str,
) -> Result<serde_json::Value, Error> {
    let loaded = state::load(scope, &rel(format!("transactions/{id}.json")))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or(Error::Io(io::Error::other("missing recorded result"))),
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ───────────────────────────── deploy ─────────────────────────────

/// What a failed deploy has to undo.
#[derive(Default)]
struct Progress {
    release: bool,
    new_container: bool,
    /// The previous container was renamed aside; whether it was running.
    previous: Option<bool>,
    /// The route text before this deploy, once the route was changed.
    route_changed: Option<Option<String>>,
}

fn run_args(
    ctx: &Context<'_>,
    req: &DeployRequest,
    scope: &Scope,
    release: &str,
    env_file: Option<&Path>,
) -> Vec<String> {
    let container = node_ingress::container_name(&req.domain);
    let mut args = argv(&[
        "run",
        "--detach",
        "--init",
        "--restart",
        "unless-stopped",
        "--name",
    ]);
    args.push(container);
    for part in [
        "--user".to_owned(),
        format!("{}:{}", req.uid, req.gid),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--read-only".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,size=256m".into(),
        "--pids-limit".into(),
        "512".into(),
        "--memory".into(),
        format!("{}m", req.memory_mb),
        "--memory-swap".into(),
        format!("{}m", req.memory_mb),
        "--cpu-shares".into(),
        "512".into(),
        "--log-opt".into(),
        "max-size=10m".into(),
        "--log-opt".into(),
        "max-file=3".into(),
        "--network".into(),
        node_ingress::network_name(&req.domain),
        "--label".into(),
        format!("{LABEL_APP}={}", req.domain),
        "--label".into(),
        format!("{LABEL_RELEASE}={release}"),
        "--mount".into(),
        format!(
            "type=bind,source={},target=/app,readonly",
            scope.dir.join("releases").join(release).display()
        ),
        "--mount".into(),
        format!(
            "type=bind,source={},target=/data",
            scope.dir.join("data").display()
        ),
        "--workdir".into(),
        "/app".into(),
        "--env".into(),
        "NODE_ENV=production".into(),
        "--env".into(),
        "HOST=0.0.0.0".into(),
        "--env".into(),
        format!("PORT={APP_PORT}"),
        "--env".into(),
        "HOME=/tmp".into(),
        "--env".into(),
        "WCP_DATA_DIR=/data".into(),
        "--health-cmd".into(),
        format!(
            "node -e \"fetch('http://127.0.0.1:{APP_PORT}/').then(r=>process.exit(r.status<500?0:1)).catch(()=>process.exit(1))\""
        ),
        "--health-interval".into(),
        "10s".into(),
        "--health-timeout".into(),
        "5s".into(),
        "--health-retries".into(),
        "3".into(),
        "--health-start-period".into(),
        "15s".into(),
    ] {
        args.push(part);
    }
    for (name, value) in &req.env {
        args.push("--env".into());
        args.push(format!("{name}={value}"));
    }
    if let Some(file) = env_file {
        args.push("--env-file".into());
        args.push(file.display().to_string());
    }
    let _ = ctx;
    args.push(req.image.as_str().to_owned());
    args.extend(req.adapter.command().iter().map(|word| (*word).to_owned()));
    args
}

/// How long the hashed files of an earlier release stay published: a page
/// cached by a browser still points at them.
const KEEP_HASHED: Duration = Duration::from_secs(30 * 24 * 3600);

/// Names the published copy leaves out: dot files, pages (the application
/// renders those) and anything executable or source-like that has no place in
/// a public file tree.
fn not_published(name: &str) -> bool {
    name.starts_with('.')
        || [
            ".html", ".htm", ".php", ".phtml", ".mjs", ".cjs", ".map", ".sql", ".sh", ".env",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Publishes the build's client files (`dist/client`) for the ingress to
/// serve directly, as `<static root>/<domain>-assets/`. The copy is staged
/// beside the live one and swapped in by renames; between the two renames a
/// request for a published file is not found there and goes to the
/// application. The hashed files (`_astro/`) of the previous copy that are
/// newer than [`KEEP_HASHED`] are carried over, so a page cached before the
/// deploy still finds its files. A release without `dist/client` publishes
/// nothing. Returns whether anything was published.
fn publish_assets(
    ctx: &Context<'_>,
    domain: &Domain,
    release: &ManagedRoot,
) -> Result<bool, Error> {
    let open = |from: &ManagedRoot, name: &str| match from.open_child_dir_nofollow(&rel(name)) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    };
    let Some(dist) = open(release, "dist")? else {
        return Ok(false);
    };
    let Some(client) = open(&dist, "client")? else {
        return Ok(false);
    };
    let static_root = ManagedRoot::open(ctx.static_root).map_err(Error::Io)?;
    let name = node_ingress::assets_dir_name(domain);
    let (live, staged, old) = (
        rel(&name),
        rel(format!("{name}.new")),
        rel(format!("{name}.old")),
    );
    for leftover in [&staged, &old] {
        if static_root.symlink_metadata(leftover).is_ok() {
            static_root.remove_dir_all(leftover).map_err(Error::Io)?;
        }
    }
    static_root.create_dir(&staged).map_err(Error::Io)?;
    static_root.set_mode(&staged, 0o755).map_err(Error::Io)?;
    let to = static_root.open_managed_dir(&staged).map_err(Error::Io)?;
    let mut copied = Copied::default();
    if let Err(error) = copy_tree(
        &client,
        &to,
        &CopyRules {
            skip: not_published,
            owner: None,
            max_entries: ARTIFACT_LIMITS.0,
            max_bytes: ARTIFACT_LIMITS.1,
        },
        0,
        &mut copied,
    ) {
        let _ = static_root.remove_dir_all(&staged);
        return Err(match error {
            crate::node_build::Error::Io(io) => Error::Io(io),
            _ => Error::Project("the client files cannot be published"),
        });
    }
    if let Ok(Some(previous)) = open_existing(&static_root, &live) {
        carry_hashed(&previous, &to);
    }
    if static_root.symlink_metadata(&live).is_ok() {
        static_root.rename(&live, &old).map_err(Error::Io)?;
    }
    static_root.rename(&staged, &live).map_err(Error::Io)?;
    let _ = static_root.remove_dir_all(&old);
    Ok(true)
}

fn open_existing(
    root: &ManagedRoot,
    name: &SiteRelativePath,
) -> Result<Option<ManagedRoot>, io::Error> {
    match root.open_managed_dir(name) {
        Ok(dir) => Ok(Some(dir)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Moves the hashed files of the previous copy that the new one does not have
/// and that are younger than [`KEEP_HASHED`] into the new copy. Best effort:
/// a file that cannot be moved is simply not kept.
fn carry_hashed(previous: &ManagedRoot, to: &ManagedRoot) {
    let astro = rel("_astro");
    let Ok(Some(from_dir)) = open_existing(previous, &astro) else {
        return;
    };
    if !to.exists(&astro) && (to.create_dir(&astro).is_err() || to.set_mode(&astro, 0o755).is_err())
    {
        return;
    }
    let Ok(Some(to_dir)) = open_existing(to, &astro) else {
        return;
    };
    let Ok(children) = from_dir.child_entries_bounded(ARTIFACT_LIMITS.0) else {
        return;
    };
    for child in children.into_iter().filter(|c| !c.is_dir) {
        let Some(file) = child
            .name
            .to_str()
            .and_then(|n| SiteRelativePath::parse(n).ok())
        else {
            continue;
        };
        let young = from_dir
            .modified(&file)
            .ok()
            .and_then(|at| at.elapsed().ok())
            .is_some_and(|age| age < KEEP_HASHED);
        if young && to_dir.symlink_metadata(&file).is_err() {
            let _ = from_dir.rename_to(&file, &to_dir, &file);
        }
    }
}

/// Makes a new release from a build artifact: copies it and installs the
/// production dependencies with the project's package manager in a sandbox.
fn install_release(
    ctx: &Context<'_>,
    req: &DeployRequest,
    scope: &Scope,
    progress: &mut Progress,
    artifact: &ManagedRoot,
    manager: PackageManager,
    cancel: &CancellationToken,
) -> Result<(String, ManagedRoot), Error> {
    let id = req.request_id;
    let release_id = id.to_string();
    let release_rel = rel(format!("releases/{release_id}"));
    scope.root.create_dir(&release_rel).map_err(Error::Io)?;
    progress.release = true;
    let owner = root_owner(req.uid, req.gid);
    if let Some((uid, gid)) = owner {
        scope
            .root
            .chown(&release_rel, uid, gid)
            .map_err(Error::Io)?;
    }
    scope
        .root
        .set_mode(&release_rel, 0o755)
        .map_err(Error::Io)?;
    let release = scope
        .root
        .open_managed_dir(&release_rel)
        .map_err(Error::Io)?;
    let mut copied = Copied::default();
    copy_tree(
        artifact,
        &release,
        &CopyRules {
            skip: skip_nothing,
            owner,
            max_entries: ARTIFACT_LIMITS.0,
            max_bytes: ARTIFACT_LIMITS.1,
        },
        0,
        &mut copied,
    )
    .map_err(|error| match error {
        crate::node_build::Error::Io(io) => Error::Io(io),
        _ => Error::Project("the build artifact cannot be copied"),
    })?;
    let release_dir = scope.dir.join("releases").join(&release_id);
    let install_name = format!("wcp-node-install-{id}");
    let mut install = sandbox_run_args(
        &install_name,
        (req.uid, req.gid),
        req.memory_mb.max(1024),
        release_dir
            .to_str()
            .ok_or(Error::Io(io::Error::other("path")))?,
        req.image.as_str(),
    );
    install.extend(manager.install_production());
    let output = docker(ctx, &install, INSTALL_TIMEOUT, cancel)?;
    if !exited_ok(&output) {
        docker_quiet(ctx, &argv(&["rm", "-f", &install_name]));
        return Err(Error::Docker {
            step: manager.install_phase(),
            diagnostics: SubprocessDiagnostics::from_output(ctx.docker_program, &output),
        });
    }
    Ok((release_id, release))
}

fn deploy_steps(
    ctx: &Context<'_>,
    req: &DeployRequest,
    scope: &Scope,
    progress: &mut Progress,
    cancel: &CancellationToken,
) -> Result<DeployResult, Error> {
    let id = req.request_id;
    let domain = &req.domain;
    let container = node_ingress::container_name(domain);
    let previous_name = format!("{container}-previous");
    let network = node_ingress::network_name(domain);

    // The files, by id: no path comes from the request. A build artifact
    // becomes a new release below; a kept release is started as it is.
    let (artifact, manager) = match req.source {
        DeploySource::Build(build_id) => {
            let hash = crate::transaction::resource_lock::canonical_hash(&req.project_root);
            let artifact = ctx
                .engine_state
                .open_managed_dir(&rel(format!("node-build/{hash}/artifacts/{build_id}")))
                .map_err(|_| Error::Project("the build artifact does not exist"))?;
            let manager = PackageManager::detect(&artifact).map_err(|_| {
                Error::Project(
                    "the build artifact is not a server build (build it with server: true)",
                )
            })?;
            for needed in ["package.json", req.adapter.entry()] {
                if !artifact.exists(&rel(needed)) {
                    return Err(Error::Project(
                        "the build artifact is not a server build (build it with server: true)",
                    ));
                }
            }
            (Some(artifact), Some(manager))
        }
        DeploySource::Release(_) => (None, None),
    };

    // The ingress must be up, and the domain's route must be free or ours.
    match inspect(ctx, INGRESS_CONTAINER)? {
        Some(facts) if facts.status == "running" => {}
        _ => return Err(Error::Conflict("the ingress container is not running")),
    }
    let live = route_path(domain);
    for suffix in ["caddyfile.disabled", "maintenance-backup"] {
        if read_route(ctx, &rel(format!("{domain}.{suffix}")))?.is_some() {
            return Err(Error::Conflict(
                "the domain's route is disabled or parked; it cannot be replaced",
            ));
        }
    }
    let wanted = node_ingress::render(domain);
    let previous_route = read_route(ctx, &live)?;
    if previous_route
        .as_deref()
        .is_some_and(|text| !node_ingress::is_managed(domain, text))
    {
        return Err(Error::Conflict(
            "the domain already has a route that is not managed Node hosting",
        ));
    }

    // 1. The release: the artifact, copied, with production dependencies
    //    installed from the lockfile in a sandbox (or a kept release, as it
    //    is). The data directory belongs to the application's identity.
    if let Some((uid, gid)) = root_owner(req.uid, req.gid) {
        scope
            .root
            .chown(&rel("data"), uid, gid)
            .map_err(Error::Io)?;
    }
    scope
        .root
        .set_mode(&rel("data"), 0o750)
        .map_err(Error::Io)?;
    let (release_id, release) = match (&artifact, manager) {
        (Some(artifact), Some(manager)) => {
            install_release(ctx, req, scope, progress, artifact, manager, cancel)?
        }
        _ => {
            let DeploySource::Release(kept) = req.source else {
                return Err(Error::Project("the release source is not usable"));
            };
            let release = scope
                .root
                .open_managed_dir(&rel(format!("releases/{kept}")))
                .map_err(|_| Error::Project("the release does not exist (it was removed)"))?;
            for needed in ["package.json", req.adapter.entry()] {
                if !release.exists(&rel(needed)) {
                    return Err(Error::Project("the release is incomplete"));
                }
            }
            (kept.to_string(), release)
        }
    };

    // 2. The application's own network, joined by the ingress.
    let exists = docker(
        ctx,
        &argv(&["network", "inspect", "--format", "{{.Name}}", &network]),
        DOCKER_TIMEOUT,
        cancel,
    )?;
    if !exited_ok(&exists) {
        docker_ok(
            ctx,
            "docker network create",
            &argv(&[
                "network",
                "create",
                "--label",
                &format!("{LABEL_APP}={domain}"),
                &network,
            ]),
            DOCKER_TIMEOUT,
            cancel,
        )?;
    }
    let connect = docker(
        ctx,
        &argv(&["network", "connect", &network, INGRESS_CONTAINER]),
        DOCKER_TIMEOUT,
        cancel,
    )?;
    if !exited_ok(&connect) && !connect.stderr.text().contains("already exists") {
        return Err(Error::Docker {
            step: "docker network connect",
            diagnostics: SubprocessDiagnostics::from_output(ctx.docker_program, &connect),
        });
    }

    // 3. The previous container steps aside (kept, stopped, for the undo).
    docker_quiet(ctx, &argv(&["rm", "-f", &previous_name]));
    if let Some(facts) = inspect(ctx, &container)? {
        docker_ok(
            ctx,
            "docker rename",
            &argv(&["rename", &container, &previous_name]),
            DOCKER_TIMEOUT,
            cancel,
        )?;
        progress.previous = Some(facts.status == "running");
        docker_ok(
            ctx,
            "docker stop",
            &argv(&["stop", "--time", STOP_GRACE, &previous_name]),
            Duration::from_secs(90),
            cancel,
        )?;
    }

    // 4. The new container. Secrets reach it through a root-only env file that
    //    is removed as soon as the container exists.
    let secrets_rel = rel(format!("secrets/{id}.env"));
    let env_path = scope.dir.join("secrets").join(format!("{id}.env"));
    let env_file = if req.secret_env.is_empty() {
        None
    } else {
        let mut text = String::new();
        for (name, value) in &req.secret_env {
            text.push_str(&format!("{name}={value}\n"));
        }
        scope
            .root
            .write_atomic_private(&secrets_rel, text.as_bytes())
            .map_err(Error::Io)?;
        Some(env_path.as_path())
    };
    let started = docker(
        ctx,
        &run_args(ctx, req, scope, &release_id, env_file),
        Duration::from_secs(120),
        cancel,
    );
    if env_file.is_some() {
        let _ = scope.root.remove_file(&secrets_rel);
    }
    let started = started?;
    progress.new_container = true;
    if !exited_ok(&started) {
        return Err(Error::Docker {
            step: "docker run",
            diagnostics: SubprocessDiagnostics::from_output(ctx.docker_program, &started),
        });
    }
    wait_healthy(ctx, &container, cancel)?;

    // 5. The hashed client files go where the ingress serves them from, then
    //    the route, then proof through the ingress itself. A file the ingress
    //    cannot find there still reaches the application.
    publish_assets(ctx, domain, &release)?;
    activate_route(ctx, domain, &wanted, previous_route.as_deref())?;
    progress.route_changed = Some(previous_route.clone());
    probe_through_ingress(ctx, domain)?;

    // 6. Committed: the previous container and old releases go.
    docker_quiet(ctx, &argv(&["rm", "-f", &previous_name]));
    prune_releases(scope, &release_id);
    Ok(DeployResult {
        domain: domain.to_string(),
        release_id: RequestId::parse(&release_id)
            .map_err(|_| Error::Project("the release id is not usable"))?,
        container,
        network,
        image: req.image.as_str().to_owned(),
        port: APP_PORT,
        health: "healthy".into(),
        deployed_at_unix_secs: now_secs(),
    })
}

/// Keeps the newest releases (by modification time) and the one in use.
fn prune_releases(scope: &Scope, current: &str) {
    let Ok(dir) = scope.root.open_managed_dir(&rel("releases")) else {
        return;
    };
    let Ok(children) = dir.child_entries() else {
        return;
    };
    let mut entries: Vec<(SystemTime, SiteRelativePath, String)> = children
        .into_iter()
        .filter_map(|child| {
            let name = child.name.to_str()?.to_owned();
            let path = SiteRelativePath::parse(&name).ok()?;
            Some((dir.modified(&path).ok()?, path, name))
        })
        .collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path, name) in entries.into_iter().skip(KEEP_RELEASES) {
        if name != current {
            let _ = dir.remove_dir_all(&path);
        }
    }
}

/// Puts the host back as it was before the deploy. `false` when a step of the
/// undo itself failed.
fn rollback(ctx: &Context<'_>, req: &DeployRequest, scope: &Scope, progress: &Progress) -> bool {
    let domain = &req.domain;
    let container = node_ingress::container_name(domain);
    let previous_name = format!("{container}-previous");
    let mut clean = true;
    docker_quiet(
        ctx,
        &argv(&["rm", "-f", &format!("wcp-node-install-{}", req.request_id)]),
    );
    if let Some(previous_route) = &progress.route_changed {
        let wanted = node_ingress::render(domain);
        let restored = match previous_route {
            Some(text) => activate_route(ctx, domain, text, Some(&wanted)).is_ok(),
            None => remove_route(ctx, domain, &wanted).is_ok(),
        };
        clean &= restored;
    }
    if progress.new_container {
        clean &= docker_quiet(ctx, &argv(&["rm", "-f", &container]));
    }
    if let Some(was_running) = progress.previous {
        clean &= docker_quiet(ctx, &argv(&["rename", &previous_name, &container]));
        if was_running {
            clean &= docker_quiet(ctx, &argv(&["start", &container]));
        }
    }
    if progress.release {
        clean &= scope
            .root
            .remove_dir_all(&rel(format!("releases/{}", req.request_id)))
            .is_ok();
    }
    clean
}

pub fn deploy(
    ctx: &Context<'_>,
    req: &DeployRequest,
    cancel: &CancellationToken,
) -> Result<DeployResult, Error> {
    let scope = open_scope(ctx, &req.domain)?;
    let value = transact(
        &scope,
        DEPLOY,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let mut progress = Progress::default();
            match deploy_steps(ctx, req, &scope, &mut progress, cancel) {
                Ok(result) => Ok(serde_json::to_value(&result).unwrap()),
                Err(error) => {
                    if rollback(ctx, req, &scope, &progress) {
                        Err(error)
                    } else {
                        Err(Error::RollbackIncomplete(Box::new(error)))
                    }
                }
            }
        },
    );
    typed(value)
}

fn typed<T: serde::de::DeserializeOwned>(
    value: Result<serde_json::Value, Error>,
) -> Result<T, Error> {
    match value {
        Ok(value) => {
            serde_json::from_value(value).map_err(|error| Error::Io(io::Error::other(error)))
        }
        Err(Error::PostCommit { result }) => Err(Error::PostCommit { result }),
        Err(error) => Err(error),
    }
}

// ───────────────────────────── status / restart / remove ─────────────────────────────

/// The release ids on disk, newest first (by modification time).
fn kept_releases(ctx: &Context<'_>, domain: &Domain) -> Option<Vec<String>> {
    let dir = ctx
        .engine_state
        .open_managed_dir(&rel(format!("node-app/{domain}/releases")))
        .ok()?;
    let mut entries: Vec<(SystemTime, String)> = dir
        .child_entries()
        .ok()?
        .into_iter()
        .filter_map(|child| {
            let name = child.name.to_str()?.to_owned();
            RequestId::parse(&name).ok()?;
            Some((dir.modified(&rel(name.as_str())).ok()?, name))
        })
        .collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    Some(entries.into_iter().map(|(_, name)| name).collect())
}

pub fn status(ctx: &Context<'_>, domain: &Domain) -> Result<AppStatus, Error> {
    let container = node_ingress::container_name(domain);
    let facts = inspect(ctx, &container)?;
    let route_managed = read_route(ctx, &route_path(domain)).ok().map(|route| {
        route
            .as_deref()
            .is_some_and(|text| node_ingress::is_managed(domain, text))
    });
    let releases = kept_releases(ctx, domain);
    Ok(match facts {
        None => AppStatus {
            domain: domain.to_string(),
            state: "absent".into(),
            health: None,
            restart_count: None,
            started_at: None,
            image: None,
            release_id: None,
            route_managed,
            releases,
        },
        Some(facts) => AppStatus {
            domain: domain.to_string(),
            state: facts.status,
            health: Some(facts.health),
            restart_count: Some(facts.restart_count),
            started_at: Some(facts.started_at),
            image: Some(facts.image),
            release_id: (!facts.release.is_empty()).then_some(facts.release),
            route_managed,
            releases,
        },
    })
}

pub fn restart(
    ctx: &Context<'_>,
    req: &DomainRequest,
    cancel: &CancellationToken,
) -> Result<RestartResult, Error> {
    let scope = open_scope(ctx, &req.domain)?;
    let value = transact(
        &scope,
        RESTART,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let container = node_ingress::container_name(&req.domain);
            if inspect(ctx, &container)?.is_none() {
                return Err(Error::Project("the application is not deployed"));
            }
            docker_ok(
                ctx,
                "docker restart",
                &argv(&["restart", "--time", STOP_GRACE, &container]),
                Duration::from_secs(90),
                cancel,
            )?;
            wait_healthy(ctx, &container, cancel)?;
            Ok(serde_json::to_value(RestartResult {
                domain: req.domain.to_string(),
                health: "healthy".into(),
                restarted_at_unix_secs: now_secs(),
            })
            .unwrap())
        },
    );
    typed(value)
}

pub fn remove(
    ctx: &Context<'_>,
    req: &DomainRequest,
    cancel: &CancellationToken,
) -> Result<RemoveResult, Error> {
    let scope = open_scope(ctx, &req.domain)?;
    let value = transact(
        &scope,
        REMOVE,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let domain = &req.domain;
            let container = node_ingress::container_name(domain);
            let network = node_ingress::network_name(domain);
            // The route first, so no request reaches a container being removed.
            let mut route_removed = false;
            if let Some(route) = read_route(ctx, &route_path(domain))? {
                if node_ingress::is_managed(domain, &route) {
                    remove_route(ctx, domain, &route)?;
                    route_removed = true;
                }
            }
            for name in [container.clone(), format!("{container}-previous")] {
                let output = docker(ctx, &argv(&["rm", "-f", &name]), DOCKER_TIMEOUT, cancel)?;
                if !exited_ok(&output) && !output.stderr.text().contains("No such") {
                    return Err(Error::Docker {
                        step: "docker rm",
                        diagnostics: SubprocessDiagnostics::from_output(
                            ctx.docker_program,
                            &output,
                        ),
                    });
                }
            }
            docker_quiet(
                ctx,
                &argv(&[
                    "network",
                    "disconnect",
                    "--force",
                    &network,
                    INGRESS_CONTAINER,
                ]),
            );
            docker_quiet(ctx, &argv(&["network", "rm", &network]));
            if let Ok(static_root) = ManagedRoot::open(ctx.static_root) {
                for suffix in ["", ".new", ".old"] {
                    let path = rel(format!("{}{suffix}", node_ingress::assets_dir_name(domain)));
                    if static_root.symlink_metadata(&path).is_ok() {
                        static_root.remove_dir_all(&path).map_err(Error::Io)?;
                    }
                }
            }
            scope
                .root
                .remove_dir_all(&rel("releases"))
                .map_err(Error::Io)?;
            scope
                .root
                .create_dir_all(&rel("releases"))
                .map_err(Error::Io)?;
            if req.delete_data {
                scope.root.remove_dir_all(&rel("data")).map_err(Error::Io)?;
                scope.root.create_dir_all(&rel("data")).map_err(Error::Io)?;
            }
            Ok(serde_json::to_value(RemoveResult {
                domain: domain.to_string(),
                route_removed,
                data_deleted: req.delete_data,
                removed_at_unix_secs: now_secs(),
            })
            .unwrap())
        },
    );
    typed(value)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const ID3: &str = "123e4567-e89b-12d3-a456-426614174002";
    const BUILD: &str = "123e4567-e89b-12d3-a456-4266141740aa";
    const DOMAIN: &str = "app.example.test";
    const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const ROOT: &str = "/var/www/app.example.test";

    struct Host {
        dir: tempfile::TempDir,
        state: PathBuf,
        ingress: TrustedRoot,
        static_root: TrustedRoot,
        compose: compose::Access,
        docker: String,
    }

    fn managed(path: &Path) -> ManagedRoot {
        ManagedRoot::open(&TrustedRoot::parse(path).unwrap()).unwrap()
    }

    /// A host with a fake `docker` that keeps container state in files
    /// (`c-<name>` holds `status|health|restarts|started|image|release`), logs
    /// every call and fails the steps named by `fail-*` marker files; and a
    /// fake `docker compose exec` that answers the ingress probe.
    fn host() -> Host {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let ingress = dir.path().join("ingress");
        let control = dir.path().join("control");
        for path in [
            &state,
            &ingress,
            &control,
            &dir.path().join("bin"),
            &dir.path().join("static"),
        ] {
            fs::create_dir(path).unwrap();
        }
        // An artifact of a server build.
        let hash = crate::transaction::resource_lock::canonical_hash(Path::new(ROOT));
        let artifact = state.join(format!("node-build/{hash}/artifacts/{BUILD}"));
        fs::create_dir_all(artifact.join("dist/server")).unwrap();
        fs::write(artifact.join("package.json"), "{}").unwrap();
        fs::write(artifact.join("package-lock.json"), "{}").unwrap();
        fs::write(artifact.join("dist/server/entry.mjs"), "// entry").unwrap();
        fs::create_dir_all(artifact.join("dist/client/_astro")).unwrap();
        fs::write(
            artifact.join("dist/client/_astro/app.abc123.js"),
            "// asset",
        )
        .unwrap();
        // The ingress container is up.
        fs::write(
            control.join("c-wcp-ingress-1"),
            "running|none|0|2026-01-01T00:00:00Z|ingress|\n",
        )
        .unwrap();
        let docker = control.join("docker");
        fs::write(
            &docker,
            format!(
                r#"#!/bin/sh
C='{control}'
printf '%s\n' "$*" >> "$C/calls.log"
for last; do :; done
name=
prev=
for arg in "$@"; do
  [ "$prev" = "--name" ] && name="$arg"
  prev="$arg"
done
case "$1" in
  container)
    if [ -f "$C/c-$last" ]; then cat "$C/c-$last"; exit 0; fi
    echo "Error: No such container: $last" >&2; exit 1 ;;
  run)
    case "$*" in
      *"npm ci"*|*"corepack pnpm install"*|*"yarn install"*) [ -f "$C/fail-install" ] && exit 1; exit 0 ;;
      *"--detach"*)
        [ -f "$C/fail-run" ] && exit 1
        health=healthy; [ -f "$C/unhealthy" ] && health=unhealthy
        rel=
        for arg in "$@"; do case "$arg" in wcp.node-release=*) rel="${{arg#wcp.node-release=}}" ;; esac; done
        echo "running|$health|0|2026-01-02T00:00:00Z|image@sha256:00|$rel" > "$C/c-$name"
        echo "container-id"; exit 0 ;;
    esac ;;
  rename) mv "$C/c-$2" "$C/c-$3" ;;
  stop) sed 's/^running/exited/' "$C/c-$last" > "$C/tmp" && mv "$C/tmp" "$C/c-$last" ;;
  start) sed 's/^exited/running/' "$C/c-$last" > "$C/tmp" && mv "$C/tmp" "$C/c-$last" ;;
  restart) [ -f "$C/c-$last" ] || exit 1 ;;
  rm) rm -f "$C/c-$last" ;;
  network)
    case "$2" in
      inspect) [ -f "$C/net-$last" ] || exit 1 ;;
      create) touch "$C/net-$last" ;;
      rm) rm -f "$C/net-$last" ;;
    esac ;;
esac
exit 0
"#,
                control = control.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        compose::write_fake_docker(
            &dir.path().join("bin"),
            &format!(
                r#"control='{control}'
printf '%s\n' "$*" >> "$control/compose.calls"
case "$*" in
  *curl*) if [ -f "$control/probe-fail" ]; then printf 502; else printf 200; fi ;;
esac
exit 0"#,
                control = control.display()
            ),
        );
        let compose = compose::Access::default()
            .stack_dir(dir.path())
            .docker_path(dir.path().join("bin"));
        Host {
            state,
            ingress: TrustedRoot::parse(&ingress).unwrap(),
            static_root: TrustedRoot::parse(dir.path().join("static")).unwrap(),
            compose,
            docker: docker.to_string_lossy().into_owned(),
            dir,
        }
    }

    impl Host {
        fn control(&self, name: &str) -> PathBuf {
            self.dir.path().join("control").join(name)
        }
        fn mark(&self, name: &str) {
            fs::write(self.control(name), "").unwrap();
        }
        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.control("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }
        fn route(&self) -> Option<String> {
            fs::read_to_string(self.dir.path().join(format!("ingress/{DOMAIN}.caddyfile"))).ok()
        }
        fn container(&self, name: &str) -> Option<String> {
            fs::read_to_string(self.control(&format!("c-{name}"))).ok()
        }
        fn run<T>(&self, f: impl FnOnce(&Context<'_>) -> T) -> T {
            let state = managed(&self.state);
            let ctx = Context {
                engine_state: &state,
                state_path: &self.state,
                ingress_root: &self.ingress,
                static_root: &self.static_root,
                compose: &self.compose,
                docker_program: &self.docker,
                poll_interval: Duration::from_millis(5),
                health_timeout: Duration::from_millis(100),
            };
            f(&ctx)
        }
    }

    fn plan(extra: &str) -> String {
        format!(
            r#"{{"domain":"{DOMAIN}","projectRoot":"{ROOT}","buildId":"{BUILD}","image":"docker.io/library/node@sha256:{DIGEST}","uid":1000,"gid":1000,"adapter":"astro-node"{extra}}}"#
        )
    }

    fn deploy_with(
        h: &Host,
        extra: &str,
        id: &str,
        key: Option<&str>,
    ) -> Result<DeployResult, Error> {
        let request = DeployRequest::parse(&plan(extra), id, key).unwrap();
        h.run(|ctx| deploy(ctx, &request, &CancellationToken::default()))
    }

    fn name() -> String {
        node_ingress::container_name(&Domain::parse(DOMAIN).unwrap())
    }

    #[test]
    fn requests_are_validated_in_full() {
        let ok = |extra: &str| DeployRequest::parse(&plan(extra), ID, None);
        assert!(ok("").is_ok());
        assert!(
            ok(r#","memoryMb":1024,"env":{"PUBLIC_SITE":"x"},"secretEnv":{"API_KEY":"s3cret"}"#)
                .is_ok()
        );
        for (extra, error) in [
            (r#","command":"sh""#, RequestError::InvalidJson),
            (r#","memoryMb":64"#, RequestError::InvalidLimit),
            (r#","memoryMb":99999"#, RequestError::InvalidLimit),
            (r#","env":{"lower":"x"}"#, RequestError::InvalidEnv),
            (r#","env":{"1A":"x"}"#, RequestError::InvalidEnv),
            (r#","env":{"A B":"x"}"#, RequestError::InvalidEnv),
            (r#","env":{"PORT":"1"}"#, RequestError::InvalidEnv),
            (
                r#","env":{"NODE_OPTIONS":"--inspect"}"#,
                RequestError::InvalidEnv,
            ),
            (r#","env":{"A":"line\nbreak"}"#, RequestError::InvalidEnv),
            (
                r#","env":{"A":"1"},"secretEnv":{"A":"2"}"#,
                RequestError::InvalidEnv,
            ),
        ] {
            assert_eq!(ok(extra).unwrap_err(), error, "{extra}");
        }
        let with = |from: &str, to: &str| plan("").replace(from, to);
        let d = format!("docker.io/library/node@sha256:{DIGEST}");
        for (body, error) in [
            (
                with("app.example.test", "Bad_Domain"),
                RequestError::InvalidDomain,
            ),
            (with(ROOT, "var/www"), RequestError::InvalidRoot),
            (with(ROOT, "/var/www/../etc"), RequestError::InvalidRoot),
            (with(BUILD, "nope"), RequestError::InvalidBuildId),
            (with(&d, "node:24"), RequestError::InvalidImage),
            (
                with(
                    &d,
                    "evil.example.com/n@sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
                RequestError::InvalidImage,
            ),
            (
                with("\"uid\":1000", "\"uid\":0"),
                RequestError::InvalidIdentity,
            ),
            (
                with("astro-node", "npm-start"),
                RequestError::InvalidAdapter,
            ),
        ] {
            assert_eq!(
                DeployRequest::parse(&body, ID, None).unwrap_err(),
                error,
                "{body}"
            );
        }
        assert_eq!(
            DeployRequest::parse(&plan(""), "x", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
        // A secret never shows in the debug text of a request.
        let request =
            DeployRequest::parse(&plan(r#","secretEnv":{"API_KEY":"s3cret"}"#), ID, None).unwrap();
        assert!(!format!("{request:?}").contains("s3cret"));
    }

    #[test]
    fn deploys_in_a_sandbox_behind_its_own_route_and_replays() {
        let h = host();
        let result = deploy_with(&h, "", ID, Some("k1")).unwrap();
        assert_eq!(result.health, "healthy");
        assert_eq!(result.container, name());
        let domain = Domain::parse(DOMAIN).unwrap();
        assert_eq!(
            h.route().as_deref(),
            Some(node_ingress::render(&domain).as_str())
        );

        let calls = h.calls();
        let at = |needle: &str| {
            calls
                .iter()
                .position(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("no call with {needle}: {calls:?}"))
        };
        // The order: ingress check, install, network, connect, run.
        assert!(at("container inspect") < at("npm ci"));
        assert!(at("npm ci") < at("network create"));
        assert!(at("network create") < at("network connect"));
        assert!(at("network connect") < at("--detach"));
        let run = &calls[at("--detach")];
        for flag in [
            "--user 1000:1000",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--read-only",
            "--pids-limit 512",
            "--memory 512m",
            "--restart unless-stopped",
            "target=/app,readonly",
            "target=/data",
            "NODE_ENV=production",
            "--health-cmd",
            &format!("--network {}", node_ingress::network_name(&domain)),
            "node ./dist/server/entry.mjs",
        ] {
            assert!(run.contains(flag), "{flag} missing in {run}");
        }
        for forbidden in [
            "--publish",
            " -p ",
            "docker.sock",
            "--privileged",
            "--network host",
            "--pid host",
        ] {
            assert!(!run.contains(forbidden), "{forbidden} in {run}");
        }
        // The release holds the artifact; the data directory exists.
        let release = h.state.join(format!("node-app/{DOMAIN}/releases/{ID}"));
        assert!(release.join("dist/server/entry.mjs").exists());
        assert!(h.state.join(format!("node-app/{DOMAIN}/data")).is_dir());
        // The install ran in the sandbox on the release, production only.
        let install = &calls[at("npm ci")];
        assert!(install.contains("--cap-drop ALL") && install.contains("--read-only"));
        assert!(install.contains("npm ci --omit=dev --no-audit --no-fund"));

        let before = h.calls().len();
        let replay = deploy_with(&h, "", ID2, Some("k1")).unwrap();
        assert_eq!(replay.release_id, result.release_id);
        assert_eq!(h.calls().len(), before, "a replay must not touch docker");
    }

    fn rollback_plan(release: &str, extra: &str) -> String {
        format!(
            r#"{{"domain":"{DOMAIN}","projectRoot":"{ROOT}","releaseId":"{release}","image":"docker.io/library/node@sha256:{DIGEST}","uid":1000,"gid":1000,"adapter":"astro-node"{extra}}}"#
        )
    }

    fn rollback_to(h: &Host, release: &str, id: &str) -> Result<DeployResult, Error> {
        let request = DeployRequest::parse(&rollback_plan(release, ""), id, None).unwrap();
        h.run(|ctx| deploy(ctx, &request, &CancellationToken::default()))
    }

    #[test]
    fn a_release_is_named_by_exactly_one_of_build_and_release() {
        let both = plan(&format!(r#","releaseId":"{ID}""#));
        let neither = plan("").replace(&format!(r#""buildId":"{BUILD}","#), "");
        for (json, ok) in [
            (plan(""), true),
            (rollback_plan(ID, ""), true),
            (both, false),
            (neither, false),
            (rollback_plan("nope", ""), false),
        ] {
            assert_eq!(DeployRequest::parse(&json, ID2, None).is_ok(), ok, "{json}");
        }
    }

    #[test]
    fn a_manual_rollback_starts_a_kept_release_without_build_or_install() {
        let h = host();
        deploy_with(&h, "", ID, None).unwrap();
        deploy_with(&h, "", ID2, None).unwrap();
        let before = h.calls().len();
        let result = rollback_to(&h, ID, ID3).unwrap();
        assert_eq!(result.release_id.to_string(), ID);
        // The live container runs the older release again.
        assert!(
            h.container(&name())
                .unwrap()
                .trim_end()
                .ends_with(&format!("|{ID}"))
        );
        assert!(h.container(&format!("{}-previous", name())).is_none());
        // No install ran, and the new request id made no release directory.
        let calls = h.calls()[before..].join("\n");
        assert!(
            !calls.contains("npm ci") && calls.contains("--detach"),
            "{calls}"
        );
        let releases = h.state.join(format!("node-app/{DOMAIN}/releases"));
        assert!(releases.join(ID).is_dir() && releases.join(ID2).is_dir());
        assert!(!releases.join(ID3).exists());
        // The status lists what a rollback can start, and the live release.
        let status = h
            .run(|ctx| status(ctx, &Domain::parse(DOMAIN).unwrap()))
            .unwrap();
        assert_eq!(status.release_id.as_deref(), Some(ID));
        let kept = status.releases.unwrap();
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&ID.to_owned()) && kept.contains(&ID2.to_owned()));
    }

    #[test]
    fn a_rollback_that_fails_keeps_the_live_release_and_the_kept_one() {
        let h = host();
        deploy_with(&h, "", ID, None).unwrap();
        deploy_with(&h, "", ID2, None).unwrap();
        h.mark("unhealthy");
        assert!(rollback_to(&h, ID, ID3).is_err());
        let _ = fs::remove_file(h.control("unhealthy"));
        assert!(
            h.container(&name())
                .unwrap()
                .trim_end()
                .ends_with(&format!("|{ID2}"))
        );
        let releases = h.state.join(format!("node-app/{DOMAIN}/releases"));
        assert!(
            releases.join(ID).is_dir(),
            "the kept release survives a failed rollback"
        );
        // A release that is gone, or was never there, is refused up front.
        let (code, message) = rollback_to(&h, ID3, "123e4567-e89b-12d3-a456-4266141740bb")
            .unwrap_err()
            .protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert!(
            message.starts_with("the release does not exist"),
            "{message}"
        );
    }

    #[test]
    fn a_pnpm_or_yarn_artifact_installs_with_its_own_tool() {
        for (lock, installs) in [
            (
                "pnpm-lock.yaml",
                "corepack pnpm install --frozen-lockfile --prod",
            ),
            (
                "yarn.lock",
                "yarn install --frozen-lockfile --non-interactive --production",
            ),
        ] {
            let h = host();
            let hash = crate::transaction::resource_lock::canonical_hash(Path::new(ROOT));
            let artifact = h.state.join(format!("node-build/{hash}/artifacts/{BUILD}"));
            fs::remove_file(artifact.join("package-lock.json")).unwrap();
            fs::write(artifact.join(lock), "# yarn lockfile v1\n").unwrap();
            deploy_with(&h, "", ID, None).unwrap();
            let calls = h.calls().join("\n");
            assert!(calls.contains(installs), "{lock}: {calls}");
            assert!(!calls.contains("npm ci"), "{lock}");
        }
    }

    #[test]
    fn secrets_reach_the_container_only_through_a_removed_root_only_file() {
        let h = host();
        let secret = "s3cr3t-value-123";
        let result = deploy_with(
            &h,
            &format!(r#","env":{{"PUBLIC_SITE":"visible"}},"secretEnv":{{"API_KEY":"{secret}"}}"#),
            ID,
            None,
        )
        .unwrap();
        let calls = h.calls().join("\n");
        assert!(!calls.contains(secret), "the secret is in an argv");
        assert!(calls.contains("--env PUBLIC_SITE=visible"));
        assert!(calls.contains("--env-file"), "{calls}");
        assert!(
            !calls.contains("API_KEY"),
            "even the name stays out of argv"
        );
        assert!(!serde_json::to_string(&result).unwrap().contains(secret));
        // The env file is gone and nothing under the state tree holds the secret.
        let secrets = h.state.join(format!("node-app/{DOMAIN}/secrets"));
        assert_eq!(fs::read_dir(&secrets).unwrap().count(), 0);
        fn holds(dir: &Path, needle: &str) -> bool {
            fs::read_dir(dir).unwrap().flatten().any(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    holds(&path, needle)
                } else {
                    fs::read_to_string(&path).is_ok_and(|text| text.contains(needle))
                }
            })
        }
        assert!(
            !holds(&h.state, secret),
            "the secret was recorded in the state tree"
        );
    }

    #[test]
    fn a_redeploy_replaces_the_container_and_keeps_the_route() {
        let h = host();
        deploy_with(&h, "", ID, None).unwrap();
        let first_route = h.route();
        let second = deploy_with(&h, "", ID2, None).unwrap();
        assert!(h.container(&name()).unwrap().contains(&format!("|{ID2}")));
        assert!(
            h.container(&format!("{}-previous", name())).is_none(),
            "the old one is removed"
        );
        assert_eq!(h.route(), first_route);
        assert_eq!(second.release_id.to_string(), ID2);
        let calls = h.calls().join("\n");
        assert!(calls.contains(&format!("rename {} {}-previous", name(), name())));
        // Only the newest two releases are kept.
        deploy_with(&h, "", ID3, None).unwrap();
        let releases = fs::read_dir(h.state.join(format!("node-app/{DOMAIN}/releases")))
            .unwrap()
            .count();
        assert_eq!(releases, KEEP_RELEASES);
    }

    #[test]
    fn an_unhealthy_application_is_rolled_back_to_the_previous_one() {
        let h = host();
        deploy_with(&h, "", ID, None).unwrap();
        let route = h.route();
        h.mark("unhealthy");
        let error = deploy_with(&h, "", ID2, None).unwrap_err();
        assert_eq!(error.protocol().1, "the application health check failed");
        // The previous container is back under its name and running; the new
        // one, its release and any route change are gone.
        assert!(h.container(&name()).unwrap().starts_with("running"));
        assert!(
            h.container(&name()).unwrap().ends_with(&format!("|{ID}\n")),
            "{:?}",
            h.container(&name())
        );
        assert!(h.container(&format!("{}-previous", name())).is_none());
        assert!(
            !h.state
                .join(format!("node-app/{DOMAIN}/releases/{ID2}"))
                .exists()
        );
        assert_eq!(h.route(), route);
    }

    #[test]
    fn a_first_deploy_that_fails_leaves_nothing_behind() {
        for fail in ["fail-install", "fail-run", "unhealthy", "probe-fail"] {
            let h = host();
            h.mark(fail);
            let error = deploy_with(&h, "", ID, None).unwrap_err();
            assert!(
                !matches!(error, Error::RollbackIncomplete(_)),
                "{fail}: {error:?}"
            );
            assert!(h.container(&name()).is_none(), "{fail}: container");
            assert!(h.route().is_none(), "{fail}: route");
            assert!(
                !h.state
                    .join(format!("node-app/{DOMAIN}/releases/{ID}"))
                    .exists(),
                "{fail}: release"
            );
            // And the failure is what a retry sees.
        }
    }

    #[test]
    fn a_route_that_is_not_managed_node_hosting_is_never_replaced() {
        let h = host();
        fs::write(
            h.dir.path().join(format!("ingress/{DOMAIN}.caddyfile")),
            "app.example.test {\n    reverse_proxy runtime-fp1-php83:80\n}\n",
        )
        .unwrap();
        let error = deploy_with(&h, "", ID, None).unwrap_err();
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
        assert!(h.route().unwrap().contains("runtime-fp1-php83"));
        assert!(
            h.calls()
                .iter()
                .all(|c| !c.contains("npm ci") && !c.contains("--detach"))
        );
    }

    #[test]
    fn only_a_server_artifact_is_deployed() {
        let h = host();
        let hash = crate::transaction::resource_lock::canonical_hash(Path::new(ROOT));
        let artifact = h.state.join(format!("node-build/{hash}/artifacts/{BUILD}"));
        fs::remove_file(artifact.join("dist/server/entry.mjs")).unwrap();
        let (code, message) = deploy_with(&h, "", ID, None).unwrap_err().protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert!(message.contains("server build"), "{message}");
        let other = DeployRequest::parse(&plan("").replace(BUILD, ID3), ID2, None).unwrap();
        let (_, missing) = h
            .run(|ctx| deploy(ctx, &other, &CancellationToken::default()))
            .unwrap_err()
            .protocol();
        assert_eq!(missing, "the build artifact does not exist");
    }

    #[test]
    fn a_stopped_ingress_refuses_the_deploy_before_anything_changes() {
        let h = host();
        fs::remove_file(h.control("c-wcp-ingress-1")).unwrap();
        let (code, _) = deploy_with(&h, "", ID, None).unwrap_err().protocol();
        assert_eq!(code, ErrorCode::Conflict);
        assert!(h.calls().iter().all(|c| !c.contains("npm ci")));
    }

    #[test]
    fn status_reports_what_docker_says_and_unknown_stays_unknown() {
        let h = host();
        let domain = Domain::parse(DOMAIN).unwrap();
        let absent = h.run(|ctx| status(ctx, &domain)).unwrap();
        assert_eq!(absent.state, "absent");
        assert_eq!(
            (absent.health, absent.restart_count, absent.route_managed),
            (None, None, Some(false))
        );
        deploy_with(&h, "", ID, None).unwrap();
        let running = h.run(|ctx| status(ctx, &domain)).unwrap();
        assert_eq!(running.state, "running");
        assert_eq!(running.health.as_deref(), Some("healthy"));
        assert_eq!(running.restart_count, Some(0));
        assert_eq!(running.release_id.as_deref(), Some(ID));
        assert_eq!(running.route_managed, Some(true));
        // A docker that fails in another way than "no such container" is an
        // error, never "absent".
        fs::write(&h.docker, "#!/bin/sh\necho boom >&2\nexit 1\n").unwrap();
        assert!(h.run(|ctx| status(ctx, &domain)).is_err());
    }

    #[test]
    fn deploy_publishes_the_hashed_client_files_and_remove_deletes_them() {
        use std::os::unix::fs::PermissionsExt;
        let h = host();
        let assets = h.dir.path().join(format!("static/{DOMAIN}-assets"));
        deploy_with(&h, "", ID, None).unwrap();
        let file = assets.join("_astro/app.abc123.js");
        assert_eq!(fs::read_to_string(&file).unwrap(), "// asset");
        // Readable by the ingress, writable only by the engine.
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(assets.join("_astro"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        // Nothing but the live copy is left behind.
        let names: Vec<_> = fs::read_dir(&assets)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["_astro"]);

        // A redeploy publishes the new files and keeps the previous hashed
        // one (a page cached before the deploy still points at it).
        let artifact = h.state.join(format!(
            "node-build/{}/artifacts/{BUILD}/dist/client/_astro",
            crate::transaction::resource_lock::canonical_hash(Path::new(ROOT))
        ));
        fs::remove_file(artifact.join("app.abc123.js")).unwrap();
        fs::write(artifact.join("app.def456.js"), "// next").unwrap();
        deploy_with(&h, "", ID2, None).unwrap();
        assert!(file.exists(), "the previous hashed file was dropped");
        assert!(assets.join("_astro/app.def456.js").exists());

        let request = DomainRequest::parse(
            &format!(r#"{{"domain":"{DOMAIN}"}}"#),
            "123e4567-e89b-12d3-a456-4266141740f0",
            None,
        )
        .unwrap();
        h.run(|ctx| remove(ctx, &request, &CancellationToken::default()))
            .unwrap();
        assert!(!assets.exists());
    }

    #[test]
    fn plain_client_files_are_published_pages_and_sources_are_not() {
        let h = host();
        let client = h.state.join(format!(
            "node-build/{}/artifacts/{BUILD}/dist/client",
            crate::transaction::resource_lock::canonical_hash(Path::new(ROOT))
        ));
        fs::write(client.join("robots.txt"), "User-agent: *").unwrap();
        fs::write(client.join("favicon.svg"), "<svg/>").unwrap();
        fs::create_dir_all(client.join("img")).unwrap();
        fs::write(client.join("img/logo.png"), "png").unwrap();
        for hidden in [
            "index.html",
            "about.htm",
            "x.php",
            "x.mjs",
            "app.js.map",
            ".secret",
            ".env",
        ] {
            fs::write(client.join(hidden), "no").unwrap();
        }
        deploy_with(&h, "", ID, None).unwrap();
        let assets = h.dir.path().join(format!("static/{DOMAIN}-assets"));
        for published in [
            "robots.txt",
            "favicon.svg",
            "img/logo.png",
            "_astro/app.abc123.js",
        ] {
            assert!(assets.join(published).is_file(), "{published}");
        }
        for hidden in [
            "index.html",
            "about.htm",
            "x.php",
            "x.mjs",
            "app.js.map",
            ".secret",
            ".env",
        ] {
            assert!(!assets.join(hidden).exists(), "{hidden}");
        }
    }

    #[test]
    fn a_hashed_file_older_than_the_keep_time_is_dropped_on_the_next_deploy() {
        let h = host();
        deploy_with(&h, "", ID, None).unwrap();
        let astro = h.dir.path().join(format!("static/{DOMAIN}-assets/_astro"));
        let old = astro.join("app.old000.js");
        let young = astro.join("app.young0.js");
        fs::write(&old, "old").unwrap();
        fs::write(&young, "young").unwrap();
        let long_ago = std::time::SystemTime::now() - KEEP_HASHED - Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        deploy_with(&h, "", ID2, None).unwrap();
        assert!(!old.exists(), "a file past the keep time stays published");
        assert!(young.exists(), "a recent file was dropped");
        assert!(astro.join("app.abc123.js").exists());
    }

    #[test]
    fn a_build_without_client_assets_publishes_nothing() {
        let h = host();
        let artifact = h.state.join(format!(
            "node-build/{}/artifacts/{BUILD}/dist/client",
            crate::transaction::resource_lock::canonical_hash(Path::new(ROOT))
        ));
        fs::remove_dir_all(artifact).unwrap();
        deploy_with(&h, "", ID, None).unwrap();
        assert!(
            !h.dir
                .path()
                .join(format!("static/{DOMAIN}-assets"))
                .exists()
        );
    }

    #[test]
    fn a_host_still_on_the_proxy_only_route_is_adopted_by_the_next_deploy() {
        let h = host();
        let domain = Domain::parse(DOMAIN).unwrap();
        let legacy = node_ingress::render_legacy(&domain);
        fs::write(
            h.dir.path().join(format!("ingress/{DOMAIN}.caddyfile")),
            &legacy,
        )
        .unwrap();
        assert_eq!(
            h.run(|ctx| status(ctx, &domain)).unwrap().route_managed,
            Some(true)
        );
        deploy_with(&h, "", ID, None).unwrap();
        assert_eq!(
            h.route().as_deref(),
            Some(node_ingress::render(&domain).as_str())
        );
    }

    #[test]
    fn restart_waits_for_health_and_remove_cleans_up() {
        let h = host();
        let domain = Domain::parse(DOMAIN).unwrap();
        let request = |id: &str, extra: &str| {
            DomainRequest::parse(&format!(r#"{{"domain":"{DOMAIN}"{extra}}}"#), id, None).unwrap()
        };
        let missing = h
            .run(|ctx| restart(ctx, &request(ID, ""), &CancellationToken::default()))
            .unwrap_err();
        assert_eq!(missing.protocol().1, "the application is not deployed");
        deploy_with(&h, "", ID2, None).unwrap();
        let restarted = h
            .run(|ctx| restart(ctx, &request(ID3, ""), &CancellationToken::default()))
            .unwrap();
        assert_eq!(restarted.health, "healthy");

        fs::write(
            h.state.join(format!("node-app/{DOMAIN}/data/keep.txt")),
            "mine",
        )
        .unwrap();
        let removed = h
            .run(|ctx| {
                remove(
                    ctx,
                    &request("123e4567-e89b-12d3-a456-4266141740f0", ""),
                    &CancellationToken::default(),
                )
            })
            .unwrap();
        assert!(removed.route_removed && !removed.data_deleted);
        assert!(h.container(&name()).is_none() && h.route().is_none());
        assert!(
            h.state
                .join(format!("node-app/{DOMAIN}/data/keep.txt"))
                .exists()
        );
        assert_eq!(h.run(|ctx| status(ctx, &domain)).unwrap().state, "absent");
        let wiped = h
            .run(|ctx| {
                remove(
                    ctx,
                    &request(
                        "123e4567-e89b-12d3-a456-4266141740f1",
                        r#","deleteData":true"#,
                    ),
                    &CancellationToken::default(),
                )
            })
            .unwrap();
        assert!(wiped.data_deleted);
        assert!(
            !h.state
                .join(format!("node-app/{DOMAIN}/data/keep.txt"))
                .exists()
        );
    }

    #[test]
    fn remove_leaves_a_route_it_does_not_manage() {
        let h = host();
        fs::write(
            h.dir.path().join(format!("ingress/{DOMAIN}.caddyfile")),
            "app.example.test {\n    respond \"other\"\n}\n",
        )
        .unwrap();
        let request =
            DomainRequest::parse(&format!(r#"{{"domain":"{DOMAIN}"}}"#), ID, None).unwrap();
        let removed = h
            .run(|ctx| remove(ctx, &request, &CancellationToken::default()))
            .unwrap();
        assert!(!removed.route_removed);
        assert!(h.route().unwrap().contains("respond"));
    }
}
