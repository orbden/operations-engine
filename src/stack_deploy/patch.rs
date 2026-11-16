//! `runtime.patchUpdate`: moves one container of the managed stack to a newer
//! image of the same release line, by hand and one service at a time. The
//! engine decides everything that makes it a patch itself; the caller only
//! names the image.
//!
//! Refused unless all hold:
//!
//! - the request carries the exact confirmation `RESTART <service>` and the
//!   list of sites the caller says run on the service (recorded, so the audit
//!   shows who was told what; the engine cannot enumerate the sites itself);
//! - the image is a digest-pinned `ghcr.io/orbden/...` reference
//!   of the same repository the service already runs;
//! - `runtime.patchStatus` judges it `patchPending` from the running image's
//!   version and the supplied `resolvedVersion` (same release line, higher
//!   patch or a rebuild); another line, an older image or an unreadable
//!   version is refused, never guessed;
//! - the compose file's image for the service is a `${VAR:-default}` whose
//!   variable `.env` does not override.
//!
//! Sequence (all under the shared stack lock and the request's transaction):
//!
//! 1. finish an interrupted predecessor from its journal (restore the compose
//!    file, bring the service up on the previous image);
//! 2. stage the compose file with only that service's default image replaced,
//!    validate it, apply the image policy to every service and pull;
//! 3. journal, back the live file up as `<file>.rollback-<request id>`, move
//!    the staged file into place;
//! 4. `up -d --no-deps <service>` and wait until it is running and healthy;
//! 5. on any failure restore the file, bring the service up on the previous
//!    image and report the failure (`restored`), or `ConfigRecoveryFailed`
//!    when that does not work either.
//!
//! The result and the journal hold image references and versions only.

use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    runtime_patch_status::{self as status, Candidate, Status},
    security_affected::{Docker as InventoryDocker, Inventory},
    security_feed::ImageRule,
};

pub const OPERATION: &str = "runtime.patchUpdate";
/// The catalog-driven variant: same sequence, but the image comes from an
/// accepted `docker.image.replace` rule and the judgement is by digest.
pub const SECURITY_OPERATION: &str = "security.dockerImageReplace";
/// `ghcr.io/orbden/<name>[:tag]@sha256:<hex>`.
pub fn catalog_image(reference: &str) -> bool {
    image_allowed(reference)
}
const PATCH_JOURNAL: &str = "patch-journal.json";
const MAX_SITES: usize = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    Malformed,
    InvalidService,
    InvalidImage,
    InvalidVersion,
    InvalidSites,
    ConfirmationMissing,
    InvalidRequestId,
    InvalidIdempotencyKey,
    CatalogNotFresh,
    UnknownFix,
    NotCatalogImage,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Malformed => "request-file is not a valid patch update request",
            Self::InvalidService => "service is not a compose service name",
            Self::InvalidImage => "image is not a digest-pinned managed image reference",
            Self::InvalidVersion => "resolvedVersion is not a dotted version",
            Self::InvalidSites => "sites must be a list of host names",
            Self::ConfirmationMissing => {
                "confirm must be exactly `RESTART <service>`: restarting a shared service \
                 interrupts every site on it"
            }
            Self::InvalidRequestId => "request-id is not a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
            Self::CatalogNotFresh => {
                "the accepted security catalog is not current; refresh it first"
            }
            Self::UnknownFix => "fixId is not a docker.image.replace fix of the accepted catalog",
            Self::NotCatalogImage => {
                "the fix's replacement is not a digest-pinned catalog image (ghcr.io/orbden/...)"
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Wire {
    service: String,
    image: String,
    resolved_version: String,
    sites: Vec<String>,
    confirm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SecurityWire {
    fix_id: String,
    service: String,
    sites: Vec<String>,
    confirm: String,
}

#[derive(Debug)]
pub struct Request {
    pub service: String,
    pub image: String,
    pub resolved_version: String,
    pub sites: Vec<String>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
    /// Set for `security.dockerImageReplace`: the accepted rule it applies.
    pub rule: Option<ImageRule>,
}

fn service_name_ok(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= 64
        && service.as_bytes()[0].is_ascii_alphanumeric()
        && service
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn site_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

impl Request {
    pub fn parse(
        json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RequestError> {
        let request_id =
            RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
        let idempotency_key = idempotency_key
            .map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?;
        let wire: Wire = serde_json::from_str(json).map_err(|_| RequestError::Malformed)?;
        if !service_name_ok(&wire.service) {
            return Err(RequestError::InvalidService);
        }
        if !image_allowed(&wire.image) {
            return Err(RequestError::InvalidImage);
        }
        if wire.resolved_version.len() > 32
            || status::parse_version(&wire.resolved_version).is_none()
        {
            return Err(RequestError::InvalidVersion);
        }
        if wire.sites.len() > MAX_SITES || !wire.sites.iter().all(|s| site_name_ok(s)) {
            return Err(RequestError::InvalidSites);
        }
        if wire.confirm != format!("RESTART {}", wire.service) {
            return Err(RequestError::ConfirmationMissing);
        }
        Ok(Self {
            service: wire.service,
            image: wire.image,
            resolved_version: wire.resolved_version,
            sites: wire.sites,
            request_id,
            idempotency_key,
            rule: None,
        })
    }

    /// `security.dockerImageReplace`: `{fixId, service, sites, confirm}`. The
    /// image is never taken from the caller; it is the accepted rule's.
    pub fn parse_security(
        json: &str,
        request_id: &str,
        idempotency_key: Option<&str>,
        rules: &[ImageRule],
        catalog_fresh: bool,
    ) -> Result<Self, RequestError> {
        let request_id =
            RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?;
        let idempotency_key = idempotency_key
            .map(IdempotencyKey::parse)
            .transpose()
            .map_err(|_| RequestError::InvalidIdempotencyKey)?;
        let wire: SecurityWire = serde_json::from_str(json).map_err(|_| RequestError::Malformed)?;
        if !crate::security_affected::runtime_service(&wire.service) {
            return Err(RequestError::InvalidService);
        }
        if wire.sites.len() > MAX_SITES || !wire.sites.iter().all(|s| site_name_ok(s)) {
            return Err(RequestError::InvalidSites);
        }
        if wire.confirm != format!("RESTART {}", wire.service) {
            return Err(RequestError::ConfirmationMissing);
        }
        if !catalog_fresh {
            return Err(RequestError::CatalogNotFresh);
        }
        let rule = rules
            .iter()
            .find(|r| {
                r.fix_id == wire.fix_id
                    && r.component == crate::security_affected::COMPONENT_PHP_RUNTIME
            })
            .ok_or(RequestError::UnknownFix)?;
        if !catalog_image(&rule.to_image) {
            return Err(RequestError::NotCatalogImage);
        }
        Ok(Self {
            service: wire.service,
            image: rule.to_image.clone(),
            resolved_version: String::new(),
            sites: wire.sites,
            request_id,
            idempotency_key,
            rule: Some(rule.clone()),
        })
    }

    pub fn operation(&self) -> &'static str {
        if self.rule.is_some() {
            SECURITY_OPERATION
        } else {
            OPERATION
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchResult {
    pub service: String,
    /// `false` when the service already ran the requested image.
    pub changed: bool,
    pub previous_image: String,
    pub image: String,
    pub previous_version: Option<String>,
    pub version: String,
    /// The sites the caller confirmed would be interrupted.
    pub sites: Vec<String>,
    /// The catalog fix that was applied (`security.dockerImageReplace`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_id: Option<String>,
    pub completed_at_unix_secs: u64,
}

#[derive(Debug)]
pub enum PatchError {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Replayed {
        code: ErrorCode,
        message: String,
    },
    Cancelled,
    InterruptedRecoveryFailed(RestoreFailure),
    /// The service is not a container of the stack, or its image is unreadable.
    ServiceUnknown,
    /// `runtime.patchStatus` did not judge it a patch.
    NotAPatch(&'static str),
    /// The running image is not one the catalog fix applies to.
    Refused(&'static str),
    /// The compose file or `.env` does not let the engine change this image.
    NotRewritable(&'static str),
    ValidateFailed(DockerFailure),
    ImageRejected(String),
    PullFailed(DockerFailure),
    NotUpRestored(NotUp),
    RecoveryFailed {
        cause: NotUp,
        restore: RestoreFailure,
    },
    PostCommit {
        result: Box<PatchResult>,
    },
}

impl PatchError {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) => (
                ErrorCode::Conflict,
                "another stack operation is in progress".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Cancelled => (ErrorCode::Cancelled, "patch update was cancelled".into()),
            Self::InterruptedRecoveryFailed(restore) => (
                ErrorCode::ConfigRecoveryFailed,
                format!(
                    "an interrupted earlier patch update could not be rolled back ({}); \
                     nothing new was changed",
                    restore.describe()
                ),
            ),
            Self::ServiceUnknown => (
                ErrorCode::InvalidInput,
                "the service is not a readable container of the managed stack".into(),
            ),
            Self::NotAPatch(reason) => (
                ErrorCode::InvalidInput,
                format!(
                    "the image is not a patch of the running one ({reason}); nothing was changed"
                ),
            ),
            Self::Refused(reason) => (
                ErrorCode::InvalidInput,
                format!("the fix does not apply to this service ({reason}); nothing was changed"),
            ),
            Self::NotRewritable(reason) => (
                ErrorCode::ConfigValidationFailed,
                format!(
                    "the stack configuration does not allow this update ({reason}); nothing was changed"
                ),
            ),
            Self::ValidateFailed(_) => (
                ErrorCode::ConfigValidationFailed,
                "docker compose rejected the changed configuration; nothing was changed".into(),
            ),
            Self::ImageRejected(image) => (
                ErrorCode::ConfigValidationFailed,
                format!(
                    "image {image} is not a digest-pinned {IMAGE_PREFIX} reference; nothing was changed"
                ),
            ),
            Self::PullFailed(failure) => (
                docker_failure_code(failure),
                "pulling the image failed; nothing was changed".into(),
            ),
            Self::NotUpRestored(cause) => (
                ErrorCode::ConfigReloadFailed,
                format!(
                    "the service did not come up on the new image ({}); the previous image \
                     was restored and the advisory is still unresolved",
                    cause.describe()
                ),
            ),
            Self::RecoveryFailed { cause, restore } => (
                ErrorCode::ConfigRecoveryFailed,
                format!(
                    "the service did not come up on the new image ({}) and {}; check the server",
                    cause.describe(),
                    restore.describe()
                ),
            ),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal patch update error".into())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchJournal {
    request_id: RequestId,
    service: String,
}

/// Why the compose text cannot be rewritten for one service.
#[derive(Debug, Eq, PartialEq)]
pub enum RewriteError {
    NoService,
    NoImageLine,
    NotAVariable,
    EnvOverride,
    OtherRepository,
}

impl RewriteError {
    fn reason(&self) -> &'static str {
        match self {
            Self::NoService => "the service is not in the compose file",
            Self::NoImageLine => "the service has no image line",
            Self::NotAVariable => "the service image is not a ${VAR:-default} reference",
            Self::EnvOverride => ".env overrides the service image",
            Self::OtherRepository => {
                "the image is another repository than the one the service uses"
            }
        }
    }
}

/// The image name without registry organisation, tag or digest, so a catalog
/// image of another organisation is still the same image.
fn repository(reference: &str) -> &str {
    let name = reference.split(['@', ':']).next().unwrap_or(reference);
    name.strip_prefix(IMAGE_PREFIX).unwrap_or(name)
}

/// Replaces the default of the service's `image: ${VAR:-default}` line and
/// returns the new text with the old default. Everything else is untouched.
pub fn rewrite_image(
    compose: &str,
    env: &str,
    service: &str,
    new_image: &str,
) -> Result<(String, String), RewriteError> {
    let header = format!("  {service}:");
    let mut in_block = false;
    let mut found = false;
    let mut out = String::with_capacity(compose.len());
    let mut old = String::new();
    for line in compose.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\n', '\r']);
        if bare.trim_end() == header {
            in_block = true;
            found = true;
        } else if in_block
            && !bare.is_empty()
            && !bare.starts_with("   ")
            && !bare.trim_start().starts_with('#')
        {
            in_block = false;
        }
        if in_block && old.is_empty() {
            if let Some(rest) = bare.strip_prefix("    image:") {
                let value = rest.trim();
                let inner = value
                    .strip_prefix("${")
                    .and_then(|v| v.strip_suffix('}'))
                    .ok_or(RewriteError::NotAVariable)?;
                let (var, default) = inner.split_once(":-").ok_or(RewriteError::NotAVariable)?;
                if env_value(env, var).is_some_and(|v| !v.is_empty()) {
                    return Err(RewriteError::EnvOverride);
                }
                if repository(default) != repository(new_image) {
                    return Err(RewriteError::OtherRepository);
                }
                default.clone_into(&mut old);
                out.push_str(&format!("    image: ${{{var}:-{new_image}}}"));
                out.push_str(&line[bare.len()..]);
                continue;
            }
        }
        out.push_str(line);
    }
    if !found {
        return Err(RewriteError::NoService);
    }
    if old.is_empty() {
        return Err(RewriteError::NoImageLine);
    }
    Ok((out, old))
}

fn patch_state_path(id: RequestId) -> SiteRelativePath {
    rel(format!("transactions/{id}.json"))
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<PatchResult, PatchError> {
    let scope = open_scope(ctx.engine_state).map_err(PatchError::Io)?;
    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        req.operation(),
    )
    .map_err(PatchError::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id, req.operation()),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = patch_state_path(req.request_id);
    let audit_path = rel("audit/events.jsonl");
    let result = match run(ctx, &scope, req, cancel) {
        Ok(result) => result,
        Err(error) => {
            let (code, message) = error.protocol();
            let _ = state.mark_failed(code, message);
            let _ = state::save(&scope, &state_path, &state);
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(req.request_id, false, Some(code)),
            );
            return Err(error);
        }
    };
    state
        .mark_committed(serde_json::to_value(&result).expect("result serializes"))
        .expect("an in-progress transaction can commit");
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(PatchError::PostCommit {
            result: Box::new(result),
        });
    }
    let _ = audit::append(
        &scope,
        &audit_path,
        &AuditRecord::result(req.request_id, true, None),
    );
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId, operation: &str) -> Result<PatchResult, PatchError> {
    let loaded = state::load(scope, &patch_state_path(id))
        .map_err(|error| PatchError::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != operation {
        return Err(PatchError::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(PatchError::ReplayInProgress),
        TransactionStatus::Committed => loaded
            .outcome
            .and_then(|outcome| outcome.result)
            .ok_or_else(|| PatchError::Io(io::Error::other("committed transaction has no result")))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|e| PatchError::Io(io::Error::other(e)))
            }),
        TransactionStatus::Failed => {
            let (code, message) = loaded
                .outcome
                .map(|o| (o.error_code, o.error_message))
                .unwrap_or((None, None));
            Err(PatchError::Replayed {
                code: code.unwrap_or(ErrorCode::Internal),
                message: message.unwrap_or_default(),
            })
        }
    }
}

fn bring_up(docker: &Docker<'_>, ctx: &Context<'_>, service: &str) -> Result<(), NotUp> {
    docker
        .compose(
            Files::Live,
            &["up", "-d", "--no-deps", service],
            ctx.timing.up,
        )
        .map_err(NotUp::Up)?;
    if service == INGRESS_SERVICE && !ensure_ports(docker, &ctx.timing).map_err(NotUp::Inspect)? {
        return Err(NotUp::PortsNotPublished);
    }
    let services = [service.to_owned()];
    let not_ready = wait_healthy(docker, &services, &ctx.timing).map_err(NotUp::Inspect)?;
    if not_ready.is_empty() {
        Ok(())
    } else {
        Err(NotUp::Unhealthy(not_ready))
    }
}

/// Puts the backed-up compose file back and brings the service up on it.
fn restore_service(
    root: &ManagedRoot,
    docker: &Docker<'_>,
    ctx: &Context<'_>,
    id: RequestId,
    service: &str,
) -> Result<(), RestoreFailure> {
    let backup = backup_path(COMPOSE_FILE, id);
    if root.exists(&backup) {
        root.rename(&backup, &rel(COMPOSE_FILE))
            .map_err(RestoreFailure::Files)?;
    }
    bring_up(docker, ctx, service).map_err(|cause| match cause {
        NotUp::PortsNotPublished => RestoreFailure::PortsNotPublished,
        NotUp::Up(failure) | NotUp::Inspect(failure) => RestoreFailure::Up(failure),
        NotUp::Unhealthy(_) | NotUp::Activation(_) | NotUp::WrongImage(_) => {
            RestoreFailure::PortsNotPublished
        }
    })
}

fn run(
    ctx: &Context<'_>,
    scope: &ManagedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<PatchResult, PatchError> {
    let root = ManagedRoot::open(ctx.stack_root).map_err(PatchError::Io)?;
    let docker = Docker {
        program: ctx.docker,
        cwd: ctx.stack_root.as_path(),
        cancel,
    };

    // 1. An interrupted predecessor is rolled back before anything new.
    if let Some(bytes) = read_optional(scope, &rel(PATCH_JOURNAL)).map_err(PatchError::Io)? {
        let journal: PatchJournal = serde_json::from_slice(&bytes)
            .map_err(|e| PatchError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        remove_if_present(&root, &rel(staged_name(COMPOSE_FILE))).map_err(PatchError::Io)?;
        restore_service(&root, &docker, ctx, journal.request_id, &journal.service)
            .map_err(PatchError::InterruptedRecoveryFailed)?;
        let path = patch_state_path(journal.request_id);
        if let Ok(mut interrupted) = state::load(scope, &path) {
            if interrupted.status == TransactionStatus::InProgress
                && interrupted
                    .mark_failed(
                        ErrorCode::Cancelled,
                        "interrupted; rolled back by a later patch update".to_owned(),
                    )
                    .is_ok()
            {
                let _ = state::save(scope, &path, &interrupted);
            }
        }
        scope
            .remove_file(&rel(PATCH_JOURNAL))
            .map_err(PatchError::Io)?;
    }

    // 2. The engine's own judgement that this is a patch.
    let digest = req
        .image
        .split_once("@sha256:")
        .map(|(_, hex)| format!("sha256:{hex}"))
        .ok_or(PatchError::ServiceUnknown)?;
    let containers = docker.inspect().map_err(|_| PatchError::ServiceUnknown)?;
    let running: Vec<&Container> = containers
        .iter()
        .filter(|c| c.service == req.service)
        .collect();
    let [current] = running.as_slice() else {
        return Err(PatchError::ServiceUnknown);
    };
    let previous_image = current.declared_image.clone();
    let inventory = InventoryDocker {
        program: ctx.docker,
    };
    let completed = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    };
    let fix_id = req.rule.as_ref().map(|rule| rule.fix_id.clone());
    let running_version: Option<String>;
    let up_to_date;
    if let Some(rule) = &req.rule {
        // The real local image, not the declared tag, decides.
        let runtimes = inventory
            .runtimes()
            .map_err(|_| PatchError::ServiceUnknown)?;
        let runtime = runtimes
            .iter()
            .find(|r| r.service == req.service)
            .ok_or(PatchError::ServiceUnknown)?;
        let facts = inventory
            .image(&runtime.image_id)
            .map_err(|_| PatchError::ServiceUnknown)?;
        if !rule.platforms.contains(&facts.platform) {
            return Err(PatchError::Refused(
                "the platform is not covered by the fix",
            ));
        }
        up_to_date = facts.digests.contains(&rule.to_digest);
        if !up_to_date && !facts.digests.iter().any(|d| rule.from_digests.contains(d)) {
            return Err(PatchError::Refused(
                "the running image is not one the fix lists",
            ));
        }
        running_version = None;
    } else {
        let judged = status::evaluate(
            &inventory,
            &status::Request {
                candidates: vec![Candidate {
                    service: req.service.clone(),
                    digest: Some(digest),
                    resolved_version: Some(req.resolved_version.clone()),
                }],
            },
        );
        let row = judged
            .services
            .iter()
            .find(|row| row.service == req.service)
            .ok_or(PatchError::ServiceUnknown)?;
        running_version = row.running_version.clone();
        up_to_date = match row.status {
            Status::UpToDate => true,
            Status::PatchPending => false,
            _ => return Err(PatchError::NotAPatch(row.reason)),
        };
    }
    if up_to_date {
        return Ok(PatchResult {
            service: req.service.clone(),
            changed: false,
            previous_image: previous_image.clone(),
            image: req.image.clone(),
            previous_version: running_version,
            version: req.resolved_version.clone(),
            sites: req.sites.clone(),
            fix_id,
            completed_at_unix_secs: completed(),
        });
    }

    // 3. Stage, validate, apply the image policy, pull.
    let compose = read_optional(&root, &rel(COMPOSE_FILE))
        .map_err(PatchError::Io)?
        .ok_or(PatchError::NotRewritable("there is no compose file"))?;
    let compose = String::from_utf8(compose)
        .map_err(|_| PatchError::NotRewritable("the compose file is not text"))?;
    let env_bytes = read_optional(&root, &rel(ENV_FILE))
        .map_err(PatchError::Io)?
        .ok_or(PatchError::NotRewritable("there is no .env file"))?;
    let env = String::from_utf8_lossy(&env_bytes).into_owned();
    let (rewritten, _old_default) = rewrite_image(&compose, &env, &req.service, &req.image)
        .map_err(|e| PatchError::NotRewritable(e.reason()))?;
    let discard = || {
        for name in [COMPOSE_FILE, ENV_FILE] {
            let _ = remove_if_present(&root, &rel(staged_name(name)));
        }
    };
    let staged = write(
        &root,
        ctx.owner,
        COMPOSE_FILE,
        &rel(staged_name(COMPOSE_FILE)),
        rewritten.as_bytes(),
    )
    .and_then(|()| {
        write(
            &root,
            ctx.owner,
            ENV_FILE,
            &rel(staged_name(ENV_FILE)),
            &env_bytes,
        )
    });
    if let Err(error) = staged {
        discard();
        return Err(PatchError::Io(error));
    }
    let checked = (|| {
        docker
            .compose(Files::Staged, &["config", "--quiet"], ctx.timing.validate)
            .map_err(PatchError::ValidateFailed)?;
        let images = docker
            .lines(
                Files::Staged,
                &["--profile", "*", "config", "--images"],
                ctx.timing.validate,
            )
            .map_err(PatchError::ValidateFailed)?;
        if let Some(bad) = images
            .iter()
            .find(|image| !(image_allowed(image) || req.rule.is_some() && **image == req.image))
        {
            return Err(PatchError::ImageRejected(bad.clone()));
        }
        if !images.iter().any(|image| image == &req.image) {
            return Err(PatchError::NotRewritable("the staged file lost the image"));
        }
        docker
            .compose(
                Files::Staged,
                &["pull", "--quiet", &req.service],
                ctx.timing.pull,
            )
            .map_err(PatchError::PullFailed)?;
        Ok(())
    })();
    if let Err(error) = checked {
        discard();
        return Err(error);
    }
    if cancel.is_cancelled() {
        discard();
        return Err(PatchError::Cancelled);
    }

    // 4. Journal, back up, activate, bring the one service up.
    let journal = PatchJournal {
        request_id: req.request_id,
        service: req.service.clone(),
    };
    if let Err(error) = scope.write_atomic(
        &rel(PATCH_JOURNAL),
        &serde_json::to_vec(&journal).expect("journal serializes"),
    ) {
        discard();
        return Err(PatchError::Io(error));
    }
    let activated = write(
        &root,
        ctx.owner,
        COMPOSE_FILE,
        &backup_path(COMPOSE_FILE, req.request_id),
        compose.as_bytes(),
    )
    .and_then(|()| root.rename(&rel(staged_name(COMPOSE_FILE)), &rel(COMPOSE_FILE)))
    .map_err(NotUp::Activation)
    .and_then(|()| bring_up(&docker, ctx, &req.service))
    .and_then(|()| verify_image(ctx, req));
    let _ = remove_if_present(&root, &rel(staged_name(ENV_FILE)));
    if let Err(cause) = activated {
        discard();
        return match restore_service(&root, &docker, ctx, req.request_id, &req.service) {
            Ok(()) => {
                let _ = scope.remove_file(&rel(PATCH_JOURNAL));
                Err(PatchError::NotUpRestored(cause))
            }
            Err(restore) => Err(PatchError::RecoveryFailed { cause, restore }),
        };
    }
    let _ = remove_if_present(&root, &backup_path(COMPOSE_FILE, req.request_id));
    let _ = scope.remove_file(&rel(PATCH_JOURNAL));

    Ok(PatchResult {
        service: req.service.clone(),
        changed: true,
        previous_image,
        image: req.image.clone(),
        previous_version: running_version,
        version: req.resolved_version.clone(),
        sites: req.sites.clone(),
        fix_id,
        completed_at_unix_secs: completed(),
    })
}

/// After the service is up: the running image must really be the fix's
/// replacement (security fixes only). Anything else is rolled back.
fn verify_image(ctx: &Context<'_>, req: &Request) -> Result<(), NotUp> {
    let Some(rule) = &req.rule else {
        return Ok(());
    };
    let inventory = InventoryDocker {
        program: ctx.docker,
    };
    let runtimes = inventory
        .runtimes()
        .map_err(|_| NotUp::Inspect(DockerFailure::Unreadable))?;
    let runs_replacement = runtimes
        .iter()
        .find(|r| r.service == req.service)
        .and_then(|r| inventory.image(&r.image_id).ok())
        .is_some_and(|facts| facts.digests.contains(&rule.to_digest));
    if runs_replacement {
        Ok(())
    } else {
        Err(NotUp::WrongImage(req.service.clone()))
    }
}

#[cfg(test)]
mod tests;
