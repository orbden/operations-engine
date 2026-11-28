//! `node.build`: one reproducible Node build in a throw-away container.
//!
//! The project is copied into an engine-private staging directory (without
//! `node_modules`, `.git`, `.env*` and `.npmrc`, so the build never sees the
//! site's secrets) and built there by two fixed container runs of a
//! digest-pinned Node image: the lockfile install and the build script,
//! each with the project's own package manager (`npm ci`, `pnpm install
//! --frozen-lockfile` or `yarn install --frozen-lockfile`, found by the
//! lockfile; see `node_pm`). The container runs as the site's non-root identity with
//! all capabilities dropped, a read-only root filesystem, memory and PID
//! limits and no Docker socket. Project scripts are untrusted application
//! code: the staging copy is the only writable project path they can reach.
//!
//! The site's own files are never written. On success the output directory is
//! copied into an engine-owned, numbered artifact directory and the staging
//! copy is removed; on failure only a bounded log stays. Publishing the
//! artifact (`site.publishStatic`) or running it is a separate operation.
//! The caller supplies only validated values (script name, output directory,
//! limits); there is no generic command.

use crate::{
    docker_resource::ImageReference,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    node_pm::PackageManager,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessTermination,
        SubprocessDiagnostics,
    },
    site::{SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const OPERATION: &str = "node.build";

/// Where the container sees the staged project.
const WORKDIR: &str = "/work";
const DEFAULT_SCRIPT: &str = "build";
const DEFAULT_OUTPUT_DIR: &str = "dist";
const DEFAULT_MEMORY_MB: u32 = 2048;
const MEMORY_MB: std::ops::RangeInclusive<u32> = 512..=8192;
const DEFAULT_TIMEOUT_SECS: u64 = 900;
const TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 60..=3600;
const PIDS_LIMIT: &str = "1024";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Captured per container run; the log keeps what was captured.
const MAX_RUN_OUTPUT: usize = 128 * 1024;
const MAX_PACKAGE_JSON: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const ARTIFACT_LIMITS: (usize, u64) = (ARTIFACT_MAX_ENTRIES, ARTIFACT_MAX_BYTES);
const SOURCE_MAX_ENTRIES: usize = 50_000;
const SOURCE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const ARTIFACT_MAX_ENTRIES: usize = 100_000;
const ARTIFACT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Artifacts and logs kept per site; older ones are removed after a build.
const KEEP_ARTIFACTS: usize = 3;
const KEEP_LOGS: usize = 10;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    project_root: String,
    image: String,
    uid: u32,
    gid: u32,
    #[serde(default)]
    script: Option<String>,
    #[serde(default)]
    output_dir: Option<String>,
    #[serde(default)]
    memory_mb: Option<u32>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    ignore_scripts: bool,
    /// Keep the output directory under its own path together with
    /// `package.json` and the lockfile, so a server application can be
    /// started from the artifact (`node.deployApp` installs its production
    /// dependencies from the lockfile). Default: the artifact is the contents
    /// of the output directory, for static publishing.
    #[serde(default)]
    server: bool,
}

#[derive(Debug)]
pub struct Request {
    project_root: PathBuf,
    image: ImageReference,
    uid: u32,
    gid: u32,
    script: String,
    output_dir: Vec<String>,
    memory_mb: u32,
    timeout: Duration,
    ignore_scripts: bool,
    server: bool,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidJson,
    InvalidRoot,
    InvalidImage,
    InvalidIdentity,
    InvalidScript,
    InvalidOutputDir,
    InvalidLimit,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

/// An npm script name: the first character is never `-`, so it cannot be
/// read as an npm option.
fn valid_script(value: &str) -> bool {
    let first = |b: u8| b.is_ascii_alphanumeric();
    let rest = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-');
    crate::util::charset_ok(value, 64, first, rest)
}

/// One component of a relative output directory.
fn valid_component(value: &str) -> bool {
    let first = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let rest = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-');
    crate::util::charset_ok(value, 64, first, rest)
}

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError::InvalidJson)?;
        let project_root = PathBuf::from(&plan.project_root);
        if plan.project_root.len() > 4096
            || plan.project_root.chars().any(char::is_control)
            || TrustedRoot::parse(&project_root).is_err()
        {
            return Err(RequestError::InvalidRoot);
        }
        // A digest pin is the point: the build image never moves under a tag.
        let image = ImageReference::parse(&plan.image).map_err(|_| RequestError::InvalidImage)?;
        if !image.as_str().contains("@sha256:") {
            return Err(RequestError::InvalidImage);
        }
        if plan.uid == 0 || plan.gid == 0 || plan.uid == u32::MAX || plan.gid == u32::MAX {
            return Err(RequestError::InvalidIdentity);
        }
        let script = plan.script.unwrap_or_else(|| DEFAULT_SCRIPT.to_owned());
        if !valid_script(&script) {
            return Err(RequestError::InvalidScript);
        }
        let output = plan
            .output_dir
            .unwrap_or_else(|| DEFAULT_OUTPUT_DIR.to_owned());
        let output_dir: Vec<String> = output.split('/').map(str::to_owned).collect();
        if output.len() > 128
            || output_dir.len() > 4
            || !output_dir.iter().all(|part| valid_component(part))
        {
            return Err(RequestError::InvalidOutputDir);
        }
        let memory_mb = plan.memory_mb.unwrap_or(DEFAULT_MEMORY_MB);
        let timeout_secs = plan.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !MEMORY_MB.contains(&memory_mb) || !TIMEOUT_SECS.contains(&timeout_secs) {
            return Err(RequestError::InvalidLimit);
        }
        Ok(Self {
            project_root,
            image,
            uid: plan.uid,
            gid: plan.gid,
            script,
            output_dir,
            memory_mb,
            timeout: Duration::from_secs(timeout_secs),
            ignore_scripts: plan.ignore_scripts,
            server: plan.server,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.project_root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildResult {
    pub build_id: RequestId,
    /// Absolute path of the artifact directory (the copied output directory).
    pub artifact_path: String,
    pub output_dir: String,
    pub files: usize,
    pub bytes: u64,
    /// Absolute path of the root-only log of both container runs.
    pub log_path: String,
    pub duration_secs: u64,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    /// Host path of the engine state root (the bind-mount source).
    pub state_path: &'a Path,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    ResourceBusy,
    Cancelled,
    Run(process::ProcessRunError),
    /// The project cannot be built as asked (missing lockfile, script,
    /// output; a symlink or an oversized tree).
    Project(&'static str),
    /// A container run failed; `phase` names it.
    Build {
        phase: &'static str,
        diagnostics: SubprocessDiagnostics,
    },
    PostCommit {
        result: BuildResult,
    },
    Replayed {
        code: ErrorCode,
        message: String,
    },
}

impl Error {
    pub fn protocol(&self) -> (ErrorCode, String) {
        match self {
            Self::Preflight(preflight::Error::Lock(_)) | Self::ResourceBusy => (
                ErrorCode::Conflict,
                "another operation is already in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Cancelled => (ErrorCode::Cancelled, "cancelled".into()),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run the build container".into(),
            ),
            Self::Project(message) => (ErrorCode::InvalidInput, (*message).into()),
            Self::Build { phase, diagnostics } => {
                let code = if diagnostics.timed_out {
                    ErrorCode::Timeout
                } else if diagnostics.cancelled {
                    ErrorCode::Cancelled
                } else {
                    ErrorCode::SubprocessFailed
                };
                let suffix = if diagnostics.timed_out {
                    " (timed out)".to_owned()
                } else if diagnostics.cancelled {
                    " (cancelled)".to_owned()
                } else if let Some(exit) = diagnostics.exit_code {
                    format!(" (exit code {exit})")
                } else {
                    String::new()
                };
                (code, format!("{phase} failed{suffix}"))
            }
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_) | Self::Preflight(_) | Self::PostCommit { .. } => {
                (ErrorCode::Internal, "internal build error".into())
            }
        }
    }
}

fn rel(path: impl Into<String>) -> SiteRelativePath {
    SiteRelativePath::parse(path.into()).unwrap()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// What a tree copy may take and how it marks the result.
pub(crate) struct CopyRules {
    /// Names (file or directory, any depth) that are left out.
    pub(crate) skip: fn(&str) -> bool,
    pub(crate) owner: Option<(u32, u32)>,
    pub(crate) max_entries: usize,
    pub(crate) max_bytes: u64,
}

#[derive(Default)]
pub(crate) struct Copied {
    pub(crate) entries: usize,
    pub(crate) files: usize,
    pub(crate) bytes: u64,
}

/// Names the staging copy never takes: dependencies are reinstalled from the
/// lockfile, and credentials stay on the site.
fn skip_for_build(name: &str) -> bool {
    matches!(name, "node_modules" | ".git" | ".npmrc")
        || name == ".env"
        || name.starts_with(".env.")
}

pub(crate) fn skip_nothing(_: &str) -> bool {
    false
}

/// A project or artifact tree, copied without following links. Symlinks,
/// special files and hard-linked files are refused (the copy has to mean what
/// the source means); sizes and entry counts are bounded.
pub(crate) fn copy_tree(
    source: &ManagedRoot,
    destination: &ManagedRoot,
    rules: &CopyRules,
    depth: usize,
    copied: &mut Copied,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Project("the tree is nested too deeply"));
    }
    let children = source
        .child_entries_bounded(rules.max_entries.saturating_sub(copied.entries))
        .map_err(|_| Error::Project("the tree has too many entries"))?;
    for child in children {
        let name = child
            .name
            .to_str()
            .ok_or(Error::Project("a file name is not valid UTF-8"))?;
        if name.is_empty() || name.contains('\\') || name.chars().any(char::is_control) {
            return Err(Error::Project("a file name is not allowed"));
        }
        if (rules.skip)(name) {
            continue;
        }
        copied.entries += 1;
        if copied.entries > rules.max_entries {
            return Err(Error::Project("the tree has too many entries"));
        }
        let path = SiteRelativePath::parse(name)
            .map_err(|_| Error::Project("a file name is not allowed"))?;
        if child.is_dir {
            let from = source.open_child_dir_nofollow(&path).map_err(Error::Io)?;
            destination.create_dir(&path).map_err(Error::Io)?;
            destination.set_mode(&path, 0o755).map_err(Error::Io)?;
            if let Some((uid, gid)) = rules.owner {
                destination.chown(&path, uid, gid).map_err(Error::Io)?;
            }
            let to = destination
                .open_child_dir_nofollow(&path)
                .map_err(Error::Io)?;
            copy_tree(&from, &to, rules, depth + 1, copied)?;
        } else {
            let file = match source.open_regular_read(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    return Err(Error::Project(
                        "the tree contains a symlink or a special file",
                    ));
                }
                Err(error) => return Err(Error::Io(error)),
            };
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata().map_err(Error::Io)?;
            if metadata.nlink() != 1 {
                return Err(Error::Project("the tree contains a hard-linked file"));
            }
            if metadata.len() > MAX_FILE_BYTES {
                return Err(Error::Project("a file is too large"));
            }
            let remaining = rules.max_bytes.saturating_sub(copied.bytes);
            let mut output = destination
                .create_new_file_with_mode(&path, 0o600)
                .map_err(Error::Io)?;
            let written =
                io::copy(&mut file.take(remaining + 1), &mut output).map_err(Error::Io)?;
            if written > remaining {
                return Err(Error::Project("the tree is too large"));
            }
            drop(output);
            let mode = if metadata.mode() & 0o111 != 0 {
                0o755
            } else {
                0o644
            };
            destination.set_mode(&path, mode).map_err(Error::Io)?;
            if let Some((uid, gid)) = rules.owner {
                destination.chown(&path, uid, gid).map_err(Error::Io)?;
            }
            copied.bytes += written;
            copied.files += 1;
        }
    }
    Ok(())
}

/// The engine runs as root in production; a build container must then own the
/// staging copy. An unprivileged engine (tests) cannot and does not chown.
pub(crate) fn root_owner(uid: u32, gid: u32) -> Option<(u32, u32)> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    (unsafe { libc::geteuid() } == 0).then_some((uid, gid))
}

fn staging_owner(req: &Request) -> Option<(u32, u32)> {
    root_owner(req.uid, req.gid)
}

pub(crate) fn exited_ok(output: &ProcessOutput) -> bool {
    matches!(
        output.termination,
        ProcessTermination::Exited { success: true, .. }
    )
}

fn container_name(req: &Request, phase: &str) -> String {
    format!("wcp-node-build-{}-{phase}", req.request_id)
}

/// The `docker run` arguments of every sandboxed Node container the engine
/// starts for a build or an install: non-root identity, no capabilities,
/// `no-new-privileges`, read-only root file system with a `/tmp` tmpfs, memory
/// (swap equal) and PID limits, low CPU shares, one bind mount at `/work` and
/// no other host path. The image and the command follow.
pub(crate) fn sandbox_run_args(
    name: &str,
    identity: (u32, u32),
    memory_mb: u32,
    mount_source: &str,
    image: &str,
) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name.to_owned(),
        "--user".into(),
        format!("{}:{}", identity.0, identity.1),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--read-only".into(),
        "--tmpfs".into(),
        "/tmp:rw,exec,nosuid,size=1g".into(),
        "--pids-limit".into(),
        PIDS_LIMIT.into(),
        "--memory".into(),
        format!("{memory_mb}m"),
        "--memory-swap".into(),
        format!("{memory_mb}m"),
        "--cpu-shares".into(),
        "512".into(),
        "--mount".into(),
        format!("type=bind,source={mount_source},target={WORKDIR}"),
        "--workdir".into(),
        WORKDIR.into(),
        "--env".into(),
        "HOME=/tmp".into(),
        "--env".into(),
        "CI=true".into(),
        "--env".into(),
        "npm_config_cache=/tmp/.npm".into(),
        "--env".into(),
        "npm_config_update_notifier=false".into(),
        // pnpm (through corepack) and yarn keep their caches under /tmp too:
        // the root file system is read-only.
        "--env".into(),
        "COREPACK_HOME=/tmp/.corepack".into(),
        "--env".into(),
        "COREPACK_ENABLE_DOWNLOAD_PROMPT=0".into(),
        "--env".into(),
        "npm_config_store_dir=/tmp/.pnpm-store".into(),
        "--env".into(),
        "YARN_CACHE_FOLDER=/tmp/.yarn".into(),
        image.to_owned(),
    ]
}

/// One container run with fixed arguments. The container is removed
/// afterwards (`--rm` on a normal exit, `rm -f` after a timeout or kill).
fn run_container(
    ctx: &Context<'_>,
    req: &Request,
    work: &Path,
    phase: &str,
    argv: &[&str],
    log: &mut String,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let name = container_name(req, phase);
    let source = work.to_str().filter(|p| !p.contains([',', '=', '\n']));
    let Some(source) = source else {
        return Err(Error::Io(invalid("staging path is not usable")));
    };
    let mut args = sandbox_run_args(
        &name,
        (req.uid, req.gid),
        req.memory_mb,
        source,
        req.image.as_str(),
    );
    args.extend(argv.iter().map(|arg| (*arg).to_owned()));
    let output = process::run(
        &ProcessRequest::new(ctx.docker_program).args(args),
        &ProcessLimits {
            timeout: req.timeout,
            max_stdout_bytes: MAX_RUN_OUTPUT,
            max_stderr_bytes: MAX_RUN_OUTPUT,
        },
        cancel,
    )
    .map_err(Error::Run)?;
    log.push_str(&format!("== {phase} ==\n"));
    log.push_str(&output.stdout.text());
    log.push_str(&output.stderr.text());
    log.push('\n');
    if !exited_ok(&output) {
        // A timed-out or killed `docker run` client leaves its container
        // running; remove it by its fixed name.
        let _ = process::run(
            &ProcessRequest::new(ctx.docker_program).args(["rm", "-f", &name]),
            &ProcessLimits {
                timeout: CLEANUP_TIMEOUT,
                ..ProcessLimits::default()
            },
            &CancellationToken::default(),
        );
    }
    Ok(output)
}

/// `scripts.<name>` of the staged package.json, read bounded.
fn has_script(work: &ManagedRoot, script: &str) -> Result<bool, Error> {
    let file = work
        .open_regular_read(&rel("package.json"))
        .map_err(|_| Error::Project("package.json is required"))?;
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE_JSON + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::Io)?;
    if bytes.len() as u64 > MAX_PACKAGE_JSON {
        return Err(Error::Project("package.json is too large"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Project("package.json is not valid JSON"))?;
    Ok(value
        .get("scripts")
        .and_then(|scripts| scripts.get(script))
        .is_some_and(serde_json::Value::is_string))
}

fn open_output(work: &ManagedRoot, parts: &[String]) -> Result<ManagedRoot, Error> {
    let missing = |_| Error::Project("the build produced no output directory");
    let (first, rest) = parts
        .split_first()
        .ok_or(Error::Project("the build produced no output directory"))?;
    let mut current = work
        .open_child_dir_nofollow(&rel(first.clone()))
        .map_err(missing)?;
    for part in rest {
        current = current
            .open_child_dir_nofollow(&rel(part.clone()))
            .map_err(missing)?;
    }
    Ok(current)
}

/// Creates the nested output path under `root` (an empty artifact) and
/// returns the innermost directory.
fn descend_create(root: &ManagedRoot, parts: &[String]) -> Result<ManagedRoot, Error> {
    let (first, rest) = parts
        .split_first()
        .ok_or(Error::Project("the output directory is invalid"))?;
    let step = |parent: &ManagedRoot, name: &String| -> Result<ManagedRoot, Error> {
        let path = rel(name.clone());
        parent.create_dir(&path).map_err(Error::Io)?;
        parent.set_mode(&path, 0o755).map_err(Error::Io)?;
        parent.open_child_dir_nofollow(&path).map_err(Error::Io)
    };
    let mut current = step(root, first)?;
    for name in rest {
        current = step(&current, name)?;
    }
    Ok(current)
}

struct Built {
    files: usize,
    bytes: u64,
}

fn build(
    ctx: &Context<'_>,
    req: &Request,
    scope: &ManagedRoot,
    scope_dir: &Path,
    log: &mut String,
    cancel: &CancellationToken,
) -> Result<Built, Error> {
    let id = req.request_id;
    let source = ManagedRoot::open(
        &TrustedRoot::parse(&req.project_root)
            .map_err(|_| Error::Project("the project root cannot be opened"))?,
    )
    .map_err(|_| Error::Project("the project root cannot be opened"))?;
    let manager =
        PackageManager::detect(&source).map_err(|error| Error::Project(error.message()))?;

    let work_rel = rel(format!("work/{id}"));
    scope.create_dir_all(&work_rel).map_err(Error::Io)?;
    let work = scope.open_managed_dir(&work_rel).map_err(Error::Io)?;
    let owner = staging_owner(req);
    if let Some((uid, gid)) = owner {
        scope.chown(&work_rel, uid, gid).map_err(Error::Io)?;
    }
    work.set_own_mode(0o755).map_err(Error::Io)?;
    let mut copied = Copied::default();
    copy_tree(
        &source,
        &work,
        &CopyRules {
            skip: skip_for_build,
            owner,
            max_entries: SOURCE_MAX_ENTRIES,
            max_bytes: SOURCE_MAX_BYTES,
        },
        0,
        &mut copied,
    )?;
    if !has_script(&work, &req.script)? {
        return Err(Error::Project(
            "package.json has no script with the requested name",
        ));
    }

    let work_dir = scope_dir.join("work").join(id.to_string());
    for (phase, argv) in [
        (manager.install_phase(), manager.install(req.ignore_scripts)),
        ("the build script", manager.run_script(&req.script)),
    ] {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let output = run_container(
            ctx,
            req,
            &work_dir,
            &phase.replace(' ', "-"),
            &argv.iter().map(String::as_str).collect::<Vec<_>>(),
            log,
            cancel,
        )?;
        if !exited_ok(&output) {
            return Err(Error::Build {
                phase,
                diagnostics: SubprocessDiagnostics::from_output(ctx.docker_program, &output),
            });
        }
    }

    let output = open_output(&work, &req.output_dir)?;
    let artifact_rel = rel(format!("artifacts/{id}"));
    scope.create_dir_all(&artifact_rel).map_err(Error::Io)?;
    scope.set_mode(&artifact_rel, 0o755).map_err(Error::Io)?;
    let artifact = scope.open_managed_dir(&artifact_rel).map_err(Error::Io)?;
    let mut taken = Copied::default();
    let rules = CopyRules {
        skip: skip_nothing,
        owner: None,
        max_entries: ARTIFACT_MAX_ENTRIES,
        max_bytes: ARTIFACT_MAX_BYTES,
    };
    if req.server {
        // `dist/...` stays at `dist/...`, next to the package files the
        // production install needs.
        let target = descend_create(&artifact, &req.output_dir)?;
        copy_tree(&output, &target, &rules, 0, &mut taken)?;
        for name in ["package.json", manager.lockfile()] {
            let path = rel(name);
            let mut input = work.open_regular_read(&path).map_err(Error::Io)?;
            let mut out = artifact
                .create_new_file_with_mode(&path, 0o600)
                .map_err(Error::Io)?;
            let written = io::copy(&mut (&mut input).take(MAX_PACKAGE_JSON * 8), &mut out)
                .map_err(Error::Io)?;
            drop(out);
            artifact.set_mode(&path, 0o644).map_err(Error::Io)?;
            taken.files += 1;
            taken.bytes += written;
        }
    } else {
        copy_tree(&output, &artifact, &rules, 0, &mut taken)?;
    }
    if taken.files == 0 {
        return Err(Error::Project("the build output directory is empty"));
    }
    artifact.sync_all().map_err(Error::Io)?;
    Ok(Built {
        files: taken.files,
        bytes: taken.bytes,
    })
}

/// Removes the oldest entries of `dir` beyond `keep` (by modification time).
fn prune(scope: &ManagedRoot, dir: &str, keep: usize, directories: bool) {
    let Ok(dir_root) = scope.open_managed_dir(&rel(dir)) else {
        return;
    };
    let Ok(children) = dir_root.child_entries() else {
        return;
    };
    let mut entries: Vec<(SystemTime, SiteRelativePath, bool)> = children
        .into_iter()
        .filter_map(|child| {
            let path = SiteRelativePath::parse(child.name.to_str()?).ok()?;
            let modified = dir_root.modified(&path).ok()?;
            Some((modified, path, child.is_dir))
        })
        .collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path, is_dir) in entries.into_iter().skip(keep) {
        let _ = if directories && is_dir {
            dir_root.remove_dir_all(&path)
        } else {
            dir_root.remove_file(&path)
        };
    }
}

pub fn execute(
    ctx: &Context<'_>,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<BuildResult, Error> {
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_rel = rel(format!("node-build/{hash}"));
    ctx.engine_state
        .create_dir_all(&scope_rel)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_rel)
        .map_err(Error::Io)?;
    scope.set_own_mode(0o700).map_err(Error::Io)?;
    for child in [
        "locks",
        "transactions",
        "audit",
        "work",
        "artifacts",
        "logs",
    ] {
        scope.create_dir_all(&rel(child)).map_err(Error::Io)?;
    }
    let scope_dir = ctx.state_path.join("node-build").join(&hash);
    let _resource_lock =
        resource_lock::acquire(ctx.engine_state, &req.project_root, req.request_id)
            .map_err(|_| Error::ResourceBusy)?;

    let admitted = match preflight::run(
        &scope,
        req.request_id,
        req.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(id) => return replay(&scope, id),
        preflight::Outcome::Proceed(value) => value,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let id = req.request_id;
    let state_path = rel(format!("transactions/{id}.json"));
    let audit_path = rel("audit/events.jsonl");
    let log_rel = rel(format!("logs/{id}.log"));

    let started = Instant::now();
    let mut log = String::new();
    let outcome = if cancel.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        build(ctx, req, &scope, &scope_dir, &mut log, cancel)
    };
    // The staging copy is never kept; a failed build keeps only its log.
    let _ = scope.remove_dir_all(&rel(format!("work/{id}")));
    if !log.is_empty() {
        let _ = scope.write_atomic_private(&log_rel, log.as_bytes());
    }
    let built = match outcome {
        Ok(built) => built,
        Err(error) => {
            let _ = scope.remove_dir_all(&rel(format!("artifacts/{id}")));
            return Err(fail(&scope, &state_path, &audit_path, state, error));
        }
    };

    let result = BuildResult {
        build_id: id,
        artifact_path: scope_dir
            .join("artifacts")
            .join(id.to_string())
            .display()
            .to_string(),
        output_dir: req.output_dir.join("/"),
        files: built.files,
        bytes: built.bytes,
        log_path: scope_dir
            .join("logs")
            .join(format!("{id}.log"))
            .display()
            .to_string(),
        duration_secs: started.elapsed().as_secs(),
        completed_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    state
        .mark_committed(serde_json::to_value(&result).unwrap())
        .unwrap();
    if state::save(&scope, &state_path, &state).is_err() {
        drop(lock);
        return Err(Error::PostCommit { result });
    }
    let _ = audit::append(&scope, &audit_path, &AuditRecord::result(id, true, None));
    prune(&scope, "artifacts", KEEP_ARTIFACTS, true);
    prune(&scope, "logs", KEEP_LOGS, false);
    drop(lock);
    Ok(result)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<BuildResult, Error> {
    let loaded = state::load(scope, &rel(format!("transactions/{id}.json")))
        .map_err(|error| Error::Io(io::Error::other(format!("{error:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|error| Error::Io(io::Error::other(error)))
        }
        TransactionStatus::Failed => {
            let outcome = loaded.outcome.unwrap();
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn fail(
    scope: &ManagedRoot,
    state_path: &SiteRelativePath,
    audit_path: &SiteRelativePath,
    mut state: crate::transaction::state::TransactionState,
    error: Error,
) -> Error {
    let (code, message) = error.protocol();
    let _ = state.mark_failed(code, message);
    let _ = state::save(scope, state_path, &state);
    let _ = audit::append(
        scope,
        audit_path,
        &AuditRecord::result(state.request_id, false, Some(code)),
    );
    error
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ID2: &str = "123e4567-e89b-12d3-a456-426614174001";
    const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn managed(directory: &Path) -> ManagedRoot {
        ManagedRoot::open(&TrustedRoot::parse(directory).unwrap()).unwrap()
    }

    fn plan(project: &Path, extra: &str) -> String {
        format!(
            r#"{{"projectRoot":"{}","image":"docker.io/library/node:22-alpine@sha256:{DIGEST}","uid":1000,"gid":1000{extra}}}"#,
            project.display()
        )
    }

    /// A project that builds: lockfile, a `build` script, secrets and
    /// dependencies that must not reach the container.
    fn project(dir: &Path) -> PathBuf {
        let root = dir.join("site");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"scripts":{"build":"astro build","lint":"x"}}"#,
        )
        .unwrap();
        fs::write(root.join("package-lock.json"), "{}").unwrap();
        fs::write(root.join("src/page.js"), "export {}").unwrap();
        fs::write(root.join(".env"), "SECRET=1").unwrap();
        fs::write(root.join(".env.production"), "SECRET=2").unwrap();
        fs::write(root.join(".npmrc"), "//registry/:_authToken=tok").unwrap();
        fs::create_dir_all(root.join("node_modules/dep")).unwrap();
        fs::write(root.join("node_modules/dep/index.js"), "x").unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/HEAD"), "ref").unwrap();
        root
    }

    /// Records every call. When it sees `npm run build` it writes the output
    /// the real build would; the first call lists the staged directory.
    /// `FAIL` makes the matching phase exit 1.
    fn fake_docker(directory: &Path, fail: &str) -> String {
        let path = directory.join("fake-docker");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
printf '%s\n' "$*" >> '{log}'
src=$(printf '%s' "$*" | sed -n 's/.*source=\([^,]*\),.*/\1/p')
case "$*" in
  "rm -f"*) exit 0 ;;
  *" npm ci"*|*" corepack pnpm install"*|*" yarn install"*) [ -n "$src" ] && ls -A "$src" > '{listing}'; case "{fail}" in ci) echo "ci boom"; exit 1;; esac ;;
  *" npm run build"*|*" corepack pnpm run build"*|*" yarn run build"*)
    case "{fail}" in build) echo "build boom"; exit 1;; nooutput) exit 0;; esac
    mkdir -p "$src/dist/assets" && echo hi > "$src/dist/index.html" && echo js > "$src/dist/assets/a.js" ;;
esac
exit 0
"#,
                log = directory.join("calls.log").display(),
                listing = directory.join("staged.ls").display(),
                fail = fail,
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn calls(directory: &Path) -> Vec<String> {
        fs::read_to_string(directory.join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    struct Fixture {
        dir: tempfile::TempDir,
        state: PathBuf,
        project: PathBuf,
        docker: String,
    }

    fn fixture(fail: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        let project = project(dir.path());
        let docker = fake_docker(dir.path(), fail);
        Fixture {
            dir,
            state,
            project,
            docker,
        }
    }

    fn run(f: &Fixture, extra: &str, id: &str, key: Option<&str>) -> Result<BuildResult, Error> {
        let state = managed(&f.state);
        let ctx = Context {
            engine_state: &state,
            state_path: &f.state,
            docker_program: &f.docker,
        };
        let request = Request::parse(&plan(&f.project, extra), id, key).unwrap();
        execute(&ctx, &request, &CancellationToken::default())
    }

    #[test]
    fn requests_are_validated_in_full() {
        let root = "/var/www/site";
        let ok = |extra: &str| Request::parse(&plan(Path::new(root), extra), ID, None);
        assert!(ok("").is_ok());
        assert!(ok(r#","script":"build:prod","outputDir":"dist/client","memoryMb":512,"timeoutSecs":60,"ignoreScripts":true"#).is_ok());
        for (extra, error) in [
            (r#","script":"--help""#, RequestError::InvalidScript),
            (r#","script":"a b""#, RequestError::InvalidScript),
            (r#","script":"x;rm""#, RequestError::InvalidScript),
            (r#","script":"""#, RequestError::InvalidScript),
            (r#","outputDir":"../dist""#, RequestError::InvalidOutputDir),
            (r#","outputDir":"/dist""#, RequestError::InvalidOutputDir),
            (r#","outputDir":"a//b""#, RequestError::InvalidOutputDir),
            (r#","outputDir":".hidden""#, RequestError::InvalidOutputDir),
            (
                r#","outputDir":"a/b/c/d/e""#,
                RequestError::InvalidOutputDir,
            ),
            (r#","outputDir":"a b""#, RequestError::InvalidOutputDir),
            (r#","memoryMb":256"#, RequestError::InvalidLimit),
            (r#","memoryMb":9000"#, RequestError::InvalidLimit),
            (r#","timeoutSecs":10"#, RequestError::InvalidLimit),
            (r#","timeoutSecs":99999"#, RequestError::InvalidLimit),
            (r#","command":"sh""#, RequestError::InvalidJson),
        ] {
            assert_eq!(ok(extra).unwrap_err(), error, "{extra}");
        }
        let with = |image: &str, root: &str, uid: u32| {
            format!(r#"{{"projectRoot":"{root}","image":"{image}","uid":{uid},"gid":1000}}"#)
        };
        let pinned = format!("docker.io/library/node:22@sha256:{DIGEST}");
        for (image, root, uid, error) in [
            ("node:22", root, 1000, RequestError::InvalidImage),
            ("node@sha256:abc", root, 1000, RequestError::InvalidImage),
            (
                "evil.example.com/n@sha256:0000000000000000000000000000000000000000000000000000000000000000",
                root,
                1000,
                RequestError::InvalidImage,
            ),
            (pinned.as_str(), "var/www", 1000, RequestError::InvalidRoot),
            (
                pinned.as_str(),
                "/var/www/../etc",
                1000,
                RequestError::InvalidRoot,
            ),
            (pinned.as_str(), "/", 1000, RequestError::InvalidRoot),
            (pinned.as_str(), root, 0, RequestError::InvalidIdentity),
        ] {
            assert_eq!(
                Request::parse(&with(image, root, uid), ID, None).unwrap_err(),
                error,
                "{image} {root} {uid}"
            );
        }
        assert_eq!(
            Request::parse(&plan(Path::new(root), ""), "nope", None).unwrap_err(),
            RequestError::InvalidRequestId
        );
    }

    #[test]
    fn builds_in_a_sandbox_and_keeps_only_the_output() {
        let f = fixture("");
        let result = run(&f, "", ID, Some("k1")).unwrap();
        assert_eq!(result.files, 2);
        assert_eq!(result.output_dir, "dist");
        let artifact = Path::new(&result.artifact_path);
        assert_eq!(
            fs::read_to_string(artifact.join("index.html")).unwrap(),
            "hi\n"
        );
        assert_eq!(
            fs::read_to_string(artifact.join("assets/a.js")).unwrap(),
            "js\n"
        );

        let recorded = calls(f.dir.path());
        assert_eq!(recorded.len(), 2, "{recorded:?}");
        assert!(
            recorded[0].ends_with(" npm ci --no-audit --no-fund"),
            "{}",
            recorded[0]
        );
        assert!(recorded[1].ends_with(" npm run build"), "{}", recorded[1]);
        for call in &recorded {
            for flag in [
                "--user 1000:1000",
                "--cap-drop ALL",
                "--security-opt no-new-privileges",
                "--read-only",
                "--pids-limit 1024",
                "--memory 2048m",
                "--memory-swap 2048m",
                "node:22-alpine@sha256:",
                "target=/work",
                "--workdir /work",
            ] {
                assert!(call.contains(flag), "{flag} missing in {call}");
            }
            assert!(!call.contains("docker.sock"), "{call}");
            assert!(!call.contains("--privileged"), "{call}");
            assert!(!call.contains(" sh "), "{call}");
        }

        // What the container saw: sources yes; secrets and dependencies no.
        let staged = fs::read_to_string(f.dir.path().join("staged.ls")).unwrap();
        let names: Vec<&str> = staged.lines().collect();
        assert!(names.contains(&"package.json") && names.contains(&"package-lock.json"));
        assert!(names.contains(&"src"));
        for hidden in [".env", ".env.production", ".npmrc", "node_modules", ".git"] {
            assert!(
                !names.contains(&hidden),
                "{hidden} reached the build: {names:?}"
            );
        }
        // The site is untouched and the staging copy is gone.
        assert!(f.project.join(".env").exists() && !f.project.join("dist").exists());
        let work = f.state.join("node-build");
        let hash = fs::read_dir(&work).unwrap().next().unwrap().unwrap().path();
        assert_eq!(fs::read_dir(hash.join("work")).unwrap().count(), 0);
        let log = fs::read_to_string(&result.log_path).unwrap();
        assert!(log.contains("== npm-ci ==") && log.contains("== the-build-script =="));
        assert_eq!(
            fs::metadata(&result.log_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_server_build_keeps_the_output_path_and_the_package_files() {
        let f = fixture("");
        let result = run(&f, r#","server":true"#, ID, None).unwrap();
        let artifact = Path::new(&result.artifact_path);
        assert_eq!(
            fs::read_to_string(artifact.join("dist/index.html")).unwrap(),
            "hi\n"
        );
        assert_eq!(
            fs::read_to_string(artifact.join("dist/assets/a.js")).unwrap(),
            "js\n"
        );
        assert!(
            artifact.join("package.json").is_file() && artifact.join("package-lock.json").is_file()
        );
        assert!(
            !artifact.join("index.html").exists(),
            "the static layout is not used"
        );
        assert_eq!(result.files, 4);
    }

    #[test]
    fn flags_follow_the_request() {
        let f = fixture("");
        run(
            &f,
            r#","script":"build","memoryMb":1024,"ignoreScripts":true"#,
            ID,
            None,
        )
        .unwrap();
        let recorded = calls(f.dir.path());
        assert!(recorded[0].ends_with("npm ci --no-audit --no-fund --ignore-scripts"));
        assert!(recorded[0].contains("--memory 1024m"));
    }

    #[test]
    fn a_failed_install_stops_before_the_build_and_is_replayed_as_failed() {
        let f = fixture("ci");
        let error = run(&f, "", ID, Some("k")).unwrap_err();
        let (code, message) = error.protocol();
        assert_eq!(code, ErrorCode::SubprocessFailed);
        assert_eq!(message, "npm ci failed (exit code 1)");
        assert_eq!(calls(f.dir.path()).len(), 2, "install + cleanup, no build");
        assert!(matches!(
            run(&f, "", ID2, Some("k")),
            Err(Error::Replayed { .. })
        ));
        assert_eq!(calls(f.dir.path()).len(), 2, "a retry must not re-run");
        // No artifact; the log of the failure stays.
        let hash = fs::read_dir(f.state.join("node-build"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(fs::read_dir(hash.join("artifacts")).unwrap().count(), 0);
        assert!(
            fs::read_to_string(hash.join("logs").join(format!("{ID}.log")))
                .unwrap()
                .contains("ci boom")
        );
    }

    #[test]
    fn a_failed_build_script_leaves_no_artifact() {
        let f = fixture("build");
        let (code, message) = run(&f, "", ID, None).unwrap_err().protocol();
        assert_eq!(code, ErrorCode::SubprocessFailed);
        assert_eq!(message, "the build script failed (exit code 1)");
        let hash = fs::read_dir(f.state.join("node-build"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(fs::read_dir(hash.join("artifacts")).unwrap().count(), 0);
        assert_eq!(fs::read_dir(hash.join("work")).unwrap().count(), 0);
    }

    #[test]
    fn a_build_without_output_is_refused() {
        let f = fixture("nooutput");
        let (code, message) = run(&f, "", ID, None).unwrap_err().protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert_eq!(message, "the build produced no output directory");
    }

    #[test]
    fn projects_that_cannot_be_built_never_start_a_container() {
        for (what, message) in [
            (
                "lock",
                "a lockfile is required (package-lock.json, pnpm-lock.yaml or yarn.lock)",
            ),
            (
                "two locks",
                "more than one lockfile exists; keep only the one of the project's package manager",
            ),
            (
                "script",
                "package.json has no script with the requested name",
            ),
            ("symlink", "the tree contains a symlink or a special file"),
            ("hardlink", "the tree contains a hard-linked file"),
            ("json", "package.json is not valid JSON"),
        ] {
            let f = fixture("");
            match what {
                "lock" => fs::remove_file(f.project.join("package-lock.json")).unwrap(),
                "two locks" => {
                    fs::write(f.project.join("yarn.lock"), "# yarn lockfile v1\n").unwrap()
                }
                "script" => fs::write(
                    f.project.join("package.json"),
                    r#"{"scripts":{"lint":"x"}}"#,
                )
                .unwrap(),
                "symlink" => {
                    std::os::unix::fs::symlink("/etc/passwd", f.project.join("src/leak")).unwrap()
                }
                "hardlink" => {
                    fs::hard_link(f.project.join("src/page.js"), f.project.join("src/twin.js"))
                        .unwrap()
                }
                _ => fs::write(f.project.join("package.json"), "{").unwrap(),
            }
            let (code, got) = run(&f, "", ID, None).unwrap_err().protocol();
            assert_eq!(
                (code, got.as_str()),
                (ErrorCode::InvalidInput, message),
                "{what}"
            );
            assert!(calls(f.dir.path()).is_empty(), "{what}: no container");
        }
    }

    #[test]
    fn pnpm_and_yarn_projects_build_with_their_own_tool() {
        for (lock, text, install, run_build, label) in [
            (
                "pnpm-lock.yaml",
                "lockfileVersion: '9.0'\n",
                " corepack pnpm install --frozen-lockfile",
                " corepack pnpm run build",
                "pnpm install",
            ),
            (
                "yarn.lock",
                "# yarn lockfile v1\n",
                " yarn install --frozen-lockfile --non-interactive",
                " yarn run build",
                "yarn install",
            ),
        ] {
            let f = fixture("");
            fs::remove_file(f.project.join("package-lock.json")).unwrap();
            fs::write(f.project.join(lock), text).unwrap();
            let result = run(&f, r#","server":true"#, ID, None).unwrap();
            let recorded = calls(f.dir.path());
            assert!(recorded[0].ends_with(install), "{lock}: {}", recorded[0]);
            assert!(recorded[1].ends_with(run_build), "{lock}: {}", recorded[1]);
            assert!(
                recorded.iter().all(|call| !call.contains(" npm ")),
                "{lock}"
            );
            // The artifact carries the project's own lockfile.
            let artifact = PathBuf::from(&result.artifact_path);
            assert!(artifact.join(lock).is_file(), "{lock}");
            assert!(!artifact.join("package-lock.json").exists(), "{lock}");
            let log = fs::read_to_string(&result.log_path).unwrap();
            assert!(
                log.contains(&format!("== {} ==", label.replace(' ', "-"))),
                "{lock}"
            );
        }
    }

    #[test]
    fn yarn_berry_is_refused_before_any_container() {
        let f = fixture("");
        fs::remove_file(f.project.join("package-lock.json")).unwrap();
        fs::write(f.project.join("yarn.lock"), "__metadata:\n  version: 8\n").unwrap();
        let (code, message) = run(&f, "", ID, None).unwrap_err().protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert!(message.starts_with("Yarn Berry"), "{message}");
        assert!(calls(f.dir.path()).is_empty());
    }

    #[test]
    fn a_requested_script_must_exist() {
        let f = fixture("");
        let (code, message) = run(&f, r#","script":"deploy""#, ID, None)
            .unwrap_err()
            .protocol();
        assert_eq!(code, ErrorCode::InvalidInput);
        assert_eq!(
            message,
            "package.json has no script with the requested name"
        );
    }

    #[test]
    fn only_the_newest_artifacts_are_kept() {
        let f = fixture("");
        let mut ids = Vec::new();
        for n in 0..5u8 {
            let id = format!("123e4567-e89b-12d3-a456-4266141740{n:02}");
            run(&f, "", &id, None).unwrap();
            ids.push(id);
            std::thread::sleep(Duration::from_millis(1100));
        }
        let hash = fs::read_dir(f.state.join("node-build"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let kept: Vec<String> = fs::read_dir(hash.join("artifacts"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(kept.len(), KEEP_ARTIFACTS, "{kept:?}");
        for id in &ids[2..] {
            assert!(kept.contains(id), "{id} should be kept: {kept:?}");
        }
    }

    #[test]
    fn the_staging_copy_skips_exactly_the_credential_and_dependency_names() {
        for name in [
            "node_modules",
            ".git",
            ".npmrc",
            ".env",
            ".env.local",
            ".env.production",
        ] {
            assert!(skip_for_build(name), "{name}");
        }
        for name in [
            ".envrc",
            "env",
            ".gitignore",
            "npmrc",
            ".github",
            "src",
            ".env_example",
        ] {
            assert!(!skip_for_build(name), "{name}");
        }
    }
}
