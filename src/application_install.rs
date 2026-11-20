//! The `application.install` operation: stands up a Composer application in
//! the project root of a site that `site.create` already made (so the root
//! exists, belongs to the site's UID and holds at most the docroot with its
//! `.user.ini`). Per-resource lock, idempotency, transaction and audit follow
//! `wordpress.install`.
//!
//! Only Statamic is installed so far. Its steps, as the site's UID inside the
//! runtime container:
//!
//! 1. `composer create-project` into a hidden directory of the project root
//!    (Composer refuses a directory that is not empty);
//! 2. every top-level entry moves into the project root with a typed rename,
//!    the docroot's entries into the existing docroot;
//! 3. a fixed set of `.env` keys is written for the site's URL;
//! 4. `php please make:user <email> --super --password=...` creates the first
//!    administrator. Without `--password` Statamic stores an *empty*
//!    password, and it takes one only as an option, so the password travels
//!    in the environment of the `docker exec` (`-e NAME`, never `-e
//!    NAME=value`) and a fixed `sh -c` script expands it: it is not in the
//!    host's argv, the request file is the only place the engine reads it
//!    from, and it is in no result, journal or audit record. The panel
//!    generates it and shows it once.
//!
//! Unlike `wordpress.install`, this operation owns what it writes, so a
//! failure removes exactly the entries it created (kept in memory: a crash
//! mid-install leaves them for the retry's non-empty check to report).

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    clock::unix_now_secs,
    db_restore::{ContainerName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessRunError,
    },
    site::{Domain, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
    wordpress_install::{validate_bounded, validate_email},
};

pub const OPERATION: &str = "application.install";

/// Where the managed Composer lives inside a runtime container.
const CONTAINER_COMPOSER: &str = "/opt/wcp-tools/composer/current/composer.phar";
const COMPOSER_HOME: &str = "/tmp/wcp-composer";
const COMPOSER_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SETUP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_ROOT_BYTES: usize = 4096;
const MIN_ADMIN_PASSWORD_BYTES: usize = 12;
const MAX_ADMIN_PASSWORD_BYTES: usize = 256;
/// The environment variable that carries the administrator's password into
/// the container; fixed text, never built from input.
const PASSWORD_ENV: &str = "STATAMIC_ADMIN_PASSWORD";
/// `$1` is the administrator's address (a positional argument), the password
/// comes from the environment.
const MAKE_USER_SCRIPT: &str = "exec php please make:user \"$1\" --super --password=\"$STATAMIC_ADMIN_PASSWORD\" --no-interaction";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Application {
    Statamic,
}

impl Application {
    const fn name(self) -> &'static str {
        match self {
            Self::Statamic => "statamic",
        }
    }
    const fn package(self) -> &'static str {
        match self {
            Self::Statamic => "statamic/statamic",
        }
    }
    /// The directory the web server serves, below the project root.
    const fn docroot(self) -> &'static str {
        match self {
            Self::Statamic => "public",
        }
    }
    const fn admin_path(self) -> &'static str {
        match self {
            Self::Statamic => "/cp",
        }
    }
    /// The Composer package whose locked version is the application's.
    const fn version_package(self) -> &'static str {
        match self {
            Self::Statamic => "statamic/cms",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    container: String,
    project_root: String,
    uid: u32,
    gid: u32,
    domain: String,
    application: Application,
    admin_email: String,
    admin_password: String,
}

pub struct Request {
    container: ContainerName,
    project_root: PathBuf,
    uid: u32,
    gid: u32,
    domain: Domain,
    application: Application,
    admin_email: String,
    admin_password: String,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestError;

impl Request {
    pub fn parse(json: &str, request_id: &str, key: Option<&str>) -> Result<Self, RequestError> {
        let plan: Plan = serde_json::from_str(json).map_err(|_| RequestError)?;
        let root = PathBuf::from(&plan.project_root);
        if !root.is_absolute()
            || plan.project_root.len() > MAX_ROOT_BYTES
            || plan.project_root.ends_with('/')
            || root.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::Normal(_) | std::path::Component::RootDir
                )
            })
        {
            return Err(RequestError);
        }
        validate_email(&plan.admin_email).map_err(|_| RequestError)?;
        // The address becomes a command-line argument: never an option.
        if plan.admin_email.starts_with('-') {
            return Err(RequestError);
        }
        validate_bounded(&plan.admin_password, MAX_ADMIN_PASSWORD_BYTES)
            .map_err(|_| RequestError)?;
        if plan.admin_password.len() < MIN_ADMIN_PASSWORD_BYTES
            || plan
                .admin_password
                .bytes()
                .any(|b| matches!(b, b'\n' | b'\r'))
        {
            return Err(RequestError);
        }
        Ok(Self {
            container: ContainerName::parse(&plan.container)
                .map_err(|_: RestoreRequestError| RequestError)?,
            project_root: root,
            uid: plan.uid,
            gid: plan.gid,
            domain: Domain::parse(&plan.domain).map_err(|_| RequestError)?,
            application: plan.application,
            admin_email: plan.admin_email,
            admin_password: plan.admin_password,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError)?,
            idempotency_key: key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError)?,
        })
    }

    pub fn project_root(&self) -> &Path {
        &self.project_root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub application: String,
    pub version: String,
    pub admin_url: String,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub engine_state: &'a ManagedRoot,
    pub docker_program: &'a str,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(ProcessRunError),
    RootUnavailable,
    TargetNotEmpty,
    ResourceBusy,
    ComposerFailed(ErrorCode),
    SetupFailed(ErrorCode),
    /// The installed application's version could not be read back.
    Unverified,
    PostCommit {
        result: InstallResult,
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
                "another operation is in progress for this site".into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request is still in progress".into(),
            ),
            Self::Run(error) => (
                process::spawn_error_code(error),
                "could not run an application install prerequisite".into(),
            ),
            Self::RootUnavailable => (
                ErrorCode::InvalidInput,
                "the project root does not exist or is outside the configured content root".into(),
            ),
            Self::TargetNotEmpty => (
                ErrorCode::Conflict,
                "the project root already has content; only an empty site can be installed".into(),
            ),
            Self::ComposerFailed(code) => (
                *code,
                "Composer could not create the project (network, package or PHP conflict)".into(),
            ),
            Self::SetupFailed(code) => (*code, "the application setup failed".into()),
            Self::Unverified => (
                ErrorCode::Internal,
                "the installed version could not be read back".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            _ => (
                ErrorCode::Internal,
                "internal application install error".into(),
            ),
        }
    }
}

fn rel(value: impl AsRef<Path>) -> Result<SiteRelativePath, Error> {
    SiteRelativePath::parse(value).map_err(|_| Error::RootUnavailable)
}

pub fn execute(
    ctx: &Context<'_>,
    content_root: &TrustedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let hash = resource_lock::canonical_hash(&req.project_root);
    let scope_path = SiteRelativePath::parse(format!("application-install/{hash}")).unwrap();
    ctx.engine_state
        .create_dir_all(&scope_path)
        .map_err(Error::Io)?;
    let scope = ctx
        .engine_state
        .open_managed_dir(&scope_path)
        .map_err(Error::Io)?;
    for child in ["locks", "transactions", "audit"] {
        scope
            .create_dir_all(&SiteRelativePath::parse(child).unwrap())
            .map_err(Error::Io)?;
    }
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
    let state_path =
        SiteRelativePath::parse(format!("transactions/{}.json", req.request_id)).unwrap();
    let audit_path = SiteRelativePath::parse("audit/events.jsonl").unwrap();

    match install(ctx, content_root, req, cancel) {
        Ok(result) => {
            state
                .mark_committed(serde_json::to_value(&result).unwrap())
                .unwrap();
            if state::save(&scope, &state_path, &state).is_err() {
                drop(lock);
                return Err(Error::PostCommit { result });
            }
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(req.request_id, true, None),
            );
            drop(lock);
            Ok(result)
        }
        Err(error) => {
            let (code, message) = error.protocol();
            let _ = state.mark_failed(code, message);
            let _ = state::save(&scope, &state_path, &state);
            let _ = audit::append(
                &scope,
                &audit_path,
                &AuditRecord::result(state.request_id, false, Some(code)),
            );
            Err(error)
        }
    }
}

/// What the install wrote below the project root, as paths relative to it.
#[derive(Default)]
struct Created(Vec<SiteRelativePath>);

fn install(
    ctx: &Context<'_>,
    content_root: &TrustedRoot,
    req: &Request,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let relative = req
        .project_root
        .strip_prefix(content_root.as_path())
        .ok()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(Error::RootUnavailable)?;
    let resolved = content_root
        .resolve_existing(&rel(relative)?)
        .map_err(|_| Error::RootUnavailable)?;
    let root_str = resolved.to_str().ok_or(Error::RootUnavailable)?;
    let root =
        ManagedRoot::open(&TrustedRoot::parse(&resolved).map_err(|_| Error::RootUnavailable)?)
            .map_err(|_| Error::RootUnavailable)?;
    let docroot = req.application.docroot();
    require_empty(&root, docroot)?;

    let staging = format!(".wcp-install-{}", req.request_id);
    let mut created = Created::default();
    match run_install(
        ctx,
        req,
        &root,
        root_str,
        docroot,
        &staging,
        &mut created,
        cancel,
    ) {
        Ok(result) => {
            let _ = root.remove_dir_all(&rel(&staging)?);
            Ok(result)
        }
        Err(error) => {
            undo(&root, &staging, &created);
            Err(error)
        }
    }
}

/// The project root may hold the docroot directory with a `.user.ini` and
/// nothing else.
fn require_empty(root: &ManagedRoot, docroot: &str) -> Result<(), Error> {
    for entry in root.child_entries_bounded(64).map_err(Error::Io)? {
        if entry.name != docroot || !entry.is_dir {
            return Err(Error::TargetNotEmpty);
        }
        let inner = root
            .open_child_dir_nofollow(&rel(docroot)?)
            .map_err(Error::Io)?;
        for child in inner.child_entries_bounded(64).map_err(Error::Io)? {
            if child.name != ".user.ini" || child.is_dir {
                return Err(Error::TargetNotEmpty);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_install(
    ctx: &Context<'_>,
    req: &Request,
    root: &ManagedRoot,
    root_str: &str,
    docroot: &str,
    staging: &str,
    created: &mut Created,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    let home = format!("COMPOSER_HOME={COMPOSER_HOME}");
    let cache = format!("COMPOSER_CACHE_DIR={COMPOSER_HOME}/cache");
    let output = exec(
        ctx,
        req,
        root_str,
        &[&home, &cache, "COMPOSER_NO_INTERACTION=1"],
        &[],
        &[
            "php",
            CONTAINER_COMPOSER,
            "create-project",
            req.application.package(),
            staging,
            "--no-interaction",
            "--no-ansi",
            "--no-progress",
        ],
        COMPOSER_TIMEOUT,
        cancel,
    )?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::ComposerFailed(code));
    }

    move_into_place(root, staging, docroot, created)?;
    set_site_url(root, req)?;

    let output = exec(
        ctx,
        req,
        root_str,
        &[],
        &[(PASSWORD_ENV, &req.admin_password)],
        &["sh", "-c", MAKE_USER_SCRIPT, "sh", &req.admin_email],
        SETUP_TIMEOUT,
        cancel,
    )?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::SetupFailed(code));
    }

    let version = locked_version(root, req.application)?;
    Ok(InstallResult {
        application: req.application.name().to_owned(),
        version,
        admin_url: format!(
            "https://{}{}",
            req.domain.as_str(),
            req.application.admin_path()
        ),
        completed_at_unix_secs: unix_now_secs(),
    })
}

/// Moves each top-level entry of the staging directory into the project root;
/// the docroot's entries go into the docroot that is already there. Nothing
/// is overwritten: a name that exists is a conflict.
fn move_into_place(
    root: &ManagedRoot,
    staging: &str,
    docroot: &str,
    created: &mut Created,
) -> Result<(), Error> {
    let staged = root
        .open_child_dir_nofollow(&rel(staging)?)
        .map_err(Error::Io)?;
    for entry in staged.child_entries().map_err(Error::Io)? {
        let name = entry
            .name
            .to_str()
            .ok_or(Error::RootUnavailable)?
            .to_owned();
        if name == docroot && entry.is_dir {
            let inner = staged
                .open_child_dir_nofollow(&rel(&name)?)
                .map_err(Error::Io)?;
            for child in inner.child_entries().map_err(Error::Io)? {
                let child_name = child.name.to_str().ok_or(Error::RootUnavailable)?;
                let target = rel(format!("{docroot}/{child_name}"))?;
                if root.symlink_metadata(&target).is_ok() {
                    return Err(Error::TargetNotEmpty);
                }
                root.rename(&rel(format!("{staging}/{docroot}/{child_name}"))?, &target)
                    .map_err(Error::Io)?;
                created.0.push(target);
            }
        } else {
            let target = rel(&name)?;
            if root.symlink_metadata(&target).is_ok() {
                return Err(Error::TargetNotEmpty);
            }
            root.rename(&rel(format!("{staging}/{name}"))?, &target)
                .map_err(Error::Io)?;
            created.0.push(target);
        }
    }
    Ok(())
}

/// Points the application at the site's own address: a fixed key set, written
/// through the managed root and kept readable by the site's UID.
fn set_site_url(root: &ManagedRoot, req: &Request) -> Result<(), Error> {
    let env = rel(".env")?;
    let original = root.read_to_string(&env).map_err(Error::Io)?;
    let url = format!("https://{}", req.domain.as_str());
    let updated = crate::util::set_env_lines(
        &original,
        &[
            ("APP_URL", &url),
            ("APP_ENV", "production"),
            ("APP_DEBUG", "false"),
        ],
    )
    .map_err(Error::Io)?;
    root.write_atomic(&env, updated.as_bytes())
        .map_err(Error::Io)?;
    root.chown(&env, req.uid, req.gid).map_err(Error::Io)?;
    root.set_mode(&env, 0o640).map_err(Error::Io)
}

/// The locked version of the application's own package, read from
/// `composer.lock` without running PHP. Not found is unknown, not success.
fn locked_version(root: &ManagedRoot, application: Application) -> Result<String, Error> {
    let lock = root
        .read_to_string(&rel("composer.lock")?)
        .map_err(|_| Error::Unverified)?;
    let value: serde_json::Value = serde_json::from_str(&lock).map_err(|_| Error::Unverified)?;
    value["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|package| package["name"] == application.version_package())
        .and_then(|package| package["version"].as_str())
        .map(|version| version.trim_start_matches('v').to_owned())
        .filter(|version| crate::joomla_update::plain_version(version))
        .ok_or(Error::Unverified)
}

/// Removes exactly what this install wrote: the moved entries and the staging
/// directory. The project root, the docroot directory and its `.user.ini`
/// were there before and stay.
fn undo(root: &ManagedRoot, staging: &str, created: &Created) {
    for path in created.0.iter().rev() {
        let is_dir = root
            .symlink_metadata(path)
            .map(|meta| meta.is_dir())
            .unwrap_or(false);
        let _ = if is_dir {
            root.remove_dir_all(path)
        } else {
            root.remove_file(path)
        };
    }
    if let Ok(staging) = SiteRelativePath::parse(staging) {
        let _ = root.remove_dir_all(&staging);
    }
}

/// `docker exec` as the site's UID in the project root; `program_and_args`
/// never carries caller text except the validated address.
#[allow(clippy::too_many_arguments)]
fn exec(
    ctx: &Context<'_>,
    req: &Request,
    cwd: &str,
    env: &[&str],
    secrets: &[(&str, &str)],
    program_and_args: &[&str],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let mut args: Vec<String> = vec![
        "exec".into(),
        "-i".into(),
        "--user".into(),
        format!("{}:{}", req.uid, req.gid),
        "-w".into(),
        cwd.to_owned(),
    ];
    for value in env {
        args.push("-e".into());
        args.push((*value).to_owned());
    }
    // `-e NAME` without a value takes the value from this process's
    // environment, so a secret is never in the argv of `docker`.
    for (name, _) in secrets {
        args.push("-e".into());
        args.push((*name).to_owned());
    }
    args.push(req.container.as_str().to_owned());
    args.extend(program_and_args.iter().map(|arg| (*arg).to_owned()));
    let mut request = ProcessRequest::new(ctx.docker_program).args(args);
    for (name, value) in secrets {
        request = request.env(name, value);
    }
    process::run(
        &request,
        &ProcessLimits {
            timeout,
            max_stdout_bytes: MAX_OUTPUT_BYTES,
            max_stderr_bytes: MAX_OUTPUT_BYTES,
        },
        cancel,
    )
    .map_err(Error::Run)
}

fn replay(scope: &ManagedRoot, id: RequestId) -> Result<InstallResult, Error> {
    let loaded = state::load(
        scope,
        &SiteRelativePath::parse(format!("transactions/{id}.json")).unwrap(),
    )
    .map_err(|e| Error::Io(std::io::Error::other(format!("{e:?}"))))?;
    if loaded.operation != OPERATION {
        return Err(Error::Io(std::io::Error::other(
            "transaction operation mismatch",
        )));
    }
    match loaded.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            serde_json::from_value(loaded.outcome.unwrap().result.unwrap())
                .map_err(|e| Error::Io(std::io::Error::other(e)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::MetadataExt, os::unix::fs::PermissionsExt};

    const REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER_ID: &str = "223e4567-e89b-12d3-a456-426614174000";
    const PASSWORD: &str = "correct-horse-battery-1";

    fn plan(root: &str, uid: u32, gid: u32) -> String {
        serde_json::json!({
            "container": "runtime-1",
            "projectRoot": root,
            "uid": uid,
            "gid": gid,
            "domain": "example.com",
            "application": "statamic",
            "adminEmail": "admin@example.com",
            "adminPassword": PASSWORD,
        })
        .to_string()
    }

    #[test]
    fn accepts_a_plan_and_rejects_malformed_fields() {
        assert!(
            Request::parse(&plan("/var/www/example.com", 1000, 1000), REQUEST_ID, None).is_ok()
        );
        let base = plan("/var/www/example.com", 1000, 1000);
        for (from, to) in [
            ("/var/www/example.com", "var/www/example.com"),
            ("/var/www/example.com", "/var/www/example.com/"),
            ("/var/www/example.com", "/var/www/../etc"),
            ("\"example.com\"", "\"-bad-\""),
            ("admin@example.com", "-x@example.com"),
            ("admin@example.com", "not-an-email"),
            ("\"statamic\"", "\"craft\""),
            ("runtime-1", "bad name"),
        ] {
            assert!(
                Request::parse(&base.replace(from, to), REQUEST_ID, None).is_err(),
                "{to}"
            );
        }
        // The password is required, long enough and one line.
        for bad in [
            "",
            "short",
            "twelve-chars\nsecond",
            "twelve-chars\rx",
            &"x".repeat(257),
        ] {
            assert!(
                Request::parse(&base.replace(PASSWORD, bad), REQUEST_ID, None).is_err(),
                "{bad:?}"
            );
        }
        let mut value: serde_json::Value = serde_json::from_str(&base).unwrap();
        value.as_object_mut().unwrap().remove("adminPassword");
        assert!(Request::parse(&value.to_string(), REQUEST_ID, None).is_err());
        value["extra"] = true.into();
        assert!(Request::parse(&value.to_string(), REQUEST_ID, None).is_err());
        assert!(Request::parse(&base, "not-a-uuid", None).is_err());
    }

    /// A fake `docker` that stands in for Composer and Statamic: it logs each
    /// call's argv to `calls.log` and, for `create-project`, writes a project
    /// tree into the staging directory named in its arguments.
    const FAKE_DOCKER: &str = r#"#!/bin/sh
dir=$(dirname "$0")
echo "$@" >> "$dir/calls.log"
echo "$STATAMIC_ADMIN_PASSWORD" >> "$dir/env.log"
cwd=""
prev=""
for a in "$@"; do
  [ "$prev" = "-w" ] && cwd="$a"
  prev="$a"
done
case "$*" in
  *create-project*)
    [ -e "$dir/fail-composer" ] && exit 1
    staging=""
    take=0
    for a in "$@"; do
      if [ "$take" = 1 ]; then staging="$a"; take=0; fi
      [ "$a" = "statamic/statamic" ] && take=1
    done
    mkdir -p "$cwd/$staging/public" "$cwd/$staging/app"
    echo '<?php' > "$cwd/$staging/public/index.php"
    printf 'APP_URL=http://localhost:8000\nAPP_ENV=local\n' > "$cwd/$staging/.env"
    echo '{"packages":[{"name":"statamic/cms","version":"v6.2.1"}]}' > "$cwd/$staging/composer.lock"
    ;;
  *make:user*)
    [ -e "$dir/fail-user" ] && exit 1
    ;;
esac
exit 0
"#;

    struct Fixture {
        dir: tempfile::TempDir,
        content_root: TrustedRoot,
        state: ManagedRoot,
        site: PathBuf,
        uid: u32,
        gid: u32,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let content = dir.path().join("content");
        let state_dir = dir.path().join("state");
        let site = content.join("example.com");
        fs::create_dir_all(site.join("public")).unwrap();
        fs::write(site.join("public/.user.ini"), "x").unwrap();
        fs::create_dir_all(&state_dir).unwrap();
        let docker = dir.path().join("docker");
        fs::write(&docker, FAKE_DOCKER).unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        let meta = fs::metadata(&site).unwrap();
        Fixture {
            content_root: TrustedRoot::parse(&content).unwrap(),
            state: ManagedRoot::open(&TrustedRoot::parse(&state_dir).unwrap()).unwrap(),
            site,
            uid: meta.uid(),
            gid: meta.gid(),
            dir,
        }
    }

    impl Fixture {
        fn run(&self, id: &str, key: Option<&str>) -> Result<InstallResult, Error> {
            let docker = self.dir.path().join("docker");
            let request = Request::parse(
                &plan(self.site.to_str().unwrap(), self.uid, self.gid),
                id,
                key,
            )
            .unwrap();
            execute(
                &Context {
                    engine_state: &self.state,
                    docker_program: docker.to_str().unwrap(),
                },
                &self.content_root,
                &request,
                &CancellationToken::default(),
            )
        }
        fn calls(&self) -> String {
            fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
        }
        fn names(&self, below: &str) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.site.join(below))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    #[test]
    fn installs_into_an_empty_site_and_keeps_the_docroot_files() {
        let f = fixture();
        let result = f.run(REQUEST_ID, None).unwrap();
        assert_eq!(result.application, "statamic");
        assert_eq!(result.version, "6.2.1");
        assert_eq!(result.admin_url, "https://example.com/cp");
        assert_eq!(f.names(""), [".env", "app", "composer.lock", "public"]);
        assert_eq!(f.names("public"), [".user.ini", "index.php"]);
        let env = fs::read_to_string(f.site.join(".env")).unwrap();
        assert_eq!(
            env,
            "APP_URL=https://example.com\nAPP_ENV=production\nAPP_DEBUG=false\n"
        );
        assert_eq!(
            fs::metadata(f.site.join(".env"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let calls = f.calls();
        assert!(calls.contains("--user"), "{calls}");
        // The address is a positional argument of a fixed script; the
        // password is only in the environment of `docker`, named without a
        // value, and in no argument.
        assert!(
            calls.contains("-e STATAMIC_ADMIN_PASSWORD runtime-1 sh -c exec php please make:user")
                && calls.trim_end().ends_with("sh admin@example.com"),
            "{calls}"
        );
        assert!(!calls.contains(PASSWORD), "{calls}");
        let env = fs::read_to_string(f.dir.path().join("env.log")).unwrap();
        assert!(env.lines().any(|line| line == PASSWORD), "{env}");
        // Nothing the engine returns or records carries it.
        assert!(!serde_json::to_string(&result).unwrap().contains(PASSWORD));
    }

    #[test]
    fn a_site_with_content_is_refused_before_anything_runs() {
        let f = fixture();
        fs::write(f.site.join("index.html"), "mine").unwrap();
        assert!(matches!(
            f.run(REQUEST_ID, None),
            Err(Error::TargetNotEmpty)
        ));
        assert_eq!(f.calls(), "");
        let g = fixture();
        fs::write(g.site.join("public/page.php"), "mine").unwrap();
        assert!(matches!(
            g.run(REQUEST_ID, None),
            Err(Error::TargetNotEmpty)
        ));
        assert_eq!(g.calls(), "");
        assert_eq!(g.names("public"), [".user.ini", "page.php"]);
    }

    #[test]
    fn a_failed_composer_run_leaves_the_site_as_it_was() {
        let f = fixture();
        fs::write(f.dir.path().join("fail-composer"), "").unwrap();
        assert!(matches!(
            f.run(REQUEST_ID, None),
            Err(Error::ComposerFailed(_))
        ));
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
    }

    #[test]
    fn a_failed_setup_removes_exactly_what_the_install_wrote() {
        let f = fixture();
        fs::write(f.dir.path().join("fail-user"), "").unwrap();
        assert!(matches!(
            f.run(REQUEST_ID, None),
            Err(Error::SetupFailed(_))
        ));
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
        // The empty site can be installed again once the cause is gone.
        fs::remove_file(f.dir.path().join("fail-user")).unwrap();
        assert!(f.run(OTHER_ID, None).is_ok());
    }

    #[test]
    fn a_repeated_request_replays_without_running_anything_again() {
        let f = fixture();
        let first = f.run(REQUEST_ID, Some("key-1")).unwrap();
        let calls = f.calls();
        let again = f.run(REQUEST_ID, Some("key-1")).unwrap();
        assert_eq!(again.version, first.version);
        assert_eq!(f.calls(), calls);
    }

    #[test]
    fn the_version_comes_from_the_lock_and_unknown_is_not_success() {
        let f = fixture();
        let root = ManagedRoot::open(&TrustedRoot::parse(&f.site).unwrap()).unwrap();
        for content in [
            "not json",
            r#"{"packages":[]}"#,
            r#"{"packages":[{"name":"statamic/cms","version":"dev-main"}]}"#,
            r#"{"packages":[{"name":"statamic/cms","version":"6.2.1; rm"}]}"#,
        ] {
            fs::write(f.site.join("composer.lock"), content).unwrap();
            assert!(
                matches!(
                    locked_version(&root, Application::Statamic),
                    Err(Error::Unverified)
                ),
                "{content}"
            );
        }
        fs::write(
            f.site.join("composer.lock"),
            r#"{"packages":[{"name":"a/b","version":"1.0.0"},{"name":"statamic/cms","version":"v6.2.1"}]}"#,
        )
        .unwrap();
        assert_eq!(
            locked_version(&root, Application::Statamic).unwrap(),
            "6.2.1"
        );
    }
}
