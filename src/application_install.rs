//! The `application.install` operation: stands up a Composer application in
//! the project root of a site that `site.create` already made (so the root
//! exists, belongs to the site's UID and holds at most the docroot with its
//! `.user.ini`). Per-resource lock, idempotency, transaction and audit follow
//! `wordpress.install`.
//!
//! Statamic, Craft CMS 5 and TYPO3 are installed. Statamic's steps, as the
//! site's UID inside the runtime container (Craft and TYPO3 share steps 1 and
//! 2 and differ after them, see their functions below):
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
//! Drupal is `drupal/recommended-project` with Drush required into the
//! project, then `drush site:install` (see `setup_drupal`).
//!
//! Laravel has no administrator and two sources: Composer's project
//! template, or a one-time shallow clone of a public HTTPS repository
//! (`clone_repository`). The repository URL check limits the clone URL only,
//! not network reach: the repository's `composer.json` can declare its own
//! repositories (even with `secure-http: false`), names are not resolved, and
//! one HTTPS redirect is followed. Network policy on the runtime container is
//! out of scope here. The repository's own code also runs: `key:generate`
//! and `storage:link` boot its service providers.
//!
//! The installed `.env` deliberately sets `SESSION_DRIVER=file`,
//! `CACHE_STORE=file` and `QUEUE_CONNECTION=sync`: the skeleton's `database`
//! drivers need tables that only a migration creates, and the install never
//! runs one. The owner switches to the database drivers after the first
//! migration.
//!
//! Joomla is no Composer project: its full package is downloaded from the
//! project's own release server (the host is fixed here; `pinned_download`
//! follows no redirect, caps size and time, and writes a 0600 file in the
//! engine's state) and must hash to the SHA-256 the panel sent from its image
//! catalog before a byte is unpacked. The package is
//! unpacked with `tar_extract` (nothing can land outside the staging
//! directory) straight into the docroot, the tree passes to the site's UID,
//! and Joomla's CLI installer runs from a fixed `php -r` script that builds its
//! options from environment variables, so neither password is in any argv.
//! The CLI removes `installation/` itself; the engine removes it if it is
//! left, and reads the version from Joomla's manifest without running PHP.
//! Nextcloud is not a Composer project: see `nextcloud.rs` for its pinned
//! archive, its data directory beside the site and its `occ` install.
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
    db_restore::{ContainerName, DatabaseName, RestoreRequestError},
    error::ErrorCode,
    filesystem::ManagedRoot,
    host_name::is_dns_name_or_ipv4,
    mutation::preflight,
    pinned_download,
    process::{
        self, CancellationToken, ProcessLimits, ProcessOutput, ProcessRequest, ProcessRunError,
    },
    site::{Domain, SiteRelativePath, TrustedRoot},
    tar_extract::{self, Limits},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        resource_lock,
        state::{self, TransactionStatus},
    },
    wordpress_install::{validate_bounded, validate_email},
};

mod nextcloud;

pub const OPERATION: &str = "application.install";

/// Where the managed Composer lives inside a runtime container.
const CONTAINER_COMPOSER: &str = "/opt/wcp-tools/composer/current/composer.phar";
const COMPOSER_HOME: &str = "/tmp/wcp-composer";
const COMPOSER_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SETUP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_ROOT_BYTES: usize = 4096;
const MAX_REPOSITORY_URL_BYTES: usize = 2048;
/// The environment of `git clone`: no prompt, no user or system config (so no
/// credential helper, `insteadOf` or proxy from the image).
const GIT_ENV: [&str; 3] = [
    "GIT_TERMINAL_PROMPT=0",
    "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_CONFIG_NOSYSTEM=1",
];
const MIN_ADMIN_PASSWORD_BYTES: usize = 12;
const MAX_ADMIN_PASSWORD_BYTES: usize = 256;
/// The environment variable that carries the administrator's password into
/// the container; fixed text, never built from input.
const PASSWORD_ENV: &str = "STATAMIC_ADMIN_PASSWORD";
const CRAFT_PASSWORD_ENV: &str = "CRAFT_ADMIN_PASSWORD";
/// Drush 13 supports Drupal 10.2 and later, so every Drupal 11.
const DRUSH_PACKAGE: &str = "drush/drush:^13";
/// Drush reads a command's options from `DRUSH_COMMAND_<NAME>_OPTIONS_<OPTION>`
/// (consolidation/config's `EnvConfig`), so neither secret is an argument.
const DRUPAL_DB_URL_ENV: &str = "DRUSH_COMMAND_SITE_INSTALL_OPTIONS_DB_URL";
const DRUPAL_PASSWORD_ENV: &str = "DRUSH_COMMAND_SITE_INSTALL_OPTIONS_ACCOUNT_PASS";
/// The administrator every installed application starts with.
const ADMIN_USER: &str = "admin";
const MIN_DB_PASSWORD_BYTES: usize = 12;
const MAX_DB_PASSWORD_BYTES: usize = 128;
/// `$1` is the administrator's address (a positional argument), the password
/// comes from the environment.
const MAKE_USER_SCRIPT: &str = "exec php please make:user \"$1\" --super --password=\"$STATAMIC_ADMIN_PASSWORD\" --no-interaction";
/// Craft takes its first user's password only as an option and reads no
/// environment variable for it: the shell inside the container expands it, so
/// the host's argv has none (the PHP process's own argv, inside the pool
/// container, shows it for the few seconds the install runs). `$1` is the
/// address, `$2` the site's domain.
const CRAFT_INSTALL_SCRIPT: &str = "exec php craft install/craft --email=\"$1\" --username=admin --password=\"$CRAFT_ADMIN_PASSWORD\" --site-name=\"$2\" --site-url=\"https://$2\" --language=en-US --interactive=0";
/// Joomla's CLI installer takes every value as an option and the passwords
/// only so. This fixed script (`php -r`, run in the docroot) builds that argv
/// inside PHP from the environment, so the only argv any process shows is this
/// text. `getStringFromOption` reads `$_SERVER['argv']`, Symfony's input too.
const JOOMLA_INSTALL_SCRIPT: &str = "$e = static fn (string $k): string => (string) getenv($k); $_SERVER['argv'] = $argv = ['installation/joomla.php', 'install', '--no-interaction', '--site-name=' . $e('JOOMLA_SITE_NAME'), '--admin-user=Administrator', '--admin-username=admin', '--admin-password=' . $e('JOOMLA_ADMIN_PASSWORD'), '--admin-email=' . $e('JOOMLA_ADMIN_EMAIL'), '--db-type=' . $e('JOOMLA_DB_TYPE'), '--db-host=' . $e('JOOMLA_DB_HOST'), '--db-user=' . $e('JOOMLA_DB_USER'), '--db-pass=' . $e('JOOMLA_DB_PASSWORD'), '--db-name=' . $e('JOOMLA_DB_NAME'), '--db-encryption=0']; $_SERVER['argc'] = $argc = count($argv); require 'installation/joomla.php';";
/// Joomla's full package is 28 MiB.
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_ARCHIVE_URL_BYTES: usize = 512;
/// Joomla 6's full package holds about 13 400 entries and 90 MiB.
const ARCHIVE_LIMITS: Limits = Limits {
    max_entries: 50_000,
    max_file_bytes: 512 * 1024 * 1024,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Application {
    Statamic,
    Craft,
    Typo3,
    Laravel,
    Joomla,
    Nextcloud,
    Drupal,
}

impl Application {
    const fn name(self) -> &'static str {
        match self {
            Self::Statamic => "statamic",
            Self::Craft => "craft",
            Self::Typo3 => "typo3",
            Self::Laravel => "laravel",
            Self::Joomla => "joomla",
            Self::Nextcloud => "nextcloud",
            Self::Drupal => "drupal",
        }
    }
    const fn package(self) -> &'static str {
        match self {
            Self::Statamic => "statamic/statamic",
            // Craft 6 is not supported: the major is pinned here.
            Self::Craft => "craftcms/craft:^5",
            Self::Typo3 => "typo3/cms-base-distribution:^14",
            Self::Laravel => "laravel/laravel",
            // Never a Composer project: `unpack_archive`.
            Self::Joomla => "",
            // Not a Composer package: installed from its archive.
            Self::Nextcloud => "",
            // Drupal 12 is not supported: the major is pinned here.
            Self::Drupal => "drupal/recommended-project:^11",
        }
    }
    /// The directory the web server serves, below the project root.
    const fn docroot(self) -> &'static str {
        match self {
            Self::Statamic | Self::Typo3 | Self::Laravel | Self::Joomla | Self::Nextcloud => {
                "public"
            }
            Self::Craft | Self::Drupal => "web",
        }
    }
    const fn admin_path(self) -> &'static str {
        match self {
            Self::Statamic => "/cp",
            Self::Craft => "/admin",
            Self::Typo3 => "/typo3",
            Self::Laravel => "/",
            Self::Joomla => "/administrator",
            Self::Nextcloud => "/login",
            Self::Drupal => "/user/login",
        }
    }
    /// The Composer package whose locked version is the application's.
    const fn version_package(self) -> &'static str {
        match self {
            Self::Statamic => "statamic/cms",
            Self::Craft => "craftcms/cms",
            Self::Typo3 => "typo3/cms-core",
            Self::Laravel => "laravel/framework",
            // Read from Joomla's manifest: `joomla_version`.
            Self::Joomla => "",
            // Read from `version.php` instead (`nextcloud::version`).
            Self::Nextcloud => "",
            Self::Drupal => "drupal/core",
        }
    }
    /// Whether the application needs a database the panel provisioned.
    const fn needs_database(self) -> bool {
        !matches!(self, Self::Statamic)
    }
    /// Whether the install creates an administrator account.
    const fn has_admin(self) -> bool {
        !matches!(self, Self::Laravel)
    }
    /// The hosts an application's archive may come from; empty for one that
    /// Composer installs. Exactly then the plan carries an `archive`.
    const fn archive_hosts(self) -> &'static [&'static str] {
        match self {
            Self::Joomla => &["update.joomla.org"],
            Self::Nextcloud => &["download.nextcloud.com"],
            _ => &[],
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
    admin_email: Option<String>,
    admin_password: Option<String>,
    #[serde(default)]
    database: Option<DatabasePlan>,
    #[serde(default)]
    source: Source,
    #[serde(default)]
    archive: Option<ArchivePlan>,
}

/// The pinned archive the panel took from its image catalog.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArchivePlan {
    url: String,
    sha256: String,
}

/// `https://<one of hosts>/<path>`: no port, userinfo, query, fragment,
/// percent-encoding, backslash, empty, `.` or `..` segment, space or control
/// byte, at most 512 bytes. The host is compared exactly (lowercase).
fn archive_url_ok(url: &str, hosts: &[&str]) -> bool {
    let Some((host, path)) = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
    else {
        return false;
    };
    url.len() <= MAX_ARCHIVE_URL_BYTES
        && url
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'\\' | b'?' | b'#' | b'@' | b'%'))
        && hosts.contains(&host)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Where the application's files come from: Composer's project template, or
/// a one-time shallow clone of a public HTTPS repository (Laravel only).
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum Source {
    #[default]
    Fresh,
    Git {
        url: String,
    },
}

/// A public HTTPS repository on a DNS name: no userinfo, port, query or
/// fragment, no IP literal of any form, no name that only resolves locally
/// (`localhost`, `.local`, `.internal`), no control, space, backslash or
/// non-ASCII byte, at most 2048 bytes. A speed bump, not a network boundary:
/// it limits the clone URL only. Names are not resolved (a public name that
/// resolves to a private address passes), git follows one HTTPS redirect, and
/// the repository's `composer.json` can name other repositories (even with
/// `secure-http: false`). Network policy on the container is out of scope.
fn validate_repository_url(url: &str) -> Result<(), RequestError> {
    if url.len() > MAX_REPOSITORY_URL_BYTES
        || !url
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'\\' | b'?' | b'#' | b'@'))
    {
        return Err(RequestError);
    }
    let (host, path) = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
        .ok_or(RequestError)?;
    let lower = host.to_ascii_lowercase();
    // A last label that starts with a letter rules out every numeric, hex and
    // octal address form (`127.1`, `0x7f000001`, `0177.0.0.1`).
    let tld_ok = lower
        .rsplit_once('.')
        .is_some_and(|(_, tld)| tld.starts_with(|c: char| c.is_ascii_alphabetic()));
    let local = [".localhost", ".local", ".internal"]
        .iter()
        .any(|suffix| lower.ends_with(suffix));
    if path.is_empty() || !is_dns_name_or_ipv4(host) || !tld_ok || local {
        return Err(RequestError);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
enum DatabaseDriver {
    Mariadb,
    Postgres,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DatabasePlan {
    driver: DatabaseDriver,
    host: String,
    port: u16,
    name: String,
    user: String,
    password: String,
}

/// The database the panel created for the site; never created or dropped here.
struct Database {
    driver: DatabaseDriver,
    host: ContainerName,
    port: u16,
    name: DatabaseName,
    user: DatabaseName,
    password: String,
}

impl Database {
    fn parse(plan: DatabasePlan) -> Result<Self, RequestError> {
        // The password also lands in a `.env` file, where quotes, `#`, `$`
        // and spaces mean something: only plain characters are accepted.
        if plan.port == 0
            || !(MIN_DB_PASSWORD_BYTES..=MAX_DB_PASSWORD_BYTES).contains(&plan.password.len())
            || !plan
                .password
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(RequestError);
        }
        Ok(Self {
            driver: plan.driver,
            host: ContainerName::parse(&plan.host)
                .map_err(|_: RestoreRequestError| RequestError)?,
            port: plan.port,
            name: DatabaseName::parse(&plan.name).map_err(|_: RestoreRequestError| RequestError)?,
            user: DatabaseName::parse(&plan.user).map_err(|_: RestoreRequestError| RequestError)?,
            password: plan.password,
        })
    }
}

/// TYPO3 refuses an administrator password without a special character; the
/// set is one that is safe in an environment variable.
fn typo3_password_ok(password: &str) -> bool {
    password.bytes().any(|b| b.is_ascii_lowercase())
        && password.bytes().any(|b| b.is_ascii_uppercase())
        && password.bytes().any(|b| b.is_ascii_digit())
        && password.bytes().any(|b| b"-_.!@%^*+=~".contains(&b))
}

pub struct Request {
    container: ContainerName,
    project_root: PathBuf,
    uid: u32,
    gid: u32,
    domain: Domain,
    application: Application,
    admin_email: Option<String>,
    admin_password: Option<String>,
    database: Option<Database>,
    source: Source,
    archive: Option<ArchivePlan>,
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
        // The administrator is given exactly when the application has one.
        if plan.application.has_admin() != plan.admin_email.is_some()
            || plan.application.has_admin() != plan.admin_password.is_some()
        {
            return Err(RequestError);
        }
        if let (Some(email), Some(password)) = (&plan.admin_email, &plan.admin_password) {
            validate_email(email).map_err(|_| RequestError)?;
            // The address becomes a command-line argument: never an option.
            if email.starts_with('-') {
                return Err(RequestError);
            }
            validate_bounded(password, MAX_ADMIN_PASSWORD_BYTES).map_err(|_| RequestError)?;
            if password.len() < MIN_ADMIN_PASSWORD_BYTES
                || password.bytes().any(|b| matches!(b, b'\n' | b'\r'))
            {
                return Err(RequestError);
            }
            if plan.application == Application::Typo3 && !typo3_password_ok(password) {
                return Err(RequestError);
            }
        }
        // The plan names a database exactly when the application needs one.
        if plan.application.needs_database() != plan.database.is_some() {
            return Err(RequestError);
        }
        let database = plan.database.map(Database::parse).transpose()?;
        if let Source::Git { url } = &plan.source {
            if plan.application != Application::Laravel {
                return Err(RequestError);
            }
            validate_repository_url(url)?;
        }
        let hosts = plan.application.archive_hosts();
        let archive = match plan.archive {
            Some(archive)
                if archive_url_ok(&archive.url, hosts)
                    && pinned_download::is_sha256_hex(&archive.sha256) =>
            {
                Some(archive)
            }
            None if hosts.is_empty() => None,
            _ => return Err(RequestError),
        };
        // Joomla's installer takes a host and no port: only the default one.
        if plan.application == Application::Joomla
            && database.as_ref().is_some_and(|db| {
                db.port
                    != match db.driver {
                        DatabaseDriver::Mariadb => 3306,
                        DatabaseDriver::Postgres => 5432,
                    }
            })
        {
            return Err(RequestError);
        }
        // Nextcloud: exactly its release file names, on top of the host.
        if plan.application == Application::Nextcloud
            && !archive
                .as_ref()
                .is_some_and(|archive| nextcloud::archive_url_ok(&archive.url))
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
            database,
            source: plan.source,
            archive,
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

    /// The administrator's address and password; `Unverified` when the
    /// application has none (parsing guarantees them otherwise).
    fn admin(&self) -> Result<(&str, &str), Error> {
        match (&self.admin_email, &self.admin_password) {
            (Some(email), Some(password)) => Ok((email, password)),
            _ => Err(Error::Unverified),
        }
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
    /// Streams a pinned archive (`engine::fetch::fetch_reader_bounded`).
    pub fetch: pinned_download::Fetch<'a>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Preflight(preflight::Error),
    ReplayInProgress,
    Run(ProcessRunError),
    RootUnavailable,
    TargetNotEmpty,
    /// The site's document root is another directory than the application's.
    DocrootMismatch(&'static str),
    ResourceBusy,
    ComposerFailed(ErrorCode),
    CloneFailed(ErrorCode),
    /// The cloned repository is not a Laravel project.
    NotLaravel,
    ArchiveFetch(ErrorCode),
    /// The downloaded archive does not hash to its pinned SHA-256.
    ArchiveDigest,
    /// The archive holds an entry `tar_extract` refuses, or is corrupt.
    ArchiveUnsafe,
    SetupFailed(ErrorCode),
    /// The installed application's version could not be read back.
    Unverified,
    /// Nextcloud's data directory beside the site already holds something.
    DataDirNotEmpty,
    /// The verified archive does not unpack to the expected tree.
    ArchiveInvalid,
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
            Self::DocrootMismatch(wanted) => (
                ErrorCode::InvalidInput,
                format!(
                    "this application needs the site's document root to be `{wanted}/`; create the site with that root"
                ),
            ),
            Self::ComposerFailed(code) => (
                *code,
                "Composer could not create the project (network, package or PHP conflict)".into(),
            ),
            Self::CloneFailed(code) => (
                *code,
                "the Git repository could not be cloned (not public, not found or network)".into(),
            ),
            Self::NotLaravel => (
                ErrorCode::InvalidInput,
                "the repository is not a Laravel project (it needs composer.json, .env.example, public/ and laravel/framework)".into(),
            ),
            Self::ArchiveFetch(code) => (
                *code,
                "the application archive could not be downloaded from its official server".into(),
            ),
            Self::ArchiveDigest => (
                ErrorCode::ArtifactVerificationFailed,
                "the downloaded archive does not match its pinned SHA-256; nothing was unpacked".into(),
            ),
            Self::ArchiveUnsafe => (
                ErrorCode::ArtifactVerificationFailed,
                "the archive holds an entry that cannot be unpacked safely".into(),
            ),
            Self::SetupFailed(code) => (*code, "the application setup failed".into()),
            Self::Unverified => (
                ErrorCode::Internal,
                "the installed version could not be read back".into(),
            ),
            Self::DataDirNotEmpty => (
                ErrorCode::Conflict,
                "the data directory beside the site already exists and is not an empty directory; it is never reused or removed by an install".into(),
            ),
            Self::ArchiveInvalid => (
                ErrorCode::ArtifactVerificationFailed,
                "the archive does not unpack to the expected application tree".into(),
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

    match install(ctx, content_root, &scope, req, cancel) {
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

fn install(
    ctx: &Context<'_>,
    content_root: &TrustedRoot,
    scope: &ManagedRoot,
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
    // Nextcloud's data directory beside the site, refused when it holds
    // anything, before the site changes.
    let data = match req.application {
        Application::Nextcloud => Some(nextcloud::prepare_data_dir(content_root, req)?),
        _ => None,
    };
    // `site.create` gives the site's UID only the docroot; a Composer
    // application writes `vendor/`, `storage/` and its staging directory
    // beside it, so the project root itself passes to the site's UID. Never
    // recursive, and only after the root was proven empty.
    if let Err(error) = root.chown_self(req.uid, req.gid) {
        if let Some((content, data)) = &data {
            nextcloud::undo_data_dir(content, data);
        }
        return Err(Error::Io(error));
    }

    let staging = format!(".wcp-install-{}", req.request_id);
    // The root was proven empty but for the docroot and its `.user.ini`:
    // whatever else appears afterwards is the install's own.
    let before = docroot_names(&root, docroot)?;
    let data_dir = data.as_ref().map(|(_, data)| data);
    match run_install(
        ctx, req, scope, &root, root_str, docroot, &staging, data_dir, cancel,
    ) {
        Ok(result) => {
            let _ = root.remove_dir_all(&rel(&staging)?);
            Ok(result)
        }
        Err(error) => {
            undo(&root, docroot, &before);
            if let Some((content, data)) = &data {
                nextcloud::undo_data_dir(content, data);
            }
            Err(error)
        }
    }
}

/// The project root may hold the docroot directory with a `.user.ini` and
/// nothing else.
fn require_empty(root: &ManagedRoot, docroot: &str) -> Result<(), Error> {
    for entry in root.child_entries_bounded(64).map_err(Error::Io)? {
        if entry.is_dir && entry.name != docroot {
            if let Some(other) = ["public", "web"]
                .into_iter()
                .find(|name| entry.name == *name && *name != docroot)
            {
                // An empty or `.user.ini`-only directory of the other
                // conventional name is a site made with the wrong root.
                let inner = root
                    .open_child_dir_nofollow(&rel(other)?)
                    .map_err(Error::Io)?;
                let bare = inner
                    .child_entries_bounded(64)
                    .map_err(Error::Io)?
                    .iter()
                    .all(|child| child.name == ".user.ini" && !child.is_dir);
                if bare && root.child_entries_bounded(64).map_err(Error::Io)?.len() == 1 {
                    return Err(Error::DocrootMismatch(match docroot {
                        "web" => "web",
                        _ => "public",
                    }));
                }
            }
        }
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
    scope: &ManagedRoot,
    root: &ManagedRoot,
    root_str: &str,
    docroot: &str,
    staging: &str,
    data: Option<&nextcloud::DataDir>,
    cancel: &CancellationToken,
) -> Result<InstallResult, Error> {
    match &req.source {
        Source::Fresh if req.application == Application::Joomla => {
            unpack_archive(ctx, req, root, staging, docroot)?
        }
        Source::Fresh if req.application == Application::Nextcloud => {
            nextcloud::stage(ctx, req, scope, root, staging)?
        }
        Source::Fresh => composer(
            ctx,
            req,
            root_str,
            &create_project_args(req.application, staging),
            cancel,
        )?,
        Source::Git { url } => clone_repository(ctx, req, root, root_str, staging, url, cancel)?,
    }
    if req.application == Application::Drupal {
        // Drush is the project's own dependency, not a global tool.
        composer(
            ctx,
            req,
            &format!("{root_str}/{staging}"),
            &[
                "php",
                CONTAINER_COMPOSER,
                "require",
                DRUSH_PACKAGE,
                "--no-interaction",
                "--no-ansi",
                "--no-progress",
            ],
            cancel,
        )?;
    }

    move_into_place(root, staging, docroot)?;
    let output = match req.application {
        Application::Statamic => {
            let (email, password) = req.admin()?;
            set_env_file(
                root,
                req,
                &[
                    ("APP_URL", &format!("https://{}", req.domain.as_str())),
                    ("APP_ENV", "production"),
                    ("APP_DEBUG", "false"),
                ],
            )?;
            exec(
                ctx,
                req,
                root_str,
                &[],
                &[(PASSWORD_ENV, password)],
                &["sh", "-c", MAKE_USER_SCRIPT, "sh", email],
                SETUP_TIMEOUT,
                cancel,
            )?
        }
        Application::Craft => setup_craft(ctx, req, root, root_str, cancel)?,
        Application::Typo3 => setup_typo3(ctx, req, root_str, cancel)?,
        Application::Laravel => setup_laravel(ctx, req, root, root_str, cancel)?,
        Application::Joomla => setup_joomla(ctx, req, root_str, docroot, cancel)?,
        Application::Nextcloud => nextcloud::setup(
            ctx,
            req,
            &format!("{root_str}/{docroot}"),
            data.ok_or(Error::Unverified)?,
            cancel,
        )?,
        Application::Drupal => setup_drupal(ctx, req, root, root_str, cancel)?,
    };
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::SetupFailed(code));
    }

    let version = match req.application {
        Application::Joomla => finish_joomla(root, root_str, docroot)?,
        Application::Nextcloud => nextcloud::version(root, docroot)?,
        _ => locked_version(root, req.application)?,
    };
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

/// Runs the managed Composer as the site's UID in `cwd`.
fn composer(
    ctx: &Context<'_>,
    req: &Request,
    cwd: &str,
    args: &[&str],
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let home = format!("COMPOSER_HOME={COMPOSER_HOME}");
    let cache = format!("COMPOSER_CACHE_DIR={COMPOSER_HOME}/cache");
    let output = exec(
        ctx,
        req,
        cwd,
        &[&home, &cache, "COMPOSER_NO_INTERACTION=1"],
        &[],
        args,
        COMPOSER_TIMEOUT,
        cancel,
    )?;
    match process::error_code(&output.termination) {
        Some(code) => Err(Error::ComposerFailed(code)),
        None => Ok(()),
    }
}

/// Shallow-clones the repository into the staging directory as the site's
/// UID, HTTPS only (a redirect or submodule to another protocol fails), then
/// makes it a Laravel project ready to move into place: `.git`, a committed
/// `.env`, `vendor/` and `bootstrap/cache/*.php` (a cached config would
/// override the `.env` written here) are dropped, `.env` comes from
/// `.env.example`, and `composer install` runs without scripts or plugins.
/// That covers the installer's own steps only: the repository's code still
/// runs when `key:generate` boots its providers. The URL is in no error text.
fn clone_repository(
    ctx: &Context<'_>,
    req: &Request,
    root: &ManagedRoot,
    root_str: &str,
    staging: &str,
    url: &str,
    cancel: &CancellationToken,
) -> Result<(), Error> {
    let output = exec(
        ctx,
        req,
        root_str,
        &GIT_ENV,
        &[],
        &[
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "clone",
            "--depth",
            "1",
            "--no-tags",
            "--no-recurse-submodules",
            "--",
            url,
            staging,
        ],
        COMPOSER_TIMEOUT,
        cancel,
    )?;
    if let Some(code) = process::error_code(&output.termination) {
        return Err(Error::CloneFailed(code));
    }
    let staged = root
        .open_child_dir_nofollow(&rel(staging)?)
        .map_err(Error::Io)?;
    for name in [".git", ".env", "vendor"] {
        let path = rel(name)?;
        match staged.symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => staged.remove_dir_all(&path),
            Ok(_) => staged.remove_file(&path),
            Err(_) => Ok(()),
        }
        .map_err(Error::Io)?;
    }
    drop_cached_php(&staged)?;
    let is = |name: &str, dir: bool| {
        rel(name).is_ok_and(|path| {
            staged
                .symlink_metadata(&path)
                .is_ok_and(|meta| meta.is_dir() == dir && !meta.is_symlink())
        })
    };
    if !is("composer.json", false) || !is(".env.example", false) || !is("public", true) {
        return Err(Error::NotLaravel);
    }
    let example = staged
        .read_to_string(&rel(".env.example")?)
        .map_err(|_| Error::NotLaravel)?;
    staged
        .write_atomic(&rel(".env")?, example.as_bytes())
        .map_err(Error::Io)?;
    composer(
        ctx,
        req,
        &format!("{root_str}/{staging}"),
        &[
            "php",
            CONTAINER_COMPOSER,
            "install",
            "--no-dev",
            "--no-interaction",
            "--prefer-dist",
            "--no-scripts",
            "--no-plugins",
            "--no-ansi",
            "--no-progress",
        ],
        cancel,
    )?;
    locked_version(&staged, Application::Laravel).map_err(|_| Error::NotLaravel)?;
    Ok(())
}

/// Removes the `*.php` files of a committed `bootstrap/cache/`, keeping the
/// rest (`.gitignore`). A `bootstrap` or `cache` that is not a plain
/// directory is not a Laravel project.
fn drop_cached_php(staged: &ManagedRoot) -> Result<(), Error> {
    let open = |dir: &ManagedRoot, name: &str| match dir.open_child_dir_nofollow(&rel(name)?) {
        Ok(inner) => Ok(Some(inner)),
        Err(_) if dir.symlink_metadata(&rel(name)?).is_err() => Ok(None),
        Err(_) => Err(Error::NotLaravel),
    };
    let Some(bootstrap) = open(staged, "bootstrap")? else {
        return Ok(());
    };
    let Some(cache) = open(&bootstrap, "cache")? else {
        return Ok(());
    };
    for entry in cache.child_entries().map_err(Error::Io)? {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        if name.ends_with(".php") {
            let path = rel(name)?;
            if entry.is_dir {
                cache.remove_dir_all(&path)
            } else {
                cache.remove_file(&path)
            }
            .map_err(Error::Io)?;
        }
    }
    Ok(())
}

/// Laravel's `post-create-project-cmd` runs `artisan migrate` against a
/// default sqlite file; the install never runs migrations, so its scripts are
/// skipped (and `.env` is made from `.env.example` in `setup_laravel`).
fn create_project_args(application: Application, staging: &str) -> Vec<&str> {
    let mut args = vec![
        "php",
        CONTAINER_COMPOSER,
        "create-project",
        application.package(),
        staging,
        "--no-interaction",
        "--no-ansi",
        "--no-progress",
    ];
    if application == Application::Laravel {
        args.push("--no-scripts");
    }
    args
}

/// Moves each top-level entry of the staging directory into the project root;
/// the docroot's entries go into the docroot that is already there. Nothing
/// is overwritten: a name that exists is a conflict.
fn move_into_place(root: &ManagedRoot, staging: &str, docroot: &str) -> Result<(), Error> {
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
            }
        } else {
            let target = rel(&name)?;
            if root.symlink_metadata(&target).is_ok() {
                return Err(Error::TargetNotEmpty);
            }
            root.rename(&rel(format!("{staging}/{name}"))?, &target)
                .map_err(Error::Io)?;
        }
    }
    Ok(())
}

/// Sets a fixed key set in the application's `.env`, written through the
/// managed root and kept readable by the site's UID.
fn set_env_file(root: &ManagedRoot, req: &Request, updates: &[(&str, &str)]) -> Result<(), Error> {
    let env = rel(".env")?;
    let original = root.read_to_string(&env).map_err(Error::Io)?;
    let updated = crate::util::set_env_lines(&original, updates).map_err(Error::Io)?;
    root.write_atomic(&env, updated.as_bytes())
        .map_err(Error::Io)?;
    root.chown(&env, req.uid, req.gid).map_err(Error::Io)?;
    root.set_mode(&env, 0o640).map_err(Error::Io)
}

/// Craft: the database and the site's address go into `.env` (Craft reads
/// `CRAFT_*` from it), `setup/keys` generates the application key, and
/// `install/craft` creates the tables and the first user.
fn setup_craft(
    ctx: &Context<'_>,
    req: &Request,
    root: &ManagedRoot,
    root_str: &str,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let db = req.database.as_ref().ok_or(Error::Unverified)?;
    let driver = match db.driver {
        DatabaseDriver::Mariadb => "mysql",
        DatabaseDriver::Postgres => "pgsql",
    };
    let port = db.port.to_string();
    set_env_file(
        root,
        req,
        &[
            ("CRAFT_ENVIRONMENT", "production"),
            ("CRAFT_DEV_MODE", "false"),
            ("CRAFT_DB_DRIVER", driver),
            ("CRAFT_DB_SERVER", db.host.as_str()),
            ("CRAFT_DB_PORT", &port),
            ("CRAFT_DB_DATABASE", db.name.as_str()),
            ("CRAFT_DB_USER", db.user.as_str()),
            ("CRAFT_DB_PASSWORD", &db.password),
            (
                "PRIMARY_SITE_URL",
                &format!("https://{}", req.domain.as_str()),
            ),
        ],
    )?;
    let keys = exec(
        ctx,
        req,
        root_str,
        &[],
        &[],
        &["php", "craft", "setup/keys", "--interactive=0"],
        SETUP_TIMEOUT,
        cancel,
    )?;
    if process::error_code(&keys.termination).is_some() {
        return Ok(keys);
    }
    let (email, password) = req.admin()?;
    exec(
        ctx,
        req,
        root_str,
        &[],
        &[(CRAFT_PASSWORD_ENV, password)],
        &[
            "sh",
            "-c",
            CRAFT_INSTALL_SCRIPT,
            "sh",
            email,
            req.domain.as_str(),
        ],
        SETUP_TIMEOUT,
        cancel,
    )
}

/// Laravel: the database and the site's address go into `.env` (the password
/// only there, never in an argument; session, cache and queue are
/// `file`/`file`/`sync`), then `key:generate` sets `APP_KEY` and
/// `storage:link` links `public/storage`.
fn setup_laravel(
    ctx: &Context<'_>,
    req: &Request,
    root: &ManagedRoot,
    root_str: &str,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let db = req.database.as_ref().ok_or(Error::Unverified)?;
    let connection = match db.driver {
        DatabaseDriver::Mariadb => "mariadb",
        DatabaseDriver::Postgres => "pgsql",
    };
    let port = db.port.to_string();
    // `--no-scripts` also skipped the script that copies `.env.example`.
    if root.symlink_metadata(&rel(".env")?).is_err() {
        let example = root
            .read_to_string(&rel(".env.example")?)
            .map_err(Error::Io)?;
        root.write_atomic(&rel(".env")?, example.as_bytes())
            .map_err(Error::Io)?;
    }
    set_env_file(
        root,
        req,
        &[
            ("APP_URL", &format!("https://{}", req.domain.as_str())),
            ("DB_CONNECTION", connection),
            ("DB_HOST", db.host.as_str()),
            ("DB_PORT", &port),
            ("DB_DATABASE", db.name.as_str()),
            ("DB_USERNAME", db.user.as_str()),
            ("DB_PASSWORD", &db.password),
            // The skeleton defaults to the `database` drivers, whose tables
            // only a migration creates; the install runs none.
            ("SESSION_DRIVER", "file"),
            ("CACHE_STORE", "file"),
            ("QUEUE_CONNECTION", "sync"),
        ],
    )?;
    let key = exec(
        ctx,
        req,
        root_str,
        &[],
        &[],
        &[
            "php",
            "artisan",
            "key:generate",
            "--force",
            "--no-interaction",
        ],
        SETUP_TIMEOUT,
        cancel,
    )?;
    if process::error_code(&key.termination).is_some() {
        return Ok(key);
    }
    exec(
        ctx,
        req,
        root_str,
        &[],
        &[],
        &["php", "artisan", "storage:link", "--no-interaction"],
        SETUP_TIMEOUT,
        cancel,
    )
}

/// Downloads the pinned archive, checks its digest before anything is
/// written, unpacks it into `<staging>/<docroot>` (so `move_into_place` puts
/// it into the docroot) and passes the staged tree to the site's UID.
fn unpack_archive(
    ctx: &Context<'_>,
    req: &Request,
    root: &ManagedRoot,
    staging: &str,
    docroot: &str,
) -> Result<(), Error> {
    let archive = req.archive.as_ref().ok_or(Error::Unverified)?;
    // Into the engine's own state (root only), never the site's tree.
    let downloads = rel("application-install/downloads")?;
    ctx.engine_state
        .create_dir_all(&downloads)
        .map_err(Error::Io)?;
    let dir = ctx
        .engine_state
        .open_managed_dir(&downloads)
        .map_err(Error::Io)?;
    let name = rel(format!("{}.tar.gz", req.request_id))?;
    let file = pinned_download::download(
        ctx.fetch,
        &archive.url,
        &archive.sha256,
        MAX_ARCHIVE_BYTES,
        ARCHIVE_TIMEOUT,
        &dir,
        &name,
    )
    .map_err(|error| match error {
        pinned_download::Error::DigestMismatch => Error::ArchiveDigest,
        pinned_download::Error::Fetch(crate::engine::fetch::Error::Timeout) => {
            Error::ArchiveFetch(ErrorCode::Timeout)
        }
        pinned_download::Error::Fetch(_) | pinned_download::Error::Io(_) => {
            Error::ArchiveFetch(ErrorCode::ArtifactFetchFailed)
        }
    })?;
    let unpacked = unpack_into(root, req, staging, docroot, file);
    let _ = dir.remove_file(&name);
    unpacked
}

fn unpack_into(
    root: &ManagedRoot,
    req: &Request,
    staging: &str,
    docroot: &str,
    file: std::fs::File,
) -> Result<(), Error> {
    let target = rel(format!("{staging}/{docroot}"))?;
    root.create_dir_all(&target).map_err(Error::Io)?;
    let dest = root.open_managed_dir(&target).map_err(Error::Io)?;
    tar_extract::extract(
        flate2::read::GzDecoder::new(std::io::BufReader::new(file)),
        &dest,
        ARCHIVE_LIMITS,
    )
    .map_err(|_| Error::ArchiveUnsafe)?;
    let staged = root
        .open_child_dir_nofollow(&rel(staging)?)
        .map_err(Error::Io)?;
    crate::permissions::execute::repair_open_directory(
        &staged.try_clone_fd().map_err(Error::Io)?,
        req.uid,
        req.gid,
        &[],
    )
    .map_err(Error::Io)?;
    Ok(())
}

/// Joomla: the CLI installer in the docroot, every value from the
/// environment (the passwords as `-e NAME` only, see `exec`).
fn setup_joomla(
    ctx: &Context<'_>,
    req: &Request,
    root_str: &str,
    docroot: &str,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let db = req.database.as_ref().ok_or(Error::Unverified)?;
    let (email, password) = req.admin()?;
    let db_type = match db.driver {
        DatabaseDriver::Mariadb => "mysqli",
        DatabaseDriver::Postgres => "pgsql",
    };
    let env = [
        format!("JOOMLA_SITE_NAME={}", req.domain.as_str()),
        format!("JOOMLA_ADMIN_EMAIL={email}"),
        format!("JOOMLA_DB_TYPE={db_type}"),
        format!("JOOMLA_DB_HOST={}", db.host.as_str()),
        format!("JOOMLA_DB_USER={}", db.user.as_str()),
        format!("JOOMLA_DB_NAME={}", db.name.as_str()),
    ];
    let env: Vec<&str> = env.iter().map(String::as_str).collect();
    exec(
        ctx,
        req,
        &format!("{root_str}/{docroot}"),
        &env,
        &[
            ("JOOMLA_ADMIN_PASSWORD", password),
            ("JOOMLA_DB_PASSWORD", &db.password),
        ],
        &["php", "-r", JOOMLA_INSTALL_SCRIPT],
        SETUP_TIMEOUT,
        cancel,
    )
}

/// After a successful CLI run: no `installation/` left, a regular
/// `configuration.php` readable only by the site's UID and group, and the
/// version from Joomla's manifest (read, never executed).
fn finish_joomla(root: &ManagedRoot, root_str: &str, docroot: &str) -> Result<String, Error> {
    let installation = rel(format!("{docroot}/installation"))?;
    if root.symlink_metadata(&installation).is_ok() {
        root.remove_dir_all(&installation).map_err(Error::Io)?;
    }
    let config = rel(format!("{docroot}/configuration.php"))?;
    if !root
        .symlink_metadata(&config)
        .is_ok_and(|meta| meta.is_file())
    {
        return Err(Error::Unverified);
    }
    root.set_mode(&config, 0o640).map_err(Error::Io)?;
    crate::joomla_update::installed_version(Path::new(&format!("{root_str}/{docroot}")))
        .map_err(|_| Error::Unverified)
}

/// Drupal: `settings.php` is made from `default.settings.php` with the site's
/// domain as the only trusted host and the runtime pool's loopback hop as the
/// only trusted reverse proxy, and `files/` exists for the site's UID, before
/// `drush site:install` runs; the installer adds `$databases` and
/// `hash_salt` to it. The database URL and the administrator's password reach
/// Drush only through the environment. Afterwards `settings.php` and
/// `sites/default` are read-only, as Drupal's status report requires.
fn setup_drupal(
    ctx: &Context<'_>,
    req: &Request,
    root: &ManagedRoot,
    root_str: &str,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let db = req.database.as_ref().ok_or(Error::Unverified)?;
    let (email, password) = req.admin()?;
    let default = "web/sites/default";
    let settings = rel(format!("{default}/settings.php"))?;
    let mut text = root
        .read_to_string(&rel(format!("{default}/default.settings.php"))?)
        .map_err(Error::Io)?;
    // A `Domain` is lowercase letters, digits, `-` and `.`: only the dot is
    // special in a pattern.
    text.push_str(&format!(
        "\n$settings['trusted_host_patterns'] = ['^{}$'];\n",
        req.domain.as_str().replace('.', "\\.")
    ));
    // The runtime pool proxies to the site's own FrankenPHP on loopback with
    // `Host: 127.0.0.1:<port>`; the site's host arrives only in
    // `X-Forwarded-Host`. The pool does not trust the ingress, so its
    // `X-Forwarded-Proto` is always `http` and is not trusted here: Drupal
    // sees the scheme as http until the pool forwards the original one.
    text.push_str(concat!(
        "$settings['reverse_proxy'] = TRUE;\n",
        "$settings['reverse_proxy_addresses'] = ['127.0.0.1'];\n",
        "$settings['reverse_proxy_trusted_headers'] = ",
        "\\Symfony\\Component\\HttpFoundation\\Request::HEADER_X_FORWARDED_FOR | ",
        "\\Symfony\\Component\\HttpFoundation\\Request::HEADER_X_FORWARDED_HOST;\n",
        // Drupal checks `trusted_host_patterns` before its reverse-proxy
        // middleware registers the proxy, so the check would see
        // `127.0.0.1`: the proxy is registered here, before that check.
        "\\Symfony\\Component\\HttpFoundation\\Request::setTrustedProxies(",
        "$settings['reverse_proxy_addresses'], $settings['reverse_proxy_trusted_headers']);\n",
    ));
    root.write_atomic(&settings, text.as_bytes())
        .map_err(Error::Io)?;
    root.chown(&settings, req.uid, req.gid).map_err(Error::Io)?;
    root.set_mode(&settings, 0o640).map_err(Error::Io)?;
    let files = rel(format!("{default}/files"))?;
    root.create_dir_all(&files).map_err(Error::Io)?;
    root.chown(&files, req.uid, req.gid).map_err(Error::Io)?;
    root.set_mode(&files, 0o755).map_err(Error::Io)?;

    let scheme = match db.driver {
        DatabaseDriver::Mariadb => "mysql",
        DatabaseDriver::Postgres => "pgsql",
    };
    // The password is `[A-Za-z0-9._-]` (`Database::parse`): nothing in it
    // needs URL encoding.
    let db_url = format!(
        "{scheme}://{}:{}@{}:{}/{}",
        db.user.as_str(),
        db.password,
        db.host.as_str(),
        db.port,
        db.name.as_str()
    );
    let uri = format!("DRUSH_OPTIONS_URI=https://{}", req.domain.as_str());
    let mail = format!("--account-mail={email}");
    let site_mail = format!("--site-mail={email}");
    let site_name = format!("--site-name={}", req.domain.as_str());
    let account = format!("--account-name={ADMIN_USER}");
    let output = exec(
        ctx,
        req,
        root_str,
        &[&uri],
        &[
            (DRUPAL_DB_URL_ENV, &db_url),
            (DRUPAL_PASSWORD_ENV, password),
        ],
        &[
            "php",
            "vendor/bin/drush",
            "site:install",
            "standard",
            "--yes",
            &account,
            &mail,
            &site_mail,
            &site_name,
        ],
        SETUP_TIMEOUT,
        cancel,
    )?;
    if process::error_code(&output.termination).is_none() {
        root.set_mode(&settings, 0o440).map_err(Error::Io)?;
        root.set_mode(&rel(default)?, 0o555).map_err(Error::Io)?;
    }
    Ok(output)
}

/// TYPO3: `typo3 setup` reads everything from the environment, passwords
/// included, so nothing secret is in any argument.
fn setup_typo3(
    ctx: &Context<'_>,
    req: &Request,
    root_str: &str,
    cancel: &CancellationToken,
) -> Result<ProcessOutput, Error> {
    let db = req.database.as_ref().ok_or(Error::Unverified)?;
    let (email, password) = req.admin()?;
    let driver = match db.driver {
        DatabaseDriver::Mariadb => "mysqli",
        DatabaseDriver::Postgres => "pdo_pgsql",
    };
    let env = [
        format!("TYPO3_DB_DRIVER={driver}"),
        format!("TYPO3_DB_HOST={}", db.host.as_str()),
        format!("TYPO3_DB_PORT={}", db.port),
        format!("TYPO3_DB_DBNAME={}", db.name.as_str()),
        format!("TYPO3_DB_USERNAME={}", db.user.as_str()),
        format!("TYPO3_SETUP_ADMIN_EMAIL={email}"),
        format!("TYPO3_SETUP_ADMIN_USERNAME={ADMIN_USER}"),
        format!("TYPO3_SETUP_CREATE_SITE=https://{}/", req.domain.as_str()),
        format!("TYPO3_PROJECT_NAME={}", req.domain.as_str()),
        "TYPO3_SERVER_TYPE=other".to_owned(),
    ];
    let env: Vec<&str> = env.iter().map(String::as_str).collect();
    exec(
        ctx,
        req,
        root_str,
        &env,
        &[
            ("TYPO3_DB_PASSWORD", &db.password),
            ("TYPO3_SETUP_ADMIN_PASSWORD", password),
        ],
        &[
            "php",
            "vendor/bin/typo3",
            "setup",
            "--force",
            "--no-interaction",
        ],
        SETUP_TIMEOUT,
        cancel,
    )
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

/// The names in the docroot before the install started.
fn docroot_names(root: &ManagedRoot, docroot: &str) -> Result<Vec<std::ffi::OsString>, Error> {
    match root.open_child_dir_nofollow(&rel(docroot)?) {
        Ok(inner) => Ok(inner
            .child_entries_bounded(64)
            .map_err(Error::Io)?
            .into_iter()
            .map(|entry| entry.name)
            .collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Removes exactly what this install wrote. The root was empty but for the
/// docroot (with at most `.user.ini`) when it started, so everything else at
/// the top level is the install's, as is anything new inside the docroot.
/// Setup commands write files of their own (`var/`, `config/system/`), which
/// is why this does not rely on a list of what the install moved.
fn undo(root: &ManagedRoot, docroot: &str, before: &[std::ffi::OsString]) {
    let remove = |dir: &ManagedRoot, prefix: &str, name: &std::ffi::OsStr, is_dir: bool| {
        let Some(name) = name.to_str() else { return };
        let Ok(path) = SiteRelativePath::parse(format!("{prefix}{name}")) else {
            return;
        };
        let _ = if is_dir {
            dir.remove_dir_all(&path)
        } else {
            dir.remove_file(&path)
        };
    };
    let Ok(entries) = root.child_entries() else {
        return;
    };
    for entry in entries {
        if entry.name == docroot && entry.is_dir {
            let Ok(path) = SiteRelativePath::parse(docroot) else {
                continue;
            };
            let Ok(inner) = root.open_child_dir_nofollow(&path) else {
                continue;
            };
            for child in inner.child_entries().unwrap_or_default() {
                if !before.contains(&child.name) {
                    remove(&inner, "", &child.name, child.is_dir);
                }
            }
        } else {
            remove(root, "", &entry.name, entry.is_dir);
        }
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
echo "$CRAFT_ADMIN_PASSWORD|$TYPO3_SETUP_ADMIN_PASSWORD|$TYPO3_DB_PASSWORD|$TYPO3_DB_DRIVER|$TYPO3_DB_HOST|$TYPO3_DB_PORT|$TYPO3_DB_DBNAME|$TYPO3_DB_USERNAME|$TYPO3_SETUP_CREATE_SITE" >> "$dir/secrets.log"
cwd=""
prev=""
for a in "$@"; do
  [ "$prev" = "-w" ] && cwd="$a"
  prev="$a"
done
case "$*" in
  *create-project*)
    [ -e "$dir/fail-composer" ] && exit 1
    package=""
    staging=""
    seen=0
    for a in "$@"; do
      if [ "$seen" = 2 ]; then staging="$a"; seen=3; fi
      if [ "$seen" = 1 ]; then package="$a"; seen=2; fi
      [ "$a" = "create-project" ] && seen=1
    done
    case "$package" in
      statamic/statamic)
        mkdir -p "$cwd/$staging/public" "$cwd/$staging/app"
        echo '<?php' > "$cwd/$staging/public/index.php"
        printf 'APP_URL=http://localhost:8000\nAPP_ENV=local\n' > "$cwd/$staging/.env"
        echo '{"packages":[{"name":"statamic/cms","version":"v6.2.1"}]}' > "$cwd/$staging/composer.lock"
        ;;
      craftcms/craft:^5)
        mkdir -p "$cwd/$staging/web" "$cwd/$staging/config"
        echo '<?php' > "$cwd/$staging/web/index.php"
        printf 'CRAFT_ENVIRONMENT=dev\nCRAFT_DEV_MODE=true\nCRAFT_DB_DRIVER=\nCRAFT_SECURITY_KEY=\n' > "$cwd/$staging/.env"
        echo '{"packages":[{"name":"craftcms/cms","version":"5.12.1"}]}' > "$cwd/$staging/composer.lock"
        ;;
      typo3/cms-base-distribution:^14)
        mkdir -p "$cwd/$staging/public" "$cwd/$staging/config"
        echo '<?php' > "$cwd/$staging/public/index.php"
        echo '{"packages":[{"name":"typo3/cms-core","version":"v14.0.1"}]}' > "$cwd/$staging/composer.lock"
        ;;
      laravel/laravel)
        mkdir -p "$cwd/$staging/public" "$cwd/$staging/app"
        echo '<?php' > "$cwd/$staging/public/index.php"
        printf 'APP_NAME=Laravel\nAPP_URL=http://localhost\nDB_CONNECTION=sqlite\n# DB_HOST=127.0.0.1\nSESSION_DRIVER=database\nCACHE_STORE=database\nQUEUE_CONNECTION=database\n' > "$cwd/$staging/.env.example"
        case "$*" in
          *--no-scripts*) ;;
          *)
            cp "$cwd/$staging/.env.example" "$cwd/$staging/.env"
            mkdir -p "$cwd/$staging/database"
            : > "$cwd/$staging/database/database.sqlite"
            echo "artisan migrate --graceful" >> "$dir/calls.log"
            ;;
        esac
        echo '{"packages":[{"name":"laravel/framework","version":"v12.1.0"}]}' > "$cwd/$staging/composer.lock"
        ;;
      drupal/recommended-project:^11)
        mkdir -p "$cwd/$staging/web/sites/default" "$cwd/$staging/web/core"
        echo '<?php' > "$cwd/$staging/web/index.php"
        printf '<?php\n// default settings\n' > "$cwd/$staging/web/sites/default/default.settings.php"
        echo '{"packages":[{"name":"drupal/core","version":"11.2.8"}]}' > "$cwd/$staging/composer.lock"
        ;;
      *) exit 3 ;;
    esac
    ;;
  *" clone "*)
    [ -e "$dir/fail-clone" ] && exit 128
    for a in "$@"; do staging="$a"; done
    cp -R "$dir/repo" "$cwd/$staging"
    ;;
  *composer.phar\ install\ *)
    mkdir -p "$cwd/vendor"
    echo '<?php' > "$cwd/vendor/autoload.php"
    cp "$dir/lock" "$cwd/composer.lock"
    ;;
  *make:user*)
    [ -e "$dir/fail-user" ] && exit 1
    ;;
  *setup/keys*)
    ;;
  *key:generate*)
    [ -e "$dir/fail-key" ] && exit 1
    ;;
  *storage:link*)
    [ -e "$dir/fail-link" ] && exit 1
    ;;
  *composer.phar\ require\ drush/drush*)
    [ -e "$dir/fail-drush" ] && exit 1
    mkdir -p "$cwd/vendor/bin"
    echo '<?php' > "$cwd/vendor/bin/drush"
    ;;
  *drush\ site:install*)
    echo "$DRUSH_COMMAND_SITE_INSTALL_OPTIONS_DB_URL|$DRUSH_COMMAND_SITE_INSTALL_OPTIONS_ACCOUNT_PASS" >> "$dir/drupal.log"
    # Drupal writes its settings and files before it can fail.
    echo '$databases = [];' >> "$cwd/web/sites/default/settings.php"
    mkdir -p "$cwd/web/sites/default/files/config_x/sync"
    [ -e "$dir/fail-drupal" ] && exit 1
    ;;
  *install/craft*)
    [ -e "$dir/fail-craft" ] && exit 1
    ;;
  *installation/joomla.php*)
    echo "$JOOMLA_ADMIN_PASSWORD|$JOOMLA_DB_PASSWORD" >> "$dir/joomla-secrets.log"
    echo "$cwd" >> "$dir/joomla-cwd.log"
    # Joomla writes its configuration before it can fail.
    echo '<?php class JConfig {}' > "$cwd/configuration.php"
    [ -e "$dir/fail-joomla" ] && exit 1
    [ -e "$dir/keep-installation" ] || rm -rf "$cwd/installation"
    ;;
  *maintenance:install*)
    echo "$NC_INSTALL_DB_PASSWORD|$NC_INSTALL_ADMIN_PASSWORD" >> "$dir/nextcloud.log"
    for a in "$@"; do data="$a"; done
    mkdir -p "$cwd/config"
    echo '<?php $CONFIG = [];' > "$cwd/config/config.php"
    : > "$data/.ncdata"
    [ -e "$dir/fail-nextcloud" ] && exit 1
    ;;
  *occ*status*)
    [ -e "$dir/not-installed" ] && { echo '{"installed":false}'; exit 0; }
    echo '{"installed":true,"version":"35.0.3.2"}'
    ;;
  *typo3*setup*)
    # TYPO3 writes files of its own before it can fail.
    mkdir -p "$cwd/var/log" "$cwd/config/system"
    echo '<?php' > "$cwd/config/system/settings.php"
    [ -e "$dir/fail-typo3" ] && exit 1
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
        /// What the fake fetcher returns for an archive URL.
        archive: std::cell::RefCell<Vec<u8>>,
        fetched: std::cell::Cell<u32>,
    }

    fn fixture() -> Fixture {
        fixture_for("public")
    }

    fn fixture_for(docroot: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let content = dir.path().join("content");
        let state_dir = dir.path().join("state");
        let site = content.join("example.com");
        fs::create_dir_all(site.join(docroot)).unwrap();
        fs::write(site.join(docroot).join(".user.ini"), "x").unwrap();
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
            archive: Default::default(),
            fetched: Default::default(),
            dir,
        }
    }

    impl Fixture {
        fn run(&self, id: &str, key: Option<&str>) -> Result<InstallResult, Error> {
            self.run_plan(
                &plan(self.site.to_str().unwrap(), self.uid, self.gid),
                id,
                key,
            )
        }
        fn run_plan(
            &self,
            json: &str,
            id: &str,
            key: Option<&str>,
        ) -> Result<InstallResult, Error> {
            let docker = self.dir.path().join("docker");
            let request = Request::parse(json, id, key).unwrap();
            let fetch = |_: &str, max: u64, _: Duration| {
                self.fetched.set(self.fetched.get() + 1);
                let bytes = std::io::Cursor::new(self.archive.borrow().clone());
                Ok(Box::new(std::io::Read::take(bytes, max)) as Box<dyn std::io::Read>)
            };
            execute(
                &Context {
                    engine_state: &self.state,
                    docker_program: docker.to_str().unwrap(),
                    fetch: &fetch,
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
        let meta = fs::metadata(&f.site).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (f.uid, f.gid));
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

    const DB_PASSWORD: &str = "Db-password_12345.x";
    const TYPO3_PASSWORD: &str = "Correct-Horse-9!battery";

    fn database(driver: &str) -> serde_json::Value {
        serde_json::json!({
            "driver": driver,
            "host": "mariadb",
            "port": 3306,
            "name": "site_db",
            "user": "site_user",
            "password": DB_PASSWORD,
        })
    }

    fn plan_for(
        f: &Fixture,
        application: &str,
        password: &str,
        db: Option<serde_json::Value>,
    ) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&plan(f.site.to_str().unwrap(), f.uid, f.gid)).unwrap();
        value["application"] = application.into();
        value["adminPassword"] = password.into();
        if let Some(db) = db {
            value["database"] = db;
        }
        value.to_string()
    }

    #[test]
    fn a_database_is_required_exactly_when_the_application_needs_one() {
        let f = fixture();
        let parse = |json: String| Request::parse(&json, REQUEST_ID, None).is_ok();
        assert!(parse(plan_for(&f, "statamic", PASSWORD, None)));
        assert!(!parse(plan_for(
            &f,
            "statamic",
            PASSWORD,
            Some(database("mariadb"))
        )));
        assert!(!parse(plan_for(&f, "craft", PASSWORD, None)));
        assert!(parse(plan_for(
            &f,
            "craft",
            PASSWORD,
            Some(database("mariadb"))
        )));
        assert!(parse(plan_for(
            &f,
            "craft",
            PASSWORD,
            Some(database("postgres"))
        )));
        assert!(!parse(plan_for(&f, "typo3", TYPO3_PASSWORD, None)));
        assert!(parse(plan_for(
            &f,
            "typo3",
            TYPO3_PASSWORD,
            Some(database("mariadb"))
        )));
    }

    #[test]
    fn database_fields_are_validated_one_by_one() {
        let f = fixture();
        let bad = |key: &str, value: serde_json::Value| {
            let mut db = database("mariadb");
            db[key] = value;
            Request::parse(&plan_for(&f, "craft", PASSWORD, Some(db)), REQUEST_ID, None).is_err()
        };
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("driver", "sqlite".into()),
            ("host", "bad host".into()),
            ("host", "".into()),
            ("port", 0.into()),
            ("name", "site; drop".into()),
            ("user", "".into()),
            // The password also goes into a .env file: plain characters only.
            ("password", "short".into()),
            ("password", "has space in it 123".into()),
            ("password", "has#hash-and-$dollar1".into()),
            ("password", "quote\"inside-123456".into()),
            ("password", "x".repeat(129).into()),
        ];
        for (key, value) in cases {
            assert!(bad(key, value.clone()), "{key} {value}");
        }
        let mut db = database("mariadb");
        db["extra"] = true.into();
        assert!(
            Request::parse(&plan_for(&f, "craft", PASSWORD, Some(db)), REQUEST_ID, None).is_err()
        );
    }

    #[test]
    fn a_site_made_with_the_wrong_document_root_is_named_as_such() {
        // Craft serves `web/`; a site created with the default `public/` is
        // refused with that reason, before anything runs.
        let f = fixture();
        let json = plan_for(&f, "craft", PASSWORD, Some(database("mariadb")));
        let error = f.run_plan(&json, REQUEST_ID, None).unwrap_err();
        assert!(matches!(error, Error::DocrootMismatch("web")), "{error:?}");
        assert_eq!(f.calls(), "");
        // And the other way round, for Statamic on a `web/` site.
        let g = fixture_for("web");
        let error = g.run(REQUEST_ID, None).unwrap_err();
        assert!(
            matches!(error, Error::DocrootMismatch("public")),
            "{error:?}"
        );
        // A directory with content is just not empty.
        let h = fixture_for("web");
        fs::write(h.site.join("web/page.php"), "mine").unwrap();
        assert!(matches!(
            h.run(REQUEST_ID, None),
            Err(Error::TargetNotEmpty)
        ));
    }

    #[test]
    fn typo3_wants_a_password_it_will_accept() {
        let f = fixture();
        let ok = |password: &str| {
            Request::parse(
                &plan_for(&f, "typo3", password, Some(database("mariadb"))),
                REQUEST_ID,
                None,
            )
            .is_ok()
        };
        assert!(ok(TYPO3_PASSWORD));
        for bad in [
            "alllowercase1!aaaa",
            "ALLUPPERCASE1!AAAA",
            "NoDigitsHere!aaaaa",
            "NoSpecialChar1aaaa",
        ] {
            assert!(!ok(bad), "{bad}");
        }
    }

    #[test]
    fn craft_installs_with_its_database_in_the_env_and_the_password_in_the_environment() {
        let f = fixture_for("web");
        let json = plan_for(&f, "craft", PASSWORD, Some(database("postgres")));
        let result = f.run_plan(&json, REQUEST_ID, None).unwrap();
        assert_eq!(result.application, "craft");
        assert_eq!(result.version, "5.12.1");
        assert_eq!(result.admin_url, "https://example.com/admin");
        assert_eq!(f.names(""), [".env", "composer.lock", "config", "web"]);
        assert_eq!(f.names("web"), [".user.ini", "index.php"]);
        let env = fs::read_to_string(f.site.join(".env")).unwrap();
        for line in [
            "CRAFT_ENVIRONMENT=production",
            "CRAFT_DEV_MODE=false",
            "CRAFT_DB_DRIVER=pgsql",
            "CRAFT_DB_SERVER=mariadb",
            "CRAFT_DB_PORT=3306",
            "CRAFT_DB_DATABASE=site_db",
            "CRAFT_DB_USER=site_user",
            &format!("CRAFT_DB_PASSWORD={DB_PASSWORD}"),
            "PRIMARY_SITE_URL=https://example.com",
        ] {
            assert!(env.lines().any(|l| l == line), "{line}\n{env}");
        }
        let calls = f.calls();
        assert!(calls.contains("craftcms/craft:^5"), "{calls}");
        assert!(
            calls.contains("php craft setup/keys --interactive=0"),
            "{calls}"
        );
        assert!(
            calls.contains("-e CRAFT_ADMIN_PASSWORD runtime-1 sh -c exec php craft install/craft")
                && calls
                    .trim_end()
                    .ends_with("sh admin@example.com example.com"),
            "{calls}"
        );
        assert!(!calls.contains(PASSWORD), "{calls}");
        let secrets = fs::read_to_string(f.dir.path().join("secrets.log")).unwrap();
        assert!(
            secrets
                .lines()
                .any(|l| l.starts_with(&format!("{PASSWORD}|"))),
            "{secrets}"
        );
    }

    #[test]
    fn typo3_installs_with_everything_in_the_environment() {
        let f = fixture();
        let json = plan_for(&f, "typo3", TYPO3_PASSWORD, Some(database("mariadb")));
        let result = f.run_plan(&json, REQUEST_ID, None).unwrap();
        assert_eq!(result.application, "typo3");
        assert_eq!(result.version, "14.0.1");
        assert_eq!(result.admin_url, "https://example.com/typo3");
        let calls = f.calls();
        for flag in [
            "-e TYPO3_DB_PASSWORD",
            "-e TYPO3_SETUP_ADMIN_PASSWORD",
            "-e TYPO3_DB_DRIVER=mysqli",
            "-e TYPO3_DB_DBNAME=site_db",
            "-e TYPO3_SETUP_ADMIN_EMAIL=admin@example.com",
            "-e TYPO3_SETUP_CREATE_SITE=https://example.com/",
            "-e TYPO3_SERVER_TYPE=other",
            "php vendor/bin/typo3 setup --force --no-interaction",
        ] {
            assert!(calls.contains(flag), "{flag}\n{calls}");
        }
        assert!(!calls.contains(TYPO3_PASSWORD), "{calls}");
        assert!(!calls.contains(DB_PASSWORD), "{calls}");
        let secrets = fs::read_to_string(f.dir.path().join("secrets.log")).unwrap();
        assert!(
            secrets
                .lines()
                .any(|l| l.contains(&format!("|{TYPO3_PASSWORD}|{DB_PASSWORD}|"))),
            "{secrets}"
        );
        assert_eq!(f.names("public"), [".user.ini", "index.php"]);
    }

    #[test]
    fn a_failed_setup_removes_files_the_setup_command_wrote_itself() {
        // TYPO3's setup creates `var/` and `config/system/` before it fails;
        // Craft's install fails after `.env` was rewritten.
        let f = fixture();
        fs::write(f.dir.path().join("fail-typo3"), "").unwrap();
        let json = plan_for(&f, "typo3", TYPO3_PASSWORD, Some(database("mariadb")));
        assert!(matches!(
            f.run_plan(&json, REQUEST_ID, None),
            Err(Error::SetupFailed(_))
        ));
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);

        let g = fixture_for("web");
        fs::write(g.dir.path().join("fail-craft"), "").unwrap();
        let json = plan_for(&g, "craft", PASSWORD, Some(database("mariadb")));
        assert!(matches!(
            g.run_plan(&json, REQUEST_ID, None),
            Err(Error::SetupFailed(_))
        ));
        assert_eq!(g.names(""), ["web"]);
        assert_eq!(g.names("web"), [".user.ini"]);
    }

    fn laravel_plan(f: &Fixture, driver: &str) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&plan_for(f, "laravel", PASSWORD, Some(database(driver))))
                .unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("adminEmail");
        object.remove("adminPassword");
        value.to_string()
    }

    #[test]
    fn laravel_install_writes_env_and_key() {
        for (driver, connection) in [("mariadb", "mariadb"), ("postgres", "pgsql")] {
            let f = fixture();
            let result = f
                .run_plan(&laravel_plan(&f, driver), REQUEST_ID, None)
                .unwrap();
            assert_eq!(result.application, "laravel");
            assert_eq!(result.version, "12.1.0");
            assert_eq!(result.admin_url, "https://example.com/");
            let env = fs::read_to_string(f.site.join(".env")).unwrap();
            for line in [
                "APP_URL=https://example.com".to_owned(),
                format!("DB_CONNECTION={connection}"),
                "DB_HOST=mariadb".to_owned(),
                "DB_PORT=3306".to_owned(),
                "DB_DATABASE=site_db".to_owned(),
                "DB_USERNAME=site_user".to_owned(),
                format!("DB_PASSWORD={DB_PASSWORD}"),
                "SESSION_DRIVER=file".to_owned(),
                "CACHE_STORE=file".to_owned(),
                "QUEUE_CONNECTION=sync".to_owned(),
            ] {
                assert!(env.lines().any(|l| l == line), "{line}\n{env}");
            }
            let calls = f.calls();
            assert!(calls.contains("laravel/laravel"), "{calls}");
            assert!(
                calls.contains("php artisan key:generate --force --no-interaction"),
                "{calls}"
            );
            assert!(!calls.contains(DB_PASSWORD), "{calls}");
            assert!(!env.contains("=database"), "{env}");
            assert_eq!(f.names("public"), [".user.ini", "index.php"]);
        }
    }

    #[test]
    fn laravel_install_failure_leaves_the_site_empty() {
        let f = fixture();
        fs::write(f.dir.path().join("fail-key"), "").unwrap();
        assert!(matches!(
            f.run_plan(&laravel_plan(&f, "mariadb"), REQUEST_ID, None),
            Err(Error::SetupFailed(_))
        ));
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
    }

    #[test]
    fn only_laravel_skips_composer_scripts_and_never_migrates() {
        let f = fixture();
        f.run_plan(&laravel_plan(&f, "mariadb"), REQUEST_ID, None)
            .unwrap();
        let calls = f.calls();
        assert!(calls.contains("--no-scripts"), "{calls}");
        assert!(!calls.contains("migrate"), "{calls}");
        assert!(!f.site.join("database/database.sqlite").exists());
        assert!(f.site.join(".env").exists());
        for (docroot, app, password, db) in [
            ("public", "statamic", PASSWORD, None),
            ("web", "craft", PASSWORD, Some(database("mariadb"))),
            ("public", "typo3", TYPO3_PASSWORD, Some(database("mariadb"))),
        ] {
            let g = fixture_for(docroot);
            g.run_plan(&plan_for(&g, app, password, db), REQUEST_ID, None)
                .unwrap();
            assert!(!g.calls().contains("--no-scripts"), "{app}");
        }
    }

    fn laravel_json(admin: bool, db: bool) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&plan("/var/www/example.com", 1000, 1000)).unwrap();
        value["application"] = "laravel".into();
        if !admin {
            let object = value.as_object_mut().unwrap();
            object.remove("adminEmail");
            object.remove("adminPassword");
        }
        if db {
            value["database"] = database("mariadb");
        }
        value.to_string()
    }

    #[test]
    fn laravel_parses_without_administrator() {
        assert!(Request::parse(&laravel_json(false, true), REQUEST_ID, None).is_ok());
    }

    #[test]
    fn laravel_with_administrator_fields_is_rejected() {
        assert_eq!(
            Request::parse(&laravel_json(true, true), REQUEST_ID, None).err(),
            Some(RequestError)
        );
    }

    #[test]
    fn statamic_without_administrator_is_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_str(&plan("/var/www/example.com", 1000, 1000)).unwrap();
        for field in ["adminEmail", "adminPassword"] {
            let mut v = value.clone();
            v.as_object_mut().unwrap().remove(field);
            assert!(Request::parse(&v.to_string(), REQUEST_ID, None).is_err());
        }
        let object = value.as_object_mut().unwrap();
        object.remove("adminEmail");
        object.remove("adminPassword");
        assert!(Request::parse(&value.to_string(), REQUEST_ID, None).is_err());
    }

    #[test]
    fn laravel_requires_a_database_plan() {
        assert!(Request::parse(&laravel_json(false, false), REQUEST_ID, None).is_err());
    }

    #[test]
    fn laravel_application_values() {
        let app = Application::Laravel;
        assert_eq!(app.name(), "laravel");
        assert_eq!(app.package(), "laravel/laravel");
        assert_eq!(app.docroot(), "public");
        assert_eq!(app.admin_path(), "/");
        assert_eq!(app.version_package(), "laravel/framework");
        assert!(app.needs_database() && !app.has_admin());
    }

    #[test]
    fn repository_url_table() {
        let longest = format!("https://github.com/{}", "a".repeat(2048 - 19));
        assert_eq!(longest.len(), 2048);
        for ok in [
            "https://github.com/laravel/laravel",
            "https://git.example.org/team/app.git",
            longest.as_str(),
        ] {
            assert_eq!(validate_repository_url(ok), Ok(()), "{ok:?}");
        }
        let too_long = format!("{longest}a");
        for bad in [
            "http://github.com/laravel/laravel",
            "ssh://git@github.com/laravel/laravel",
            "git@github.com:a/b",
            "https://user:pass@github.com/a/b",
            "https://user@github.com/a/b",
            "https://github.com/a/b?x=1#y",
            "https://github.com/a/b?x=1",
            "https://github.com/a/b#y",
            "-oProxyCommand=x",
            "https://github.com/a b",
            "https://github.com/a\tb",
            "https://github.com/a\nb",
            "https://github.com/a/b\n",
            " https://github.com/a/b",
            "",
            too_long.as_str(),
            "https://localhost/a",
            "https://LOCALHOST/a",
            "https://127.0.0.1/a",
            "https://10.0.0.1/a",
            "https://192.168.1.1/a",
            "https://169.254.169.254/a",
            "https://8.8.8.8/a",
            // IPv6 literals.
            "https://[::1]/a",
            "https://[2001:db8::1]/a",
            "https://[::ffff:127.0.0.1]/a",
            // Names that only resolve on a local network.
            "https://printer.local/a",
            "https://metadata.google.internal/a",
            "https://app.localhost/a",
            "https://APP.LOCAL/a",
            // Numeric, hex and octal address forms.
            "https://2130706433/a",
            "https://0x7f000001/a",
            "https://0177.0.0.1/a",
            "https://0x7f.0.0.1/a",
            "https://127.1/a",
            "https://1.0x7f/a",
            // Empty or trailing-dot labels, ports, missing path.
            "https://github.com./a",
            "https://github..com/a",
            "https://.github.com/a",
            "https:///a",
            "https://github.com:443/a",
            "https://github.com",
            "https://github.com/",
            "https://github/a",
            "HTTPS://github.com/a",
            "https://g\u{ef}thub.com/a",
            "https://github.com\\@evil.com/a",
            "https://github.com/a\\b",
        ] {
            assert_eq!(validate_repository_url(bad), Err(RequestError), "{bad:?}");
        }
    }

    fn laravel_git_plan(f: &Fixture, url: &str) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&laravel_plan(f, "mariadb")).unwrap();
        value["source"] = serde_json::json!({ "kind": "git", "url": url });
        value.to_string()
    }

    #[test]
    fn the_source_is_fresh_by_default_and_git_only_for_laravel() {
        let f = fixture();
        let parse = |json: String| Request::parse(&json, REQUEST_ID, None).is_ok();
        assert!(parse(laravel_plan(&f, "mariadb")));
        let mut fresh: serde_json::Value =
            serde_json::from_str(&laravel_plan(&f, "mariadb")).unwrap();
        fresh["source"] = serde_json::json!({ "kind": "fresh" });
        assert!(parse(fresh.to_string()));
        assert!(parse(laravel_git_plan(
            &f,
            "https://github.com/laravel/laravel"
        )));
        assert!(!parse(laravel_git_plan(&f, "https://127.0.0.1/a")));
        assert!(!parse(laravel_git_plan(&f, "ssh://github.com/a/b")));
        let mut extra: serde_json::Value =
            serde_json::from_str(&laravel_git_plan(&f, "https://github.com/a/b")).unwrap();
        extra["source"]["branch"] = "main".into();
        assert!(!parse(extra.to_string()));
        let mut unknown = fresh.clone();
        unknown["source"] = serde_json::json!({ "kind": "zip" });
        assert!(!parse(unknown.to_string()));
        let mut statamic: serde_json::Value =
            serde_json::from_str(&plan_for(&f, "statamic", PASSWORD, None)).unwrap();
        statamic["source"] = serde_json::json!({ "kind": "git", "url": "https://github.com/a/b" });
        assert!(!parse(statamic.to_string()));
    }

    const GIT_URL: &str = "https://github.com/example/app";
    const LARAVEL_LOCK: &str = r#"{"packages":[{"name":"laravel/framework","version":"v12.3.0"}]}"#;

    /// A committed Laravel project the fake `git clone` copies.
    fn repo(f: &Fixture, lock: &str, with_public: bool) {
        let repo = f.dir.path().join("repo");
        fs::create_dir_all(repo.join("app")).unwrap();
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join(".git/config"), "[core]").unwrap();
        fs::write(repo.join("composer.json"), "{}").unwrap();
        fs::write(
            repo.join(".env.example"),
            "APP_NAME=App\nDB_CONNECTION=sqlite\nSESSION_DRIVER=database\nCACHE_STORE=database\nQUEUE_CONNECTION=database\n",
        )
        .unwrap();
        if with_public {
            fs::create_dir_all(repo.join("public")).unwrap();
            fs::write(repo.join("public/index.php"), "<?php").unwrap();
        }
        fs::write(f.dir.path().join("lock"), lock).unwrap();
    }

    #[test]
    fn git_source_installs_after_composer_install() {
        let f = fixture();
        repo(&f, LARAVEL_LOCK, true);
        let result = f
            .run_plan(&laravel_git_plan(&f, GIT_URL), REQUEST_ID, None)
            .unwrap();
        assert_eq!(result.application, "laravel");
        assert_eq!(result.version, "12.3.0");
        assert_eq!(
            f.names(""),
            [
                ".env",
                ".env.example",
                "app",
                "composer.json",
                "composer.lock",
                "public",
                "vendor"
            ]
        );
        assert_eq!(f.names("public"), [".user.ini", "index.php"]);
        let env = fs::read_to_string(f.site.join(".env")).unwrap();
        assert!(env.starts_with("APP_NAME=App\n"), "{env}");
        assert!(env.lines().any(|l| l == "DB_CONNECTION=mariadb"), "{env}");
        for line in [
            "SESSION_DRIVER=file",
            "CACHE_STORE=file",
            "QUEUE_CONNECTION=sync",
        ] {
            assert!(env.lines().any(|l| l == line), "{line}\n{env}");
        }
        assert!(!env.contains("=database"), "{env}");
        let calls = f.calls();
        let lines: Vec<&str> = calls.lines().collect();
        let position = |needle: &str| lines.iter().position(|l| l.contains(needle)).unwrap();
        let clone = position(" clone ");
        let install = position("composer.phar install ");
        let key = position("key:generate");
        let link = position("php artisan storage:link --no-interaction");
        assert!(clone < install && install < key && key < link, "{calls}");
        assert!(!calls.contains("create-project"), "{calls}");
        let staging = format!(".wcp-install-{REQUEST_ID}");
        for part in [
            format!("--user {}:{}", f.uid, f.gid),
            "-e GIT_TERMINAL_PROMPT=0".to_owned(),
            "-e GIT_CONFIG_GLOBAL=/dev/null".to_owned(),
            "-e GIT_CONFIG_NOSYSTEM=1".to_owned(),
            format!(
                "runtime-1 git -c credential.helper= -c protocol.allow=never -c protocol.https.allow=always clone --depth 1 --no-tags --no-recurse-submodules -- {GIT_URL} {staging}"
            ),
        ] {
            assert!(lines[clone].contains(&part), "{part}\n{calls}");
        }
        assert!(
            lines[install].contains(&format!("/example.com/{staging} -e COMPOSER_HOME="))
                && lines[install].ends_with(
                    "install --no-dev --no-interaction --prefer-dist --no-scripts --no-plugins --no-ansi --no-progress"
                ),
            "{calls}"
        );
    }

    fn assert_refused_and_undone(f: &Fixture) {
        let error = f
            .run_plan(&laravel_git_plan(f, GIT_URL), REQUEST_ID, None)
            .unwrap_err();
        assert!(matches!(error, Error::NotLaravel), "{error:?}");
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
        assert!(!f.calls().contains("key:generate"));
    }

    #[test]
    fn git_source_without_laravel_framework_is_refused_and_undone() {
        let f = fixture();
        repo(
            &f,
            r#"{"packages":[{"name":"symfony/symfony","version":"7.1.0"}]}"#,
            true,
        );
        assert_refused_and_undone(&f);
    }

    #[test]
    fn git_source_without_public_directory_is_refused_and_undone() {
        let f = fixture();
        repo(&f, LARAVEL_LOCK, false);
        assert_refused_and_undone(&f);
        // Refused before Composer runs anything from the repository.
        assert!(
            !f.calls().contains("composer.phar install"),
            "{}",
            f.calls()
        );
    }

    #[test]
    fn git_source_without_env_example_is_refused_and_undone() {
        let f = fixture();
        repo(&f, LARAVEL_LOCK, true);
        fs::remove_file(f.dir.path().join("repo/.env.example")).unwrap();
        assert_refused_and_undone(&f);
    }

    #[test]
    fn git_source_ignores_committed_env_and_vendor() {
        let f = fixture();
        repo(&f, LARAVEL_LOCK, true);
        let repo = f.dir.path().join("repo");
        fs::write(repo.join(".env"), "APP_KEY=committed-secret\n").unwrap();
        fs::create_dir_all(repo.join("vendor/evil")).unwrap();
        fs::write(repo.join("vendor/evil/x.php"), "<?php").unwrap();
        f.run_plan(&laravel_git_plan(&f, GIT_URL), REQUEST_ID, None)
            .unwrap();
        let env = fs::read_to_string(f.site.join(".env")).unwrap();
        assert!(!env.contains("committed-secret"), "{env}");
        assert_eq!(f.names("vendor"), ["autoload.php"]);
    }

    #[test]
    fn git_source_removes_dot_git() {
        let f = fixture();
        repo(&f, LARAVEL_LOCK, true);
        f.run_plan(&laravel_git_plan(&f, GIT_URL), REQUEST_ID, None)
            .unwrap();
        assert!(!f.site.join(".git").exists());
        assert!(!f.site.join(format!(".wcp-install-{REQUEST_ID}")).exists());
    }

    #[test]
    fn a_failed_clone_leaves_the_site_as_it_was() {
        let f = fixture();
        repo(&f, LARAVEL_LOCK, true);
        fs::write(f.dir.path().join("fail-clone"), "").unwrap();
        let error = f
            .run_plan(&laravel_git_plan(&f, GIT_URL), REQUEST_ID, None)
            .unwrap_err();
        assert!(matches!(error, Error::CloneFailed(_)), "{error:?}");
        assert!(!error.protocol().1.contains(GIT_URL));
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
    }

    #[test]
    fn laravel_links_storage_after_the_key() {
        let f = fixture();
        f.run_plan(&laravel_plan(&f, "mariadb"), REQUEST_ID, None)
            .unwrap();
        let calls = f.calls();
        let key = calls.find("key:generate").unwrap();
        let link = calls
            .find("php artisan storage:link --no-interaction")
            .unwrap();
        assert!(key < link, "{calls}");
    }

    #[test]
    fn a_failed_storage_link_leaves_the_site_empty() {
        let f = fixture();
        fs::write(f.dir.path().join("fail-link"), "").unwrap();
        assert!(matches!(
            f.run_plan(&laravel_plan(&f, "mariadb"), REQUEST_ID, None),
            Err(Error::SetupFailed(_))
        ));
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
    }

    #[test]
    fn git_source_drops_committed_bootstrap_cache() {
        let f = fixture();
        repo(&f, LARAVEL_LOCK, true);
        let cache = f.dir.path().join("repo/bootstrap/cache");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join(".gitignore"), "*\n!.gitignore\n").unwrap();
        fs::write(cache.join("config.php"), "<?php return ['app' => []];").unwrap();
        fs::write(cache.join("packages.php"), "<?php return [];").unwrap();
        f.run_plan(&laravel_git_plan(&f, GIT_URL), REQUEST_ID, None)
            .unwrap();
        assert_eq!(f.names("bootstrap/cache"), [".gitignore"]);
    }

    // ── Joomla ───────────────────────────────────────────────────────────

    const JOOMLA_URL: &str =
        "https://update.joomla.org/releases/6.2.1/Joomla_6.2.1-Stable-Full_Package.tar.gz";
    const JOOMLA_MANIFEST: &[u8] = b"<extension><version>6.2.1</version></extension>";

    fn gzip(tar: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(tar).unwrap();
        gz.finish().unwrap()
    }

    /// The shape of Joomla's full package: the files sit at the top level.
    fn joomla_archive() -> Vec<u8> {
        gzip(
            &crate::test_support::TarArchive::new()
                .entry("administrator/", b'5', b"", 0o755, "")
                .entry("administrator/manifests/", b'5', b"", 0o755, "")
                .entry("administrator/manifests/files/", b'5', b"", 0o755, "")
                .file("administrator/manifests/files/joomla.xml", JOOMLA_MANIFEST)
                .entry("installation/", b'5', b"", 0o755, "")
                .file("installation/joomla.php", b"<?php")
                .file("index.php", b"<?php")
                .file("htaccess.txt", b"x")
                .end(),
        )
    }

    fn joomla_plan_with(f: &Fixture, archive: &[u8], db: serde_json::Value) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&plan_for(f, "joomla", PASSWORD, Some(db))).unwrap();
        value["archive"] = serde_json::json!({
            "url": JOOMLA_URL,
            "sha256": crate::util::sha256_hex(archive),
        });
        value.to_string()
    }

    fn joomla_fixture() -> (Fixture, String) {
        let f = fixture();
        let archive = joomla_archive();
        let plan = joomla_plan_with(&f, &archive, database("mariadb"));
        *f.archive.borrow_mut() = archive;
        (f, plan)
    }

    #[test]
    fn joomla_installs_from_the_pinned_archive_into_the_docroot() {
        let (f, plan) = joomla_fixture();
        let result = f.run_plan(&plan, REQUEST_ID, None).unwrap();
        assert_eq!(result.application, "joomla");
        assert_eq!(result.version, "6.2.1");
        assert_eq!(result.admin_url, "https://example.com/administrator");
        assert_eq!(f.fetched.get(), 1);
        // Joomla's files are the document root itself; the CLI removed
        // `installation/` and wrote `configuration.php`.
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(
            f.names("public"),
            [
                ".user.ini",
                "administrator",
                "configuration.php",
                "htaccess.txt",
                "index.php"
            ]
        );
        let config = f.site.join("public/configuration.php");
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let meta = fs::metadata(f.site.join("public/administrator/manifests")).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (f.uid, f.gid));
        // The CLI ran once in the docroot, no Composer at all, and neither
        // password is in any argument; both reached it through the
        // environment.
        let calls = f.calls();
        assert_eq!(calls.lines().count(), 1, "{calls}");
        assert!(!calls.contains("composer"), "{calls}");
        assert!(
            calls.contains("-e JOOMLA_ADMIN_PASSWORD -e JOOMLA_DB_PASSWORD runtime-1 php -r"),
            "{calls}"
        );
        assert!(calls.contains("-e JOOMLA_DB_TYPE=mysqli"), "{calls}");
        assert!(calls.contains("-e JOOMLA_DB_HOST=mariadb"), "{calls}");
        assert!(
            !calls.contains(PASSWORD) && !calls.contains(DB_PASSWORD),
            "{calls}"
        );
        let secrets = fs::read_to_string(f.dir.path().join("joomla-secrets.log")).unwrap();
        assert_eq!(secrets.trim(), format!("{PASSWORD}|{DB_PASSWORD}"));
        let cwd = fs::read_to_string(f.dir.path().join("joomla-cwd.log")).unwrap();
        assert!(cwd.trim().ends_with("example.com/public"), "{cwd}");
        // The downloaded file was in the engine's state and is gone.
        let downloads = f.dir.path().join("state/application-install/downloads");
        assert_eq!(fs::read_dir(&downloads).unwrap().count(), 0);
        assert!(!serde_json::to_string(&result).unwrap().contains(PASSWORD));
    }

    #[test]
    fn joomla_on_postgres_uses_the_pgsql_driver() {
        let f = fixture();
        let archive = joomla_archive();
        let mut db = database("postgres");
        db["port"] = 5432.into();
        db["host"] = "postgres-18".into();
        let plan = joomla_plan_with(&f, &archive, db);
        *f.archive.borrow_mut() = archive;
        f.run_plan(&plan, REQUEST_ID, None).unwrap();
        let calls = f.calls();
        assert!(calls.contains("-e JOOMLA_DB_TYPE=pgsql"), "{calls}");
        assert!(calls.contains("-e JOOMLA_DB_HOST=postgres-18"), "{calls}");
    }

    #[test]
    fn a_tampered_archive_is_refused_before_anything_is_written_or_run() {
        let (f, plan) = joomla_fixture();
        f.archive.borrow_mut().push(0);
        let error = f.run_plan(&plan, REQUEST_ID, None).unwrap_err();
        assert!(matches!(error, Error::ArchiveDigest), "{error:?}");
        assert_eq!(error.protocol().0, ErrorCode::ArtifactVerificationFailed);
        assert_eq!(f.calls(), "");
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
    }

    #[test]
    fn an_archive_with_an_escaping_entry_is_refused_and_undone() {
        for archive in [
            crate::test_support::TarArchive::new()
                .file("index.php", b"<?php")
                .file("../evil.php", b"<?php")
                .end(),
            crate::test_support::TarArchive::new()
                .file("index.php", b"<?php")
                .entry("up", b'2', b"", 0o777, "../../..")
                .end(),
            crate::test_support::TarArchive::new()
                .file("index.php", b"<?php")
                .entry("hard", b'1', b"", 0o644, "index.php")
                .end(),
        ] {
            let f = fixture();
            let archive = gzip(&archive);
            let plan = joomla_plan_with(&f, &archive, database("mariadb"));
            *f.archive.borrow_mut() = archive;
            let error = f.run_plan(&plan, REQUEST_ID, None).unwrap_err();
            assert!(matches!(error, Error::ArchiveUnsafe), "{error:?}");
            assert_eq!(f.calls(), "");
            assert_eq!(f.names(""), ["public"]);
            assert_eq!(f.names("public"), [".user.ini"]);
            assert!(!f.site.parent().unwrap().join("evil.php").exists());
        }
    }

    #[test]
    fn a_failed_joomla_install_leaves_the_site_empty() {
        let (f, plan) = joomla_fixture();
        fs::write(f.dir.path().join("fail-joomla"), "").unwrap();
        assert!(matches!(
            f.run_plan(&plan, REQUEST_ID, None),
            Err(Error::SetupFailed(_))
        ));
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
    }

    #[test]
    fn an_installation_directory_joomla_left_behind_is_removed() {
        let (f, plan) = joomla_fixture();
        fs::write(f.dir.path().join("keep-installation"), "").unwrap();
        f.run_plan(&plan, REQUEST_ID, None).unwrap();
        assert!(!f.site.join("public/installation").exists());
    }

    #[test]
    fn joomla_without_a_manifest_version_is_not_success() {
        let f = fixture();
        let archive = gzip(
            &crate::test_support::TarArchive::new()
                .file("index.php", b"<?php")
                .end(),
        );
        let plan = joomla_plan_with(&f, &archive, database("mariadb"));
        *f.archive.borrow_mut() = archive;
        assert!(matches!(
            f.run_plan(&plan, REQUEST_ID, None),
            Err(Error::Unverified)
        ));
        assert_eq!(f.names("public"), [".user.ini"]);
    }

    #[test]
    fn joomla_plan_table() {
        let f = fixture();
        let archive = joomla_archive();
        let good: serde_json::Value =
            serde_json::from_str(&joomla_plan_with(&f, &archive, database("mariadb"))).unwrap();
        let parse = |value: &serde_json::Value| {
            Request::parse(&value.to_string(), REQUEST_ID, None).is_ok()
        };
        assert!(parse(&good));
        let mut postgres = good.clone();
        postgres["database"]["driver"] = "postgres".into();
        postgres["database"]["port"] = 5432.into();
        assert!(parse(&postgres));
        let rejected: [(&str, serde_json::Value); 10] = [
            ("archive", serde_json::Value::Null),
            ("archive", serde_json::json!({"url": JOOMLA_URL})),
            (
                "archive",
                serde_json::json!({"url": JOOMLA_URL, "sha256": "ab", "extra": 1}),
            ),
            (
                "archive",
                serde_json::json!({
                    "url": "https://downloads.joomla.org/cms/joomla6/6-2-1/x.tar.gz",
                    "sha256": crate::util::sha256_hex(&archive),
                }),
            ),
            (
                "archive",
                serde_json::json!({
                    "url": JOOMLA_URL.replace("https", "http"),
                    "sha256": crate::util::sha256_hex(&archive),
                }),
            ),
            (
                "archive",
                serde_json::json!({"url": JOOMLA_URL, "sha256": "A".repeat(64)}),
            ),
            ("source", serde_json::json!({"kind": "git", "url": GIT_URL})),
            ("database", serde_json::Value::Null),
            ("adminPassword", serde_json::Value::Null),
            ("database", {
                let mut db = database("mariadb");
                db["port"] = 3307.into();
                db
            }),
        ];
        for (key, value) in rejected {
            let mut plan = good.clone();
            if value.is_null() {
                plan.as_object_mut().unwrap().remove(key);
            } else {
                plan[key] = value.clone();
            }
            assert!(!parse(&plan), "{key}: {value}");
        }
        let mut postgres_on_maria_port = postgres.clone();
        postgres_on_maria_port["database"]["port"] = 3306.into();
        assert!(!parse(&postgres_on_maria_port));
        // An archive is only for an application that installs from one.
        let mut statamic: serde_json::Value =
            serde_json::from_str(&plan(f.site.to_str().unwrap(), f.uid, f.gid)).unwrap();
        statamic["archive"] = good["archive"].clone();
        assert!(!parse(&statamic));
    }

    #[test]
    fn archive_url_table() {
        let hosts = &["update.joomla.org"];
        for url in [JOOMLA_URL, "https://update.joomla.org/a.tar.gz"] {
            assert!(archive_url_ok(url, hosts), "{url}");
        }
        let long = format!("https://update.joomla.org/{}", "a".repeat(512));
        for url in [
            "http://update.joomla.org/a.tar.gz",
            "https://downloads.joomla.org/a.tar.gz",
            "https://update.joomla.org.evil.test/a.tar.gz",
            "https://evil.test/update.joomla.org/a.tar.gz",
            "https://UPDATE.joomla.org/a.tar.gz",
            "https://update.joomla.org:443/a.tar.gz",
            "https://user@update.joomla.org/a.tar.gz",
            "https://update.joomla.org/a.tar.gz?x=1",
            "https://update.joomla.org/a.tar.gz#x",
            "https://update.joomla.org/a%2e%2e/b",
            "https://update.joomla.org/../a.tar.gz",
            "https://update.joomla.org/./a.tar.gz",
            "https://update.joomla.org//a.tar.gz",
            "https://update.joomla.org/a\\b",
            "https://update.joomla.org/a b",
            "https://update.joomla.org/a\nb",
            "https://update.joomla.org/",
            "https://update.joomla.org",
            "update.joomla.org/a.tar.gz",
            "",
            &long,
        ] {
            assert!(!archive_url_ok(url, hosts), "{url:?}");
        }
        assert!(!archive_url_ok(JOOMLA_URL, &[]));
    }

    #[test]
    fn a_failed_download_writes_nothing_and_keeps_no_file() {
        let (f, plan) = joomla_fixture();
        let request = Request::parse(&plan, REQUEST_ID, None).unwrap();
        let failing = |_: &str,
                       _: u64,
                       _: Duration|
         -> Result<Box<dyn std::io::Read>, crate::engine::fetch::Error> {
            Err(crate::engine::fetch::Error::Status(404))
        };
        let docker = f.dir.path().join("docker");
        let error = execute(
            &Context {
                engine_state: &f.state,
                docker_program: docker.to_str().unwrap(),
                fetch: &failing,
            },
            &f.content_root,
            &request,
            &CancellationToken::default(),
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::ArchiveFetch(ErrorCode::ArtifactFetchFailed)),
            "{error:?}"
        );
        assert_eq!(f.calls(), "");
        assert_eq!(f.names(""), ["public"]);
        assert_eq!(f.names("public"), [".user.ini"]);
        let downloads = f.dir.path().join("state/application-install/downloads");
        assert_eq!(fs::read_dir(&downloads).unwrap().count(), 0);
    }

    #[test]
    fn joomla_application_values() {
        let joomla = Application::Joomla;
        assert_eq!(joomla.name(), "joomla");
        assert_eq!(joomla.docroot(), "public");
        assert_eq!(joomla.admin_path(), "/administrator");
        assert!(joomla.needs_database() && joomla.has_admin());
        assert_eq!(joomla.archive_hosts(), ["update.joomla.org"]);
        assert!(Application::Statamic.archive_hosts().is_empty());
    }
    mod nextcloud_install;
    fn drupal_plan(f: &Fixture, driver: &str) -> String {
        plan_for(f, "drupal", PASSWORD, Some(database(driver)))
    }

    /// Lets the temporary directory be removed after a successful install
    /// made `sites/default` read-only.
    fn unlock_drupal(f: &Fixture) {
        let _ = fs::set_permissions(
            f.site.join("web/sites/default"),
            fs::Permissions::from_mode(0o755),
        );
    }

    #[test]
    fn drupal_application_values() {
        let app = Application::Drupal;
        assert_eq!(app.name(), "drupal");
        assert_eq!(app.package(), "drupal/recommended-project:^11");
        assert_eq!(app.docroot(), "web");
        assert_eq!(app.admin_path(), "/user/login");
        assert_eq!(app.version_package(), "drupal/core");
        assert!(app.needs_database() && app.has_admin());
    }

    #[test]
    fn drupal_requires_an_administrator_and_a_database() {
        let f = fixture_for("web");
        let parse = |json: &str| Request::parse(json, REQUEST_ID, None).is_ok();
        assert!(parse(&drupal_plan(&f, "mariadb")));
        assert!(parse(&drupal_plan(&f, "postgres")));
        assert!(!parse(&plan_for(&f, "drupal", PASSWORD, None)));
        let mut value: serde_json::Value =
            serde_json::from_str(&drupal_plan(&f, "mariadb")).unwrap();
        value.as_object_mut().unwrap().remove("adminPassword");
        assert!(!parse(&value.to_string()));
        let mut value: serde_json::Value =
            serde_json::from_str(&drupal_plan(&f, "mariadb")).unwrap();
        value.as_object_mut().unwrap().remove("adminEmail");
        assert!(!parse(&value.to_string()));
        // Only Laravel has a repository source.
        let mut value: serde_json::Value =
            serde_json::from_str(&drupal_plan(&f, "mariadb")).unwrap();
        value["source"] = serde_json::json!({"kind": "git", "url": GIT_URL});
        assert!(!parse(&value.to_string()));
    }

    #[test]
    fn drupal_installs_with_secrets_only_in_the_environment() {
        for (driver, scheme) in [("mariadb", "mysql"), ("postgres", "pgsql")] {
            let f = fixture_for("web");
            let result = f
                .run_plan(&drupal_plan(&f, driver), REQUEST_ID, None)
                .unwrap();
            assert_eq!(result.application, "drupal");
            assert_eq!(result.version, "11.2.8");
            assert_eq!(result.admin_url, "https://example.com/user/login");
            let calls = f.calls();
            for part in [
                "drupal/recommended-project:^11",
                "-e DRUSH_OPTIONS_URI=https://example.com",
                "-e DRUSH_COMMAND_SITE_INSTALL_OPTIONS_DB_URL",
                "-e DRUSH_COMMAND_SITE_INSTALL_OPTIONS_ACCOUNT_PASS",
                "php vendor/bin/drush site:install standard --yes --account-name=admin --account-mail=admin@example.com --site-mail=admin@example.com --site-name=example.com",
            ] {
                assert!(calls.contains(part), "{part}\n{calls}");
            }
            assert!(!calls.contains(PASSWORD), "{calls}");
            assert!(!calls.contains(DB_PASSWORD), "{calls}");
            let secrets = fs::read_to_string(f.dir.path().join("drupal.log")).unwrap();
            assert_eq!(
                secrets.trim(),
                format!("{scheme}://site_user:{DB_PASSWORD}@mariadb:3306/site_db|{PASSWORD}"),
            );
            assert!(!serde_json::to_string(&result).unwrap().contains(PASSWORD));

            // Drupal's own settings file: the default one, the site's host as
            // the only trusted one, what the installer added, read-only.
            let default = f.site.join("web/sites/default");
            let settings = fs::read_to_string(default.join("settings.php")).unwrap();
            assert!(
                settings.starts_with("<?php\n// default settings\n"),
                "{settings}"
            );
            assert!(
                settings.contains("$settings['trusted_host_patterns'] = ['^example\\.com$'];\n"),
                "{settings}"
            );
            // The site's own FrankenPHP is reached through the runtime pool
            // on loopback, with the site's host in `X-Forwarded-Host` only.
            assert!(
                settings.contains(
                    "$settings['reverse_proxy'] = TRUE;\n$settings['reverse_proxy_addresses'] = ['127.0.0.1'];\n$settings['reverse_proxy_trusted_headers'] = \\Symfony\\Component\\HttpFoundation\\Request::HEADER_X_FORWARDED_FOR | \\Symfony\\Component\\HttpFoundation\\Request::HEADER_X_FORWARDED_HOST;\n\\Symfony\\Component\\HttpFoundation\\Request::setTrustedProxies($settings['reverse_proxy_addresses'], $settings['reverse_proxy_trusted_headers']);\n"
                ),
                "{settings}"
            );
            assert!(settings.contains("$databases = [];"), "{settings}");
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&default.join("settings.php")), 0o440);
            assert_eq!(mode(&default), 0o555);
            assert!(default.join("files").is_dir());
            let meta = fs::metadata(default.join("settings.php")).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (f.uid, f.gid));
            assert_eq!(f.names("web"), [".user.ini", "core", "index.php", "sites"]);
            unlock_drupal(&f);
        }
    }

    #[test]
    fn drupal_installs_drush_from_the_project_before_moving_it() {
        let f = fixture_for("web");
        f.run_plan(&drupal_plan(&f, "mariadb"), REQUEST_ID, None)
            .unwrap();
        let calls = f.calls();
        let require = calls
            .lines()
            .position(|l| l.contains("composer.phar require drush/drush:^13"))
            .expect(&calls);
        let install = calls
            .lines()
            .position(|l| l.contains("drush site:install"))
            .expect(&calls);
        assert!(require < install, "{calls}");
        // Composer ran in the staging directory, as the site's UID.
        let line = calls.lines().nth(require).unwrap();
        assert!(
            line.contains("/.wcp-install-") && line.contains("--user"),
            "{line}"
        );
        assert!(f.site.join("vendor/bin/drush").is_file());
        unlock_drupal(&f);
    }

    #[test]
    fn a_failed_drupal_install_leaves_the_site_empty() {
        for marker in ["fail-drush", "fail-drupal"] {
            let f = fixture_for("web");
            fs::write(f.dir.path().join(marker), "").unwrap();
            let error = f
                .run_plan(&drupal_plan(&f, "mariadb"), REQUEST_ID, None)
                .unwrap_err();
            assert!(
                matches!(error, Error::ComposerFailed(_) | Error::SetupFailed(_)),
                "{marker}: {error:?}"
            );
            assert_eq!(f.names(""), ["web"], "{marker}");
            assert_eq!(f.names("web"), [".user.ini"], "{marker}");
        }
    }
}
