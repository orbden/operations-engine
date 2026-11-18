//! `runtime.patchStatus`: for every container of the managed stack, which
//! full version it runs and whether a candidate image the caller names is a
//! patch within the same minor, a minor or major jump, or already running.
//! Read-only and local: it asks the local Docker daemon about the stack and
//! changes nothing. The candidate comes from the caller (the panel's image
//! catalog); the engine fetches nothing.
//!
//! The running version is read from the image the container was created from
//! (OCI version label, then the official images' version environment
//! variable), never by running anything in the container. A version that
//! cannot be read, a candidate without a digest or version, a candidate older
//! than what runs, or a daemon that cannot answer is `unknown`: never "up to
//! date" and never "patch pending".

use crate::security_affected::{Docker, Unavailable};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const OPERATION: &str = "runtime.patchStatus";
const MAX_CANDIDATES: usize = 64;
const MAX_SERVICES: usize = 256;
const MANAGED_PROJECT_LABEL: &str = "label=com.docker.compose.project=wcp";
const IMAGE_PREFIX: &str = "ghcr.io/orbden/";

#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    Malformed,
    TooManyCandidates,
    InvalidService,
    InvalidDigest,
    InvalidVersion,
    DuplicateService,
}

impl RequestError {
    pub const fn message(&self) -> &'static str {
        match self {
            Self::Malformed => "request-file is not a valid patch status request",
            Self::TooManyCandidates => "too many candidates",
            Self::InvalidService => "candidate service is not a compose service name",
            Self::InvalidDigest => "candidate digest is not sha256:<64 hex>",
            Self::InvalidVersion => "candidate resolvedVersion is not a dotted version",
            Self::DuplicateService => "a service has more than one candidate",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCandidate {
    service: String,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    resolved_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRequest {
    candidates: Vec<RawCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub service: String,
    pub digest: Option<String>,
    pub resolved_version: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub candidates: Vec<Candidate>,
}

fn digest_ok(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn service_ok(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= 64
        && service.as_bytes()[0].is_ascii_alphanumeric()
        && service
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl Request {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let raw: RawRequest = serde_json::from_str(json).map_err(|_| RequestError::Malformed)?;
        if raw.candidates.len() > MAX_CANDIDATES {
            return Err(RequestError::TooManyCandidates);
        }
        let mut seen = BTreeSet::new();
        let mut candidates = Vec::new();
        for c in raw.candidates {
            if !service_ok(&c.service) {
                return Err(RequestError::InvalidService);
            }
            if c.digest.as_deref().is_some_and(|d| !digest_ok(d)) {
                return Err(RequestError::InvalidDigest);
            }
            if c.resolved_version
                .as_deref()
                .is_some_and(|v| parse_version(v).is_none() || v.len() > 32)
            {
                return Err(RequestError::InvalidVersion);
            }
            if !seen.insert(c.service.clone()) {
                return Err(RequestError::DuplicateService);
            }
            candidates.push(Candidate {
                service: c.service,
                digest: c.digest,
                resolved_version: c.resolved_version,
            });
        }
        Ok(Self { candidates })
    }
}

/// `1:11.4.5+maria~ubu2404`, `v1.53.3`, `18.1` -> numeric components.
/// At least major and minor are required. After the numbers only an apt
/// revision may follow (`+...`, or `-` and a digit): a pre-release or other
/// junk (`18.1rc1`, `18.1~rc1`, `18.1-beta`, a control character) is not
/// provably a release, so it is unparseable and the caller reports unknown.
pub fn parse_version(raw: &str) -> Option<Vec<u32>> {
    let raw = raw.trim();
    let raw = match raw.split_once(':') {
        Some((epoch, rest)) if epoch.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => raw,
    };
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let end = raw
        .bytes()
        .position(|b| !(b.is_ascii_digit() || b == b'.'))
        .unwrap_or(raw.len());
    let suffix = &raw.as_bytes()[end..];
    let suffix_ok = match suffix {
        [] => true,
        [b'+', rest @ ..] => rest.iter().all(|b| b.is_ascii_graphic()),
        [b'-', d, rest @ ..] => d.is_ascii_digit() && rest.iter().all(|b| b.is_ascii_graphic()),
        _ => false,
    };
    if !suffix_ok {
        return None;
    }
    let parts: Option<Vec<u32>> = raw[..end]
        .trim_end_matches('.')
        .split('.')
        .map(|p| p.parse::<u32>().ok())
        .collect();
    parts.filter(|p| p.len() >= 2 && p.len() <= 4)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub service: String,
    pub declared_image: String,
    pub image_id: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageFacts {
    pub platform: String,
    pub digests: Vec<String>,
    /// `org.opencontainers.image.version`.
    pub label_version: Option<String>,
    /// The image's `KEY=value` environment entries (only the version keys are kept).
    pub env: Vec<(String, String)>,
}

pub trait Inventory {
    fn services(&self) -> Result<Vec<Service>, Unavailable>;
    fn image(&self, image_id: &str) -> Result<ImageFacts, Unavailable>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    /// The container already runs the candidate digest.
    UpToDate,
    /// Same major.minor, a higher patch (or a rebuild of the same version).
    PatchPending,
    /// The candidate is another major.minor line: never applied as a patch.
    MinorOrMajor,
    /// Not provable (see `reason`).
    Unknown,
    /// Not an image the engine's catalog owns.
    Manual,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub service: String,
    pub kind: Option<&'static str>,
    pub container_status: String,
    pub declared_image: String,
    pub platform: Option<String>,
    pub digests: Vec<String>,
    pub running_version: Option<String>,
    pub candidate_version: Option<String>,
    pub status: Status,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PatchStatus {
    /// `ok`, or `unavailable` when Docker could not list the stack (then there
    /// are no rows and nothing is claimed).
    pub inventory: &'static str,
    pub services: Vec<Row>,
}

const KINDS: [&str; 5] = ["frankenphp", "mariadb", "valkey", "postgres", "meilisearch"];

fn kind_of(declared_image: &str) -> Option<&'static str> {
    let rest = declared_image.strip_prefix(IMAGE_PREFIX)?;
    let name = rest.split([':', '@']).next()?;
    KINDS.iter().copied().find(|k| *k == name)
}

fn version_env(kind: &str) -> &'static str {
    match kind {
        "frankenphp" => "PHP_VERSION",
        "mariadb" => "MARIADB_VERSION",
        "valkey" => "VALKEY_VERSION",
        "postgres" => "PG_VERSION",
        _ => "MEILI_VERSION",
    }
}

fn running_version(kind: &str, facts: &ImageFacts) -> Option<String> {
    let env = facts
        .env
        .iter()
        .find(|(k, _)| k == version_env(kind))
        .map(|(_, v)| v.as_str());
    let from_label = facts
        .label_version
        .as_deref()
        .filter(|v| parse_version(v).is_some());
    let raw = from_label.or(env.filter(|v| parse_version(v).is_some()))?;
    let parts = parse_version(raw)?;
    Some(
        parts
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// How many leading version components name the release line. PostgreSQL
/// numbers its minor releases `18.1`, `18.2`: they are patches of line `18`.
fn line_len(kind: &str) -> usize {
    if kind == "postgres" { 1 } else { 2 }
}

fn judge(
    kind: &str,
    running: Option<&Vec<u32>>,
    facts: &ImageFacts,
    candidate: Option<&Candidate>,
) -> (Status, &'static str) {
    let Some(candidate) = candidate else {
        return (Status::Unknown, "noCandidate");
    };
    let Some(digest) = candidate.digest.as_deref() else {
        return (Status::Unknown, "candidateDigestMissing");
    };
    if facts.digests.iter().any(|d| d == digest) {
        return (Status::UpToDate, "digestMatches");
    }
    let Some(running) = running else {
        return (Status::Unknown, "runningVersionUnknown");
    };
    let Some(candidate_version) = candidate
        .resolved_version
        .as_deref()
        .and_then(parse_version)
    else {
        return (Status::Unknown, "candidateVersionUnknown");
    };
    if candidate_version.len() < 2 || running.len() < 2 {
        return (Status::Unknown, "candidateVersionUnknown");
    }
    let line = line_len(kind);
    if candidate_version[..line] != running[..line] {
        return if candidate_version[..line] > running[..line] {
            (Status::MinorOrMajor, "differentLine")
        } else {
            (Status::Unknown, "candidateOlder")
        };
    }
    match candidate_version.cmp(running) {
        std::cmp::Ordering::Greater => (Status::PatchPending, "newerPatch"),
        std::cmp::Ordering::Equal => (Status::PatchPending, "sameVersionNewImage"),
        std::cmp::Ordering::Less => (Status::Unknown, "candidateOlder"),
    }
}

pub fn evaluate(docker: &dyn Inventory, request: &Request) -> PatchStatus {
    let mut result = PatchStatus {
        inventory: "ok",
        services: Vec::new(),
    };
    let Ok(services) = docker.services() else {
        result.inventory = "unavailable";
        return result;
    };
    for service in services.into_iter().take(MAX_SERVICES) {
        let kind = kind_of(&service.declared_image);
        let facts = docker.image(&service.image_id).ok();
        let candidate = request
            .candidates
            .iter()
            .find(|c| c.service == service.service);
        let version = kind
            .zip(facts.as_ref())
            .and_then(|(k, f)| running_version(k, f));
        let parsed = version.as_deref().and_then(parse_version);
        let (status, reason) = match (kind, facts.as_ref()) {
            (None, _) => (Status::Manual, "notManagedImage"),
            (Some(_), None) => (Status::Unknown, "imageUnreadable"),
            (Some(kind), Some(facts)) => judge(kind, parsed.as_ref(), facts, candidate),
        };
        result.services.push(Row {
            service: service.service,
            kind,
            container_status: service.status,
            declared_image: service.declared_image,
            platform: facts.as_ref().map(|f| f.platform.clone()),
            digests: facts.map(|f| f.digests).unwrap_or_default(),
            running_version: version,
            candidate_version: candidate.and_then(|c| c.resolved_version.clone()),
            status,
            reason,
        });
    }
    result
}

// ---- Docker ------------------------------------------------------------------------

fn parse_services(bytes: &[u8]) -> Option<Vec<Service>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let mut out = Vec::new();
    for item in value.as_array()? {
        let text = |pointer: &str| item.pointer(pointer).and_then(|v| v.as_str());
        let Some(service) = text("/Config/Labels/com.docker.compose.service") else {
            continue;
        };
        if !service_ok(service) {
            continue;
        }
        let image_id = text("/Image")?;
        if !crate::security_affected::image_id_ok(image_id) {
            return None;
        }
        out.push(Service {
            service: service.to_owned(),
            declared_image: text("/Config/Image")?.chars().take(300).collect(),
            image_id: image_id.to_owned(),
            status: text("/State/Status")?.chars().take(32).collect(),
        });
    }
    out.sort_by(|a, b| a.service.cmp(&b.service));
    Some(out)
}

fn parse_image(bytes: &[u8]) -> Option<ImageFacts> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let image = value.as_array()?.first()?;
    let os = image.get("Os")?.as_str()?;
    let arch = image.get("Architecture")?.as_str()?;
    let digests = image
        .get("RepoDigests")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str()?.split_once('@'))
                .map(|(_, digest)| digest.to_owned())
                .filter(|d| digest_ok(d))
                .collect()
        })
        .unwrap_or_default();
    let label_version = image
        .pointer("/Config/Labels/org.opencontainers.image.version")
        .and_then(|v| v.as_str())
        .map(|v| v.chars().take(64).collect());
    let env = image
        .pointer("/Config/Env")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str()?.split_once('='))
                .filter(|(k, _)| {
                    matches!(
                        *k,
                        "PHP_VERSION"
                            | "MARIADB_VERSION"
                            | "VALKEY_VERSION"
                            | "PG_VERSION"
                            | "MEILI_VERSION"
                    )
                })
                .map(|(k, v)| (k.to_owned(), v.chars().take(64).collect()))
                .collect()
        })
        .unwrap_or_default();
    Some(ImageFacts {
        platform: format!("{os}/{arch}"),
        digests,
        label_version,
        env,
    })
}

impl Inventory for Docker<'_> {
    fn services(&self) -> Result<Vec<Service>, Unavailable> {
        let ids = self.run(&["ps", "-aq", "--filter", MANAGED_PROJECT_LABEL])?;
        let ids = String::from_utf8(ids).map_err(|_| Unavailable)?;
        let ids: Vec<&str> = ids.split_whitespace().collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids
            .iter()
            .any(|id| id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Unavailable);
        }
        let mut args = vec!["inspect", "--type", "container"];
        args.extend(ids);
        parse_services(&self.run(&args)?).ok_or(Unavailable)
    }

    fn image(&self, image_id: &str) -> Result<ImageFacts, Unavailable> {
        if !crate::security_affected::image_id_ok(image_id) {
            return Err(Unavailable);
        }
        parse_image(&self.run(&["image", "inspect", image_id])?).ok_or(Unavailable)
    }
}

#[cfg(test)]
mod tests;
