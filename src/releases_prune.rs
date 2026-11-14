//! `releases.prune`: deletes old release directories of an engine-deployed
//! site (`sites/<siteId>/releases/<releaseId>`), in two steps.
//!
//! - **Preview** (no confirmations): lists what a delete would remove, with
//!   sizes, and why every other release is kept. It never changes anything.
//! - **Delete** (one exact confirmation per directory): removes exactly the
//!   named directories, and only when each one is still an old release.
//!
//! What is never a candidate: the release `current` points at, the newest
//! `keepReleases` releases of the site manifest (default 5, the value deploy
//! and rollback already use for their own retention), and any release a
//! deploy or rollback checkpoint still names (the rollback target). Anything
//! that does not look like a release directory (a name that is not a
//! canonical UUID, a symlink, a plain file) is left alone and only counted.
//!
//! Safety:
//!
//! - The releases directory is reached by descending `sites`, `<siteId>`,
//!   `releases` one capability-scoped, no-follow step at a time, so a symlink
//!   anywhere on the way (or as the directory itself) is refused instead of
//!   followed. Entries are never opened through a path, only by name inside
//!   that directory, and sizes are measured without following links.
//! - An unfinished deploy or rollback, an unreadable `current`, an unreadable
//!   checkpoint or a missing active directory refuses the whole request: a
//!   state the engine cannot read is not guessed.
//! - Delete takes the site's mutation lock (the one deploy and rollback hold),
//!   recomputes the plan under it, validates every confirmation before it
//!   removes anything, and is idempotent: a confirmed directory that is
//!   already gone is reported as absent, and the same idempotency key replays
//!   the recorded result.

use std::{
    collections::HashSet,
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use cap_std::fs::MetadataExt;
use serde::{Deserialize, Serialize};

use crate::{
    config::SiteManifest,
    deploy::{ReleaseId, activate},
    deployment_recovery,
    error::ErrorCode,
    filesystem::ManagedRoot,
    mutation::preflight,
    site::{SiteId, SiteRelativePath, TrustedRoot},
    transaction::{
        IdempotencyKey, RequestId,
        audit::{self, AuditRecord},
        lock,
        state::{self, TransactionStatus},
    },
};

pub const OPERATION: &str = "releases.prune";

/// Most confirmations one request may carry.
pub const MAX_CONFIRMATIONS: usize = 100;
/// Most entries the releases directory may hold before the engine refuses to
/// guess about it.
const MAX_ENTRIES: usize = 2000;
/// Bounds of the size measurement; past them the size is reported unknown.
const MAX_WALK_ENTRIES: u64 = 2_000_000;
const MAX_WALK_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidSiteId,
    InvalidRelease,
    TooManyConfirmations,
    DuplicateConfirmation,
    InvalidRequestId,
    InvalidIdempotencyKey,
}

impl RequestError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidSiteId => "site-id is not a canonical UUID",
            Self::InvalidRelease => "confirm must be the exact name of a release directory",
            Self::TooManyConfirmations => "too many release directories in one request",
            Self::DuplicateConfirmation => "a release directory is confirmed twice",
            Self::InvalidRequestId => "request-id is not a canonical UUID",
            Self::InvalidIdempotencyKey => "idempotency-key is invalid",
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub site_id: SiteId,
    /// Exact directory names to delete. Empty means preview.
    pub confirm: Vec<ReleaseId>,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

impl Request {
    pub fn parse(
        site_id: &str,
        confirm: &[String],
        request_id: &str,
        idempotency_key: Option<&str>,
    ) -> Result<Self, RequestError> {
        if confirm.len() > MAX_CONFIRMATIONS {
            return Err(RequestError::TooManyConfirmations);
        }
        let mut seen = HashSet::new();
        let mut names = Vec::new();
        for name in confirm {
            let release = ReleaseId::parse(name).map_err(|_| RequestError::InvalidRelease)?;
            if !seen.insert(release) {
                return Err(RequestError::DuplicateConfirmation);
            }
            names.push(release);
        }
        Ok(Self {
            site_id: SiteId::parse(site_id).map_err(|_| RequestError::InvalidSiteId)?,
            confirm: names,
            request_id: RequestId::parse(request_id).map_err(|_| RequestError::InvalidRequestId)?,
            idempotency_key: idempotency_key
                .map(IdempotencyKey::parse)
                .transpose()
                .map_err(|_| RequestError::InvalidIdempotencyKey)?,
        })
    }

    pub fn is_preview(&self) -> bool {
        self.confirm.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseEntry {
    pub release_id: ReleaseId,
    pub modified_at_unix_secs: u64,
    /// Disk usage, `None` when it could not be measured.
    pub size_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeepReason {
    /// The release `current` points at.
    Active,
    /// Among the newest `keepReleases`.
    Newest,
    /// Named by a deploy or rollback checkpoint (the rollback target).
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeptEntry {
    pub release_id: ReleaseId,
    pub reason: KeepReason,
}

/// The `result` of a preview.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewResult {
    pub keep_releases: usize,
    pub active_release_id: Option<ReleaseId>,
    /// Old releases a delete may remove, newest first. Each needs its own
    /// exact confirmation.
    pub candidates: Vec<ReleaseEntry>,
    pub kept: Vec<KeptEntry>,
    /// Entries of the releases directory that are not release directories
    /// (other names, symlinks, files); never touched.
    pub ignored_entries: u32,
    /// Sum of the candidate sizes, `None` when any is unknown.
    pub total_bytes: Option<u64>,
}

/// The `result` of a delete.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneResult {
    pub keep_releases: usize,
    pub removed: Vec<ReleaseId>,
    /// Confirmed directories that were already gone.
    pub already_absent: Vec<ReleaseId>,
    /// Sum of what was removed, `None` when any size is unknown.
    pub freed_bytes: Option<u64>,
    pub completed_at_unix_secs: u64,
}

pub struct Context<'a> {
    pub content_root: &'a TrustedRoot,
    pub engine_state: &'a ManagedRoot,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The manifest's `contentRoot` is not the standard `sites/<id>/current`.
    ContentRootMismatch,
    Preflight(preflight::Error),
    Recovery(deployment_recovery::Error),
    /// The releases tree, `current` or a release directory cannot be read as
    /// the engine expects, so nothing is decided.
    Unreadable,
    /// `current` is missing, not a release link, or its release is not in
    /// the releases directory.
    NoActiveRelease,
    /// A confirmed directory is not an old release that may be deleted (it
    /// is active, newest, a rollback target or not a release directory).
    NotEligible,
    ReplayInProgress,
    State(state::StateError),
    PostCommit {
        result: PruneResult,
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
                "another mutation is already in progress for this site".into(),
            ),
            Self::Recovery(error) => error.protocol(),
            Self::Unreadable => (
                ErrorCode::Conflict,
                "the site's releases could not be read safely; nothing was changed".into(),
            ),
            Self::NoActiveRelease => (
                ErrorCode::Conflict,
                "the active release could not be determined; nothing was changed".into(),
            ),
            Self::NotEligible => (
                ErrorCode::Conflict,
                "a confirmed directory is not an old release that can be deleted; nothing was changed"
                    .into(),
            ),
            Self::ReplayInProgress => (
                ErrorCode::Conflict,
                "the original request for this idempotency key is still in progress".into(),
            ),
            Self::Replayed { code, message } => (*code, message.clone()),
            Self::Io(_)
            | Self::ContentRootMismatch
            | Self::Preflight(_)
            | Self::State(_)
            | Self::PostCommit { .. } => (ErrorCode::Internal, "internal releases error".into()),
        }
    }
}

struct Candidate {
    id: ReleaseId,
    modified: u64,
    /// Full resolution, so releases created within one second still order.
    modified_nanos: u128,
}

struct Listing {
    active: ReleaseId,
    candidates: Vec<Candidate>,
    kept: Vec<KeptEntry>,
    ignored: u32,
    /// Names of release directories that exist but are not candidates.
    existing: HashSet<ReleaseId>,
}

/// Opens `sites/<siteId>/releases` one no-follow step at a time. `None` when
/// a step does not exist; any symlink or non-directory on the way is an error.
fn open_releases(content: &TrustedRoot, site_id: SiteId) -> Result<Option<ManagedRoot>, Error> {
    let mut dir = ManagedRoot::open(content).map_err(Error::Io)?;
    for step in [
        "sites".to_owned(),
        site_id.to_string(),
        "releases".to_owned(),
    ] {
        let name = SiteRelativePath::parse(step).expect("literal path components are valid");
        dir = match dir.open_child_dir_nofollow(&name) {
            Ok(next) => next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Unreadable),
        };
    }
    Ok(Some(dir))
}

fn name_path(id: ReleaseId) -> SiteRelativePath {
    SiteRelativePath::parse(id.to_string()).expect("a canonical ReleaseId is a valid component")
}

fn listing(
    content: &TrustedRoot,
    scope: &ManagedRoot,
    site_id: SiteId,
    keep: usize,
) -> Result<(Option<ManagedRoot>, Option<Listing>), Error> {
    let Some(releases) = open_releases(content, site_id)? else {
        // No releases directory: nothing to prune, nothing to guess.
        return Ok((None, None));
    };
    let active = activate::current_release(content, site_id)
        .map_err(|_| Error::NoActiveRelease)?
        .ok_or(Error::NoActiveRelease)?;
    let referenced: HashSet<ReleaseId> = deployment_recovery::referenced_releases(scope)
        .map_err(Error::Recovery)?
        .into_iter()
        .collect();

    let children = releases
        .child_entries_bounded(MAX_ENTRIES)
        .map_err(|_| Error::Unreadable)?;
    let mut ignored = 0u32;
    let mut releases_found: Vec<Candidate> = Vec::new();
    for child in children {
        let id = child
            .name
            .to_str()
            .and_then(|name| ReleaseId::parse(name).ok());
        let Some(id) = id.filter(|_| child.is_dir) else {
            ignored += 1;
            continue;
        };
        let metadata = releases
            .symlink_metadata(&name_path(id))
            .map_err(|_| Error::Unreadable)?;
        let age = metadata
            .modified()
            .map_err(|_| Error::Unreadable)?
            .into_std()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unreadable)?;
        releases_found.push(Candidate {
            id,
            modified: age.as_secs(),
            modified_nanos: age.as_nanos(),
        });
    }
    // Newest first; the name breaks ties so the order is stable.
    releases_found.sort_by(|a, b| {
        b.modified_nanos
            .cmp(&a.modified_nanos)
            .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
    });
    if !releases_found.iter().any(|release| release.id == active) {
        return Err(Error::NoActiveRelease);
    }

    let mut candidates = Vec::new();
    let mut kept = Vec::new();
    let mut existing = HashSet::new();
    for (index, release) in releases_found.into_iter().enumerate() {
        existing.insert(release.id);
        let reason = if release.id == active {
            Some(KeepReason::Active)
        } else if index < keep {
            Some(KeepReason::Newest)
        } else if referenced.contains(&release.id) {
            Some(KeepReason::Rollback)
        } else {
            None
        };
        match reason {
            Some(reason) => kept.push(KeptEntry {
                release_id: release.id,
                reason,
            }),
            None => candidates.push(release),
        }
    }
    Ok((
        Some(releases),
        Some(Listing {
            active,
            candidates,
            kept,
            ignored,
            existing,
        }),
    ))
}

fn disk_bytes(metadata: &cap_std::fs::Metadata) -> u64 {
    metadata.blocks().saturating_mul(512)
}

/// Disk usage of one release directory, never following a link. `None` when
/// a bound is hit or something cannot be read.
fn tree_bytes(dir: &ManagedRoot, depth: usize, budget: &mut u64) -> Option<u64> {
    if depth > MAX_WALK_DEPTH {
        return None;
    }
    let mut total = disk_bytes(&dir.own_metadata().ok()?);
    for child in dir.child_entries().ok()? {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let name = SiteRelativePath::parse(&child.name).ok()?;
        total = total.saturating_add(disk_bytes(&dir.symlink_metadata(&name).ok()?));
        if child.is_dir {
            let inner = dir.open_child_dir_nofollow(&name).ok()?;
            total = total.saturating_add(tree_bytes(&inner, depth + 1, budget)?);
        }
    }
    Some(total)
}

fn release_size(releases: &ManagedRoot, id: ReleaseId) -> Option<u64> {
    let dir = releases.open_child_dir_nofollow(&name_path(id)).ok()?;
    tree_bytes(&dir, 0, &mut MAX_WALK_ENTRIES.clone())
}

fn sum(mut sizes: impl Iterator<Item = Option<u64>>) -> Option<u64> {
    sizes.try_fold(0u64, |total, size| size.map(|s| total.saturating_add(s)))
}

fn check_manifest(manifest: &SiteManifest, site_id: SiteId) -> Result<(), Error> {
    let expected = SiteRelativePath::parse(format!("sites/{site_id}/current"))
        .expect("a canonical SiteId always yields a valid relative path");
    if manifest.site_id != site_id || manifest.content_root != expected {
        return Err(Error::ContentRootMismatch);
    }
    Ok(())
}

/// What a delete would remove. Takes the site lock for a consistent read and
/// writes nothing but the lock file.
pub fn preview(
    context: &Context<'_>,
    manifest: &SiteManifest,
    request: &Request,
) -> Result<PreviewResult, Error> {
    check_manifest(manifest, request.site_id)?;
    let scope =
        preflight::open_site_state(context.engine_state, request.site_id).map_err(Error::Io)?;
    let _guard = lock::acquire(&scope, &preflight::lock_path(), request.request_id)
        .map_err(|error| Error::Preflight(preflight::Error::Lock(error)))?;
    let (releases, listing) = listing(
        context.content_root,
        &scope,
        request.site_id,
        manifest.keep_releases,
    )?;
    let (Some(releases), Some(listing)) = (releases, listing) else {
        return Ok(PreviewResult {
            keep_releases: manifest.keep_releases,
            active_release_id: None,
            candidates: Vec::new(),
            kept: Vec::new(),
            ignored_entries: 0,
            total_bytes: Some(0),
        });
    };
    let candidates: Vec<ReleaseEntry> = listing
        .candidates
        .iter()
        .map(|candidate| ReleaseEntry {
            release_id: candidate.id,
            modified_at_unix_secs: candidate.modified,
            size_bytes: release_size(&releases, candidate.id),
        })
        .collect();
    Ok(PreviewResult {
        keep_releases: manifest.keep_releases,
        active_release_id: Some(listing.active),
        total_bytes: sum(candidates.iter().map(|entry| entry.size_bytes)),
        candidates,
        kept: listing.kept,
        ignored_entries: listing.ignored,
    })
}

/// Deletes exactly the confirmed old release directories.
pub fn execute(
    context: &Context<'_>,
    manifest: &SiteManifest,
    request: &Request,
) -> Result<PruneResult, Error> {
    check_manifest(manifest, request.site_id)?;
    let site_state =
        preflight::open_site_state(context.engine_state, request.site_id).map_err(Error::Io)?;
    let admitted = match preflight::run(
        &site_state,
        request.request_id,
        request.idempotency_key.as_ref(),
        OPERATION,
    )
    .map_err(Error::Preflight)?
    {
        preflight::Outcome::Replay(original) => return replay(&site_state, original),
        preflight::Outcome::Proceed(admitted) => admitted,
    };
    let preflight::Admitted { lock, mut state } = admitted;
    let state_path = state_path_for(request.request_id);
    let audit_path = audit_log_path();

    let outcome = remove_confirmed(context, manifest, request, &site_state);
    match outcome {
        Err(error) => {
            let (code, message) = error.protocol();
            let _ = state.mark_failed(code, message);
            let _ = state::save(&site_state, &state_path, &state);
            let _ = audit::append(
                &site_state,
                &audit_path,
                &AuditRecord::result(request.request_id, false, Some(code)),
            );
            Err(error)
        }
        Ok(result) => {
            let value = serde_json::to_value(&result).expect("PruneResult always serializes");
            state
                .mark_committed(value)
                .expect("state is always InProgress at this point");
            if let Err(cause) = state::save(&site_state, &state_path, &state) {
                let _ = cause;
                return Err(Error::PostCommit { result });
            }
            let _ = audit::append(
                &site_state,
                &audit_path,
                &AuditRecord::result(request.request_id, true, None),
            );
            drop(lock);
            Ok(result)
        }
    }
}

fn remove_confirmed(
    context: &Context<'_>,
    manifest: &SiteManifest,
    request: &Request,
    scope: &ManagedRoot,
) -> Result<PruneResult, Error> {
    let (releases, listing) = listing(
        context.content_root,
        scope,
        request.site_id,
        manifest.keep_releases,
    )?;
    let candidates: HashSet<ReleaseId> = listing
        .as_ref()
        .map(|listing| listing.candidates.iter().map(|c| c.id).collect())
        .unwrap_or_default();
    let existing = listing
        .as_ref()
        .map(|listing| &listing.existing)
        .cloned()
        .unwrap_or_default();

    // Validate every confirmation before anything is removed. A name that is
    // not a release directory at all is "already absent" only when nothing of
    // that name is there; a symlink or file of that name is refused.
    let mut to_remove = Vec::new();
    let mut absent = Vec::new();
    for id in &request.confirm {
        if candidates.contains(id) {
            to_remove.push(*id);
        } else if existing.contains(id) {
            return Err(Error::NotEligible);
        } else if let Some(releases) = &releases {
            match releases.symlink_metadata(&name_path(*id)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => absent.push(*id),
                _ => return Err(Error::NotEligible),
            }
        } else {
            absent.push(*id);
        }
    }

    let mut removed = Vec::new();
    let mut sizes = Vec::new();
    if let Some(releases) = &releases {
        for id in to_remove {
            let path = name_path(id);
            let size = release_size(releases, id);
            // The directory could have been swapped for a link since the
            // listing; a link is never removed through this operation.
            let metadata = releases.symlink_metadata(&path).map_err(Error::Io)?;
            if !metadata.is_dir() {
                return Err(Error::NotEligible);
            }
            releases.remove_dir_all(&path).map_err(Error::Io)?;
            sizes.push(size);
            removed.push(id);
        }
    }
    Ok(PruneResult {
        keep_releases: manifest.keep_releases,
        removed,
        already_absent: absent,
        freed_bytes: sum(sizes.into_iter()),
        completed_at_unix_secs: unix_now_secs(),
    })
}

fn replay(site_state: &ManagedRoot, original: RequestId) -> Result<PruneResult, Error> {
    let record = state::load(site_state, &state_path_for(original)).map_err(Error::State)?;
    match record.status {
        TransactionStatus::InProgress => Err(Error::ReplayInProgress),
        TransactionStatus::Committed => {
            let value = record
                .outcome
                .and_then(|outcome| outcome.result)
                .ok_or(Error::State(state::StateError::Corrupt))?;
            serde_json::from_value(value).map_err(|_| Error::State(state::StateError::Corrupt))
        }
        TransactionStatus::Failed => {
            let outcome = record
                .outcome
                .ok_or(Error::State(state::StateError::Corrupt))?;
            Err(Error::Replayed {
                code: outcome.error_code.unwrap_or(ErrorCode::Internal),
                message: outcome.error_message.unwrap_or_default(),
            })
        }
    }
}

fn state_path_for(request_id: RequestId) -> SiteRelativePath {
    SiteRelativePath::parse(format!("transactions/{request_id}.json"))
        .expect("a canonical RequestId always yields a valid relative path")
}

fn audit_log_path() -> SiteRelativePath {
    SiteRelativePath::parse("audit/events.jsonl").expect("literal path is valid")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(test, unix))]
mod tests;
