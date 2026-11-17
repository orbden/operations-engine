//! Durable evidence for `backup.activateConfig`: what the live files and the
//! root crontab were before the request touched them, written to the engine
//! state (root-only) before the first live write, so a crash at any point can
//! be rolled back by `backup.recoverConfig` instead of leaving a mixed
//! configuration. The previous contents may hold remote credentials, so they
//! live only under the engine's state root, owner-only, and never in the
//! staging directory beside the live files.
//!
//! Layout below the `backup-activate` scope: `recovery/<request id>/` with
//! `journal.json` and `prev/<n>` (the previous content of artifact `n` of
//! [`ARTIFACTS`]) plus `prev/crontab`. The journal is written last in each
//! step, so its phase never claims more than what is on disk.

use serde::{Deserialize, Serialize};

use crate::{
    backup_deploy::ARTIFACTS, filesystem::ManagedRoot, site::SiteRelativePath,
    transaction::RequestId,
};

/// How far the activation got when the journal was last written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    /// Nothing live has been touched yet.
    Begin,
    /// The previous files and crontab are saved; live files may be changing.
    Files,
    /// The files are replaced; the crontab install is about to start or ran.
    Crontab,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PreviousFile {
    pub existed: bool,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Journal {
    pub request_id: RequestId,
    pub phase: Phase,
    /// One entry per [`ARTIFACTS`] item once the previous state is saved.
    pub files: Vec<PreviousFile>,
    /// Whether root had a crontab before; its text is `prev/crontab`.
    pub crontab_existed: Option<bool>,
}

fn rel(path: impl AsRef<str>) -> SiteRelativePath {
    SiteRelativePath::parse(path.as_ref()).expect("a fixed or validated relative path")
}

fn directory(id: RequestId) -> String {
    format!("recovery/{id}")
}

pub fn journal_path(id: RequestId) -> SiteRelativePath {
    rel(format!("{}/journal.json", directory(id)))
}

pub fn previous_path(id: RequestId, name: &str) -> SiteRelativePath {
    rel(format!("{}/prev/{name}", directory(id)))
}

fn write_journal(evidence: &ManagedRoot, journal: &Journal) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(journal).expect("the journal serializes");
    let path = journal_path(journal.request_id);
    evidence.write_atomic(&path, &bytes)?;
    evidence.set_mode(&path, 0o600)
}

/// Opens the evidence for a request, before anything live is touched.
pub fn begin(evidence: &ManagedRoot, id: RequestId) -> std::io::Result<()> {
    evidence.create_dir_all(&rel(format!("{}/prev", directory(id))))?;
    write_journal(
        evidence,
        &Journal {
            request_id: id,
            phase: Phase::Begin,
            files: Vec::new(),
            crontab_existed: None,
        },
    )
}

/// Saves the live files and crontab as they are now. Must be called after
/// [`begin`] and before the first live write.
pub fn record_previous(
    evidence: &ManagedRoot,
    id: RequestId,
    config_root: &ManagedRoot,
    crontab: Option<&[u8]>,
) -> std::io::Result<()> {
    let mut files = Vec::with_capacity(ARTIFACTS.len());
    for (index, artifact) in ARTIFACTS.iter().enumerate() {
        let live = rel(artifact.relative_path);
        if config_root.exists(&live) {
            let content = config_root.read_bytes(&live)?;
            let mode = config_root.mode(&live)?;
            let saved = previous_path(id, &index.to_string());
            evidence.write_atomic(&saved, &content)?;
            evidence.set_mode(&saved, 0o600)?;
            files.push(PreviousFile {
                existed: true,
                mode: Some(mode),
            });
        } else {
            files.push(PreviousFile {
                existed: false,
                mode: None,
            });
        }
    }
    if let Some(tab) = crontab {
        let saved = previous_path(id, "crontab");
        evidence.write_atomic(&saved, tab)?;
        evidence.set_mode(&saved, 0o600)?;
    }
    write_journal(
        evidence,
        &Journal {
            request_id: id,
            phase: Phase::Files,
            files,
            crontab_existed: Some(crontab.is_some()),
        },
    )
}

/// Moves the journal to `phase` (keeps everything else).
pub fn set_phase(evidence: &ManagedRoot, id: RequestId, phase: Phase) -> std::io::Result<()> {
    let mut journal = load(evidence, id)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no activation journal")
    })?;
    journal.phase = phase;
    write_journal(evidence, &journal)
}

pub fn load(evidence: &ManagedRoot, id: RequestId) -> std::io::Result<Option<Journal>> {
    let path = journal_path(id);
    if !evidence.exists(&path) {
        return Ok(None);
    }
    let bytes = evidence.read_bytes(&path)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Removes the evidence once the request is committed or rolled back.
pub fn discard(evidence: &ManagedRoot, id: RequestId) -> std::io::Result<()> {
    match evidence.remove_dir_all(&rel(directory(id))) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}
