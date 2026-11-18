//! Immutable database/snapshot evidence for explicit content recovery.
use crate::util::sha256_reader;
use crate::{
    filesystem::ManagedRoot,
    process::{self, CancellationToken, ProcessLimits, ProcessRequest, ProcessTermination},
    site::SiteRelativePath,
};
use std::{
    fs::File,
    io::{self, Read},
};
pub fn container_id(docker: &str, name: &str) -> io::Result<String> {
    let out = process::run(
        &ProcessRequest::new(docker).args(["inspect", "--format", "{{.Id}}", name]),
        &ProcessLimits {
            max_stdout_bytes: 128,
            ..ProcessLimits::default()
        },
        &CancellationToken::default(),
    )
    .map_err(|_| io::Error::other("container identity unavailable"))?;
    let id = out.stdout.text().trim().to_owned();
    if !matches!(
        out.termination,
        ProcessTermination::Exited { success: true, .. }
    ) || out.stdout.truncated
        || id.len() != 64
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(io::Error::other("invalid immutable container identity"));
    }
    Ok(id)
}
pub fn digest(file: File) -> io::Result<String> {
    Ok(sha256_reader(file)?.1)
}
pub fn record(
    scope: &ManagedRoot,
    marker: &SiteRelativePath,
    dumps: &ManagedRoot,
    snapshot: &SiteRelativePath,
    name: &str,
    id: &str,
) -> io::Result<()> {
    let mut bytes = Vec::new();
    scope
        .open_regular_read(marker)?
        .take(16385)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(io::Error::other("checkpoint too large"));
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid checkpoint"))?;
    let file = dumps.open_regular_read(snapshot)?;
    file.sync_all()?;
    value["databaseContainer"] = name.into();
    value["databaseContainerId"] = id.into();
    value["databaseSnapshotSha256"] = digest(file)?.into();
    value["recoveryEvidenceVersion"] = 1.into();
    value["mutationStarted"] = false.into();
    scope.write_atomic_private(
        marker,
        &serde_json::to_vec(&value).map_err(|_| io::Error::other("invalid checkpoint"))?,
    )?;
    sync_parent(scope, marker)?;
    sync_parent(dumps, snapshot)
}
pub fn mutation_started(scope: &ManagedRoot, marker: &SiteRelativePath) -> io::Result<()> {
    let mut bytes = Vec::new();
    scope
        .open_regular_read(marker)?
        .take(16385)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(io::Error::other("checkpoint too large"));
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid checkpoint"))?;
    value["mutationStarted"] = true.into();
    scope.write_atomic_private(
        marker,
        &serde_json::to_vec(&value).map_err(|_| io::Error::other("invalid checkpoint"))?,
    )?;
    sync_parent(scope, marker)
}
fn sync_parent(root: &ManagedRoot, path: &SiteRelativePath) -> io::Result<()> {
    match path
        .as_path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        Some(parent) => root
            .open_managed_dir(
                &SiteRelativePath::parse(parent)
                    .map_err(|_| io::Error::other("invalid checkpoint parent"))?,
            )?
            .sync_all(),
        None => root.sync_all(),
    }
}
