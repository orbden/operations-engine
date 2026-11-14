//! End-to-end test for `releases.prune` against real deploys and a real
//! rollback: four releases are deployed from a local Git remote, the site is
//! rolled back to the oldest, and the prune preview and delete must keep the
//! active release and the rollback bookkeeping, remove only what was
//! confirmed, and refuse a symlink planted in the releases directory.

use std::process::Command;

use operations_engine::{
    config::SiteManifest,
    deploy::{self, ReleaseId, execute::DeployContext},
    filesystem::ManagedRoot,
    process::CancellationToken,
    releases_prune::{self, Context, Request},
    rollback::{
        RollbackRequest,
        execute::{RollbackContext, execute as rollback},
    },
    site::{SiteId, TrustedRoot},
};

const SITE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const CREDENTIAL_ID: &str = "00000000-0000-0000-0000-000000000001";

struct Remote {
    _dir: tempfile::TempDir,
    url: String,
    branch: String,
    /// The first commit's SHA. Deploying this one happens while it is
    /// still the branch tip (see `advance`), since `deploy::resolve`
    /// authorizes only the *current* tip of an allowed branch.
    first_commit: String,
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("git should run");
    assert!(status.success(), "git {args:?} should succeed");
}

fn head(dir: &std::path::Path) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse should run");
    String::from_utf8(output.stdout)
        .expect("HEAD SHA should be UTF-8")
        .trim()
        .to_owned()
}

/// A local "remote" with one commit on its default branch. Deploy a second
/// commit onto it later via `advance`, once the first has already been
/// deployed while it was still the tip — `deploy::resolve` only authorizes
/// a revision that is the branch's *current* tip, so both commits can never
/// be pre-created before either deploy.
fn local_remote() -> Remote {
    let dir = tempfile::tempdir().expect("remote directory should exist");
    git(dir.path(), &["init", "--quiet"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "first",
        ],
    );
    let first_commit = head(dir.path());

    let branch_output = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["symbolic-ref", "--short", "HEAD"])
        .output()
        .expect("git symbolic-ref should run");
    let branch = String::from_utf8(branch_output.stdout)
        .expect("branch name should be UTF-8")
        .trim()
        .to_owned();
    let url = dir
        .path()
        .to_str()
        .expect("path should be UTF-8")
        .to_owned();

    Remote {
        _dir: dir,
        url,
        branch,
        first_commit,
    }
}

/// Advances `remote`'s branch tip with a new commit and returns its SHA.
fn advance(remote: &Remote) -> String {
    git(
        remote._dir.path(),
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "next",
        ],
    );
    head(remote._dir.path())
}

fn current_username() -> String {
    let whoami = Command::new("whoami").output().expect("whoami should run");
    String::from_utf8(whoami.stdout)
        .expect("username should be UTF-8")
        .trim()
        .to_owned()
}

fn manifest_json(remote: &Remote) -> String {
    format!(
        r#"{{
          "schemaVersion": 1,
          "siteId": "{SITE_ID}",
          "domain": "example.com",
          "contentRoot": "sites/{SITE_ID}/current",
          "siteUser": "{user}",
          "repository": {{
            "url": "{url}",
            "allowedBranches": ["{branch}"],
            "credentialId": "{CREDENTIAL_ID}"
          }}
        }}"#,
        user = current_username(),
        url = remote.url,
        branch = remote.branch,
    )
}

struct Harness {
    _content_dir: tempfile::TempDir,
    _state_dir: tempfile::TempDir,
    _credential_dir: tempfile::TempDir,
    content_root: TrustedRoot,
    credential_root: TrustedRoot,
    engine_state: ManagedRoot,
}

fn harness() -> Harness {
    let content_dir = tempfile::tempdir().expect("content root should exist");
    let state_dir = tempfile::tempdir().expect("state root should exist");
    let credential_dir = tempfile::tempdir().expect("credential root should exist");
    let content_root =
        TrustedRoot::parse(content_dir.path()).expect("content root should be valid");
    let credential_root =
        TrustedRoot::parse(credential_dir.path()).expect("credential root should be valid");
    let state_root = TrustedRoot::parse(state_dir.path()).expect("state root should be valid");
    let engine_state = ManagedRoot::open(&state_root).expect("state root should open");

    Harness {
        _content_dir: content_dir,
        _state_dir: state_dir,
        _credential_dir: credential_dir,
        content_root,
        credential_root,
        engine_state,
    }
}

impl Harness {
    fn deploy_context(&self) -> DeployContext<'_> {
        DeployContext {
            content_root: &self.content_root,
            credential_root: &self.credential_root,
            engine_state: &self.engine_state,
        }
    }
}

fn site_id() -> SiteId {
    SiteId::parse(SITE_ID).expect("site id should be canonical")
}

/// Deploys `commit` with `request_id` and returns the resulting
/// `ReleaseId` (equal to `request_id` per `deploy::ReleaseId::from`).
fn deploy(harness: &Harness, manifest: &SiteManifest, commit: &str, request_id: &str) -> String {
    let request = deploy::DeployRequest::parse(SITE_ID, commit, request_id, None)
        .expect("deploy request should be valid");
    deploy::execute::execute(
        &harness.deploy_context(),
        manifest,
        &request,
        &CancellationToken::default(),
    )
    .expect("setup deploy should succeed");
    request_id.to_owned()
}

const RELEASES: [&str; 4] = [
    "123e4567-e89b-12d3-a456-426614174000",
    "9b2f1c34-5678-4abc-9def-0123456789ab",
    "9b2f1c34-5678-4abc-9def-0123456789ac",
    "9b2f1c34-5678-4abc-9def-0123456789ad",
];

fn prune_request(confirm: &[&str], id: &str) -> Request {
    let confirm: Vec<String> = confirm.iter().map(|name| (*name).to_owned()).collect();
    Request::parse(SITE_ID, &confirm, id, None).expect("request should be valid")
}

#[test]
fn prune_after_real_deploys_and_a_rollback_keeps_the_active_and_rollback_releases() {
    let remote = local_remote();
    let harness = harness();
    let manifest = SiteManifest::from_json_for_site(&manifest_json(&remote), site_id())
        .expect("manifest should be valid");
    // The same manifest with a lowered setting: keep the newest two.
    let keep_two = SiteManifest::from_json_for_site(
        &manifest_json(&remote).replace("\"siteUser\"", "\"keepReleases\": 2, \"siteUser\""),
        site_id(),
    )
    .expect("manifest should be valid");

    deploy(&harness, &manifest, &remote.first_commit, RELEASES[0]);
    for release in &RELEASES[1..] {
        let commit = advance(&remote);
        deploy(&harness, &manifest, &commit, release);
    }
    // Back to the oldest: the active release is now the oldest directory.
    let request = RollbackRequest::parse(
        SITE_ID,
        RELEASES[0],
        "00000000-0000-0000-0000-0000000000a1",
        None,
    )
    .expect("rollback request should be valid");
    rollback(
        &RollbackContext {
            content_root: &harness.content_root,
            engine_state: &harness.engine_state,
        },
        &manifest,
        &request,
        &CancellationToken::default(),
    )
    .expect("rollback should succeed");

    let context = Context {
        content_root: &harness.content_root,
        engine_state: &harness.engine_state,
    };
    let releases_dir = harness
        ._content_dir
        .path()
        .join(format!("sites/{SITE_ID}/releases"));
    let exists = |name: &str| releases_dir.join(name).is_dir();

    // Nothing to remove with the default of five.
    let none = releases_prune::preview(
        &context,
        &manifest,
        &prune_request(&[], "00000000-0000-0000-0000-0000000000b1"),
    )
    .expect("preview should work");
    assert!(none.candidates.is_empty());
    assert_eq!(
        none.active_release_id.map(|id| id.to_string()),
        Some(RELEASES[0].to_owned())
    );

    // Keep two: the active (oldest) and the rollback source (newest) stay.
    let preview = releases_prune::preview(
        &context,
        &keep_two,
        &prune_request(&[], "00000000-0000-0000-0000-0000000000b2"),
    )
    .expect("preview should work");
    let listed: Vec<String> = preview
        .candidates
        .iter()
        .map(|c| c.release_id.to_string())
        .collect();
    assert_eq!(listed, vec![RELEASES[1].to_owned()]);
    assert!(preview.candidates[0].size_bytes.is_some());
    assert!(
        RELEASES.iter().all(|name| exists(name)),
        "a preview never deletes"
    );

    // The active and the newest release cannot be confirmed.
    for (n, protected) in [RELEASES[0], RELEASES[3]].into_iter().enumerate() {
        let refused = releases_prune::execute(
            &context,
            &keep_two,
            &prune_request(
                &[protected],
                &format!("00000000-0000-0000-0000-0000000000c{n}"),
            ),
        )
        .expect_err("a protected release must be refused");
        assert_eq!(
            refused.protocol().0,
            operations_engine::error::ErrorCode::Conflict
        );
    }
    assert!(RELEASES.iter().all(|name| exists(name)));

    // A symlink with a release name in the releases directory is not followed.
    let outside = tempfile::tempdir().expect("outside directory should exist");
    std::fs::write(outside.path().join("precious.txt"), "keep").expect("file should be written");
    let trap = "9b2f1c34-5678-4abc-9def-0123456789ae";
    std::os::unix::fs::symlink(outside.path(), releases_dir.join(trap))
        .expect("link should be created");
    assert!(
        releases_prune::execute(
            &context,
            &keep_two,
            &prune_request(&[trap], "00000000-0000-0000-0000-0000000000b4")
        )
        .is_err()
    );
    assert!(outside.path().join("precious.txt").exists());

    // The confirmed old release goes; everything else stays; a repeat is a no-op.
    let done = releases_prune::execute(
        &context,
        &keep_two,
        &prune_request(&[RELEASES[1]], "00000000-0000-0000-0000-0000000000b5"),
    )
    .expect("delete should succeed");
    assert_eq!(
        done.removed
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec![RELEASES[1].to_owned()]
    );
    assert!(!exists(RELEASES[1]));
    assert!(exists(RELEASES[0]) && exists(RELEASES[2]) && exists(RELEASES[3]));
    let again = releases_prune::execute(
        &context,
        &keep_two,
        &prune_request(&[RELEASES[1]], "00000000-0000-0000-0000-0000000000b6"),
    )
    .expect("a repeat should succeed");
    assert!(again.removed.is_empty());
    assert_eq!(again.already_absent.len(), 1);

    // current still points at the oldest release and a rollback target remains.
    let target = std::fs::read_link(
        harness
            ._content_dir
            .path()
            .join(format!("sites/{SITE_ID}/current")),
    )
    .expect("current should be a symlink");
    assert_eq!(
        target,
        std::path::PathBuf::from(format!("releases/{}", RELEASES[0]))
    );
    let _ = ReleaseId::parse(RELEASES[0]).expect("release id should parse");
}
