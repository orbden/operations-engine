use std::{fs, os::unix::fs::symlink, path::Path};

use super::*;
use crate::{deploy::activate, transaction::state};

const SITE: &str = "550e8400-e29b-41d4-a716-446655440000";
const REQUEST: &str = "9b2f1c34-5678-4abc-9def-0123456789ab";
const REVISION: &str = "abcdef0123456789abcdef0123456789abcdef01";

struct Fixture {
    content_dir: tempfile::TempDir,
    _state_dir: tempfile::TempDir,
    content: TrustedRoot,
    state: ManagedRoot,
    site: SiteId,
}

fn release(n: u8) -> ReleaseId {
    ReleaseId::parse(&format!("123e4567-e89b-12d3-a456-4266141740{n:02x}")).unwrap()
}

fn request_id(n: u8) -> RequestId {
    RequestId::parse(&format!("00000000-0000-4000-8000-0000000000{n:02x}")).unwrap()
}

fn manifest(keep: Option<usize>) -> SiteManifest {
    let keep = keep
        .map(|keep| format!(r#""keepReleases": {keep},"#))
        .unwrap_or_default();
    SiteManifest::from_json_for_site(
        &format!(
            r#"{{"schemaVersion":1,"siteId":"{SITE}","domain":"example.com",
            "contentRoot":"sites/{SITE}/current","siteUser":"site-example",{keep}
            "repository":{{"url":"git@github.com:example/site.git",
            "allowedBranches":["main"],"credentialId":"{SITE}"}}}}"#
        ),
        SiteId::parse(SITE).unwrap(),
    )
    .unwrap()
}

impl Fixture {
    fn new() -> Self {
        let content_dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let content = TrustedRoot::parse(content_dir.path()).unwrap();
        let state = ManagedRoot::open(&TrustedRoot::parse(state_dir.path()).unwrap()).unwrap();
        Self {
            content_dir,
            _state_dir: state_dir,
            content,
            state,
            site: SiteId::parse(SITE).unwrap(),
        }
    }

    fn releases_dir(&self) -> std::path::PathBuf {
        self.content_dir
            .path()
            .join(format!("sites/{SITE}/releases"))
    }

    /// A release with a 20 000 byte file; larger `n` is newer.
    fn add(&self, n: u8) -> ReleaseId {
        let id = release(n);
        let dir = self.releases_dir().join(id.to_string());
        fs::create_dir_all(dir.join("nested")).unwrap();
        fs::write(dir.join("nested/app.bin"), vec![7u8; 20_000]).unwrap();
        let root = ManagedRoot::open(&self.content).unwrap();
        root.set_modified_nofollow(
            &SiteRelativePath::parse(format!("sites/{SITE}/releases/{id}")).unwrap(),
            1_700_000_000 + i64::from(n) * 100,
            0,
        )
        .unwrap();
        id
    }

    fn activate(&self, id: ReleaseId) {
        activate::activate(&self.content, self.site, id).unwrap();
    }

    fn context(&self) -> Context<'_> {
        Context {
            content_root: &self.content,
            engine_state: &self.state,
        }
    }

    fn request(&self, confirm: &[ReleaseId], n: u8) -> Request {
        let names: Vec<String> = confirm.iter().map(ToString::to_string).collect();
        Request::parse(SITE, &names, &request_id(n).to_string(), None).unwrap()
    }

    fn preview(&self, keep: Option<usize>) -> Result<PreviewResult, Error> {
        preview(&self.context(), &manifest(keep), &self.request(&[], 1))
    }

    fn delete(
        &self,
        keep: Option<usize>,
        confirm: &[ReleaseId],
        n: u8,
    ) -> Result<PruneResult, Error> {
        execute(&self.context(), &manifest(keep), &self.request(confirm, n))
    }

    fn exists(&self, id: ReleaseId) -> bool {
        self.releases_dir().join(id.to_string()).exists()
    }

    /// A finished deploy whose checkpoint names `previous` as its rollback target.
    fn checkpoint(&self, previous: ReleaseId, finish: bool) {
        self.activate(previous);
        let scope = preflight::open_site_state(&self.state, self.site).unwrap();
        let id = request_id(90);
        let preflight::Outcome::Proceed(admitted) =
            preflight::run(&scope, id, None, "site.deploy").unwrap()
        else {
            panic!("fresh request");
        };
        deployment_recovery::prepare(
            &self.content,
            &scope,
            self.site,
            id,
            "site.deploy",
            ReleaseId::from(id),
            Some(crate::site::GitCommitSha::parse(REVISION).unwrap()),
        )
        .unwrap();
        let preflight::Admitted { lock, mut state } = admitted;
        if finish {
            state.mark_committed(serde_json::json!({})).unwrap();
            state::save(&scope, &state_path_for(id), &state).unwrap();
        }
        drop(lock);
    }
}

#[test]
fn request_parsing_accepts_exact_names_only() {
    let id = release(1).to_string();
    let ok = Request::parse(SITE, &[id.clone()], REQUEST, Some("key-1")).unwrap();
    assert_eq!(ok.confirm.len(), 1);
    assert!(!ok.is_preview());
    assert!(
        Request::parse(SITE, &[], REQUEST, None)
            .unwrap()
            .is_preview()
    );
    for bad in [
        "../etc",
        "..",
        "a/b",
        "",
        &id.to_uppercase(),
        &format!("{id}/"),
    ] {
        assert_eq!(
            Request::parse(SITE, &[bad.to_owned()], REQUEST, None).unwrap_err(),
            RequestError::InvalidRelease,
            "{bad:?}"
        );
    }
    assert_eq!(
        Request::parse(SITE, &[id.clone(), id.clone()], REQUEST, None).unwrap_err(),
        RequestError::DuplicateConfirmation
    );
    let many: Vec<String> = (0..=MAX_CONFIRMATIONS as u8)
        .map(|n| release(n).to_string())
        .collect();
    assert_eq!(
        Request::parse(SITE, &many, REQUEST, None).unwrap_err(),
        RequestError::TooManyConfirmations
    );
    assert_eq!(
        Request::parse("nope", &[], REQUEST, None).unwrap_err(),
        RequestError::InvalidSiteId
    );
}

#[test]
fn preview_lists_old_releases_with_sizes_and_deletes_nothing() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=8).map(|n| f.add(n)).collect();
    f.activate(ids[7]);

    let result = f.preview(None).unwrap();
    // Default 5: releases 8..4 are kept, 3, 2, 1 are old (newest first).
    let listed: Vec<ReleaseId> = result.candidates.iter().map(|c| c.release_id).collect();
    assert_eq!(listed, vec![ids[2], ids[1], ids[0]]);
    assert_eq!(result.keep_releases, 5);
    assert_eq!(result.active_release_id, Some(ids[7]));
    assert!(
        result
            .candidates
            .iter()
            .all(|c| c.size_bytes.unwrap() >= 20_000)
    );
    assert_eq!(
        result.total_bytes,
        Some(
            result
                .candidates
                .iter()
                .map(|c| c.size_bytes.unwrap())
                .sum()
        )
    );
    assert_eq!(result.kept.len(), 5);
    assert_eq!(result.kept[0].reason, KeepReason::Active);
    assert!(
        result.kept[1..]
            .iter()
            .all(|k| k.reason == KeepReason::Newest)
    );
    assert!(
        ids.iter().all(|id| f.exists(*id)),
        "a preview never deletes"
    );
}

#[test]
fn the_manifest_setting_sets_how_many_are_kept() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=6).map(|n| f.add(n)).collect();
    f.activate(ids[5]);
    let result = f.preview(Some(2)).unwrap();
    assert_eq!(result.keep_releases, 2);
    assert_eq!(result.candidates.len(), 4);
    assert_eq!(f.preview(Some(100)).unwrap().candidates.len(), 0);
}

#[test]
fn the_active_release_is_never_a_candidate_even_when_it_is_the_oldest() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=4).map(|n| f.add(n)).collect();
    f.activate(ids[0]); // rolled back to the oldest

    let result = f.preview(Some(1)).unwrap();
    let listed: Vec<ReleaseId> = result.candidates.iter().map(|c| c.release_id).collect();
    assert_eq!(listed, vec![ids[2], ids[1]]);
    assert!(
        result
            .kept
            .iter()
            .any(|k| k.release_id == ids[0] && k.reason == KeepReason::Active)
    );

    assert!(matches!(
        f.delete(Some(1), &[ids[0]], 2),
        Err(Error::NotEligible)
    ));
    assert!(matches!(
        f.delete(Some(1), &[ids[3]], 3),
        Err(Error::NotEligible)
    ));
    assert!(ids.iter().all(|id| f.exists(*id)));
}

#[test]
fn a_release_a_checkpoint_names_as_rollback_target_is_kept() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=5).map(|n| f.add(n)).collect();
    f.checkpoint(ids[0], true); // the oldest was current before the last deploy
    f.activate(ids[4]);

    let result = f.preview(Some(2)).unwrap();
    let listed: Vec<ReleaseId> = result.candidates.iter().map(|c| c.release_id).collect();
    assert_eq!(listed, vec![ids[2], ids[1]]);
    assert!(
        result
            .kept
            .iter()
            .any(|k| k.release_id == ids[0] && k.reason == KeepReason::Rollback)
    );
    assert!(matches!(
        f.delete(Some(2), &[ids[0]], 2),
        Err(Error::NotEligible)
    ));
    assert!(f.exists(ids[0]));
}

#[test]
fn an_unfinished_deploy_refuses_both_steps() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=4).map(|n| f.add(n)).collect();
    f.checkpoint(ids[0], false);
    f.activate(ids[3]);
    assert!(matches!(
        f.preview(Some(1)),
        Err(Error::Recovery(deployment_recovery::Error::Conflict))
    ));
    assert!(matches!(
        f.delete(Some(1), &[ids[1]], 2),
        Err(Error::Recovery(deployment_recovery::Error::Conflict))
    ));
    assert!(ids.iter().all(|id| f.exists(*id)));
}

#[test]
fn a_held_site_lock_refuses_as_a_conflict() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=4).map(|n| f.add(n)).collect();
    f.activate(ids[3]);
    let scope = preflight::open_site_state(&f.state, f.site).unwrap();
    let _held = lock::acquire(&scope, &preflight::lock_path(), request_id(50)).unwrap();
    for error in [
        f.preview(Some(1)).unwrap_err(),
        f.delete(Some(1), &[ids[0]], 2).unwrap_err(),
    ] {
        assert_eq!(error.protocol().0, ErrorCode::Conflict);
    }
    assert!(f.exists(ids[0]));
}

#[test]
fn delete_removes_exactly_the_confirmed_directories_and_is_idempotent() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=8).map(|n| f.add(n)).collect();
    f.activate(ids[7]);

    let result = f.delete(None, &[ids[0], ids[2]], 2).unwrap();
    assert_eq!(result.removed, vec![ids[0], ids[2]]);
    assert!(result.already_absent.is_empty());
    assert!(result.freed_bytes.unwrap() >= 40_000);
    assert!(!f.exists(ids[0]) && !f.exists(ids[2]));
    assert!(
        f.exists(ids[1]),
        "an old release that was not confirmed stays"
    );
    assert!(ids[3..].iter().all(|id| f.exists(*id)));

    // Same directories again: absent, success, nothing else touched.
    let again = f.delete(None, &[ids[0], ids[2]], 3).unwrap();
    assert!(again.removed.is_empty());
    assert_eq!(again.already_absent, vec![ids[0], ids[2]]);
    assert!(f.exists(ids[1]));

    // The preview now lists only what is left.
    let left = f.preview(None).unwrap();
    assert_eq!(left.candidates.len(), 1);
    assert_eq!(left.candidates[0].release_id, ids[1]);
}

#[test]
fn one_ineligible_confirmation_refuses_the_whole_request_before_any_removal() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=8).map(|n| f.add(n)).collect();
    f.activate(ids[7]);
    assert!(matches!(
        f.delete(None, &[ids[0], ids[6]], 2),
        Err(Error::NotEligible)
    ));
    assert!(ids.iter().all(|id| f.exists(*id)));
}

#[test]
fn a_retried_idempotency_key_replays_the_recorded_result() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=7).map(|n| f.add(n)).collect();
    f.activate(ids[6]);
    let names = [ids[0].to_string()];
    let first = Request::parse(SITE, &names, &request_id(2).to_string(), Some("prune-1")).unwrap();
    let a = execute(&f.context(), &manifest(None), &first).unwrap();
    let retry = Request::parse(SITE, &names, &request_id(3).to_string(), Some("prune-1")).unwrap();
    let b = execute(&f.context(), &manifest(None), &retry).unwrap();
    assert_eq!(a.removed, vec![ids[0]]);
    assert_eq!(b.removed, vec![ids[0]]);
    assert_eq!(a.completed_at_unix_secs, b.completed_at_unix_secs);
}

#[test]
fn a_refused_attempt_is_recorded_as_failed_and_replays_the_refusal() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=7).map(|n| f.add(n)).collect();
    f.activate(ids[6]);
    let names = [ids[6].to_string()];
    let first = Request::parse(SITE, &names, &request_id(2).to_string(), Some("prune-2")).unwrap();
    assert!(matches!(
        execute(&f.context(), &manifest(None), &first),
        Err(Error::NotEligible)
    ));
    let retry = Request::parse(SITE, &names, &request_id(3).to_string(), Some("prune-2")).unwrap();
    assert!(matches!(
        execute(&f.context(), &manifest(None), &retry),
        Err(Error::Replayed {
            code: ErrorCode::Conflict,
            ..
        })
    ));
    assert!(f.exists(ids[6]));
}

#[test]
fn a_missing_or_foreign_current_refuses_instead_of_guessing() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=7).map(|n| f.add(n)).collect();
    // Releases exist but nothing was ever activated.
    assert!(matches!(f.preview(None), Err(Error::NoActiveRelease)));
    assert!(matches!(
        f.delete(None, &[ids[0]], 2),
        Err(Error::NoActiveRelease)
    ));

    // `current` points somewhere that is not releases/<id>.
    symlink("/tmp", f.releases_dir().parent().unwrap().join("current")).unwrap();
    assert!(matches!(f.preview(None), Err(Error::NoActiveRelease)));

    // `current` names a release that is not on disk.
    fs::remove_file(f.releases_dir().parent().unwrap().join("current")).unwrap();
    f.activate(release(99));
    assert!(matches!(f.preview(None), Err(Error::NoActiveRelease)));
    assert!(ids.iter().all(|id| f.exists(*id)));
}

#[test]
fn no_releases_directory_means_nothing_to_prune() {
    let f = Fixture::new();
    let preview = f.preview(None).unwrap();
    assert!(preview.candidates.is_empty() && preview.active_release_id.is_none());
    let result = f.delete(None, &[release(1)], 2).unwrap();
    assert!(result.removed.is_empty());
    assert_eq!(result.already_absent, vec![release(1)]);
}

#[test]
fn a_symlinked_release_entry_is_never_followed_listed_or_removed() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=7).map(|n| f.add(n)).collect();
    f.activate(ids[6]);
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("precious.txt"), "keep me").unwrap();
    let link = release(40);
    symlink(outside.path(), f.releases_dir().join(link.to_string())).unwrap();
    ManagedRoot::open(&f.content)
        .unwrap()
        .set_modified_nofollow(
            &SiteRelativePath::parse(format!("sites/{SITE}/releases/{link}")).unwrap(),
            1_000,
            0,
        )
        .unwrap();

    let result = f.preview(None).unwrap();
    assert_eq!(result.ignored_entries, 1);
    assert!(result.candidates.iter().all(|c| c.release_id != link));

    assert!(matches!(
        f.delete(None, &[link], 2),
        Err(Error::NotEligible)
    ));
    assert!(outside.path().join("precious.txt").exists());
    assert!(fs::symlink_metadata(f.releases_dir().join(link.to_string())).is_ok());
}

#[test]
fn a_symlink_inside_a_release_is_removed_as_a_link_not_followed() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=7).map(|n| f.add(n)).collect();
    f.activate(ids[6]);
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("precious.txt"), "keep me").unwrap();
    symlink(
        outside.path(),
        f.releases_dir().join(ids[0].to_string()).join("storage"),
    )
    .unwrap();
    // Adding an entry touched the directory; put its age back.
    ManagedRoot::open(&f.content)
        .unwrap()
        .set_modified_nofollow(
            &SiteRelativePath::parse(format!("sites/{SITE}/releases/{}", ids[0])).unwrap(),
            1_700_000_100,
            0,
        )
        .unwrap();

    let preview = f.preview(None).unwrap();
    assert!(
        preview
            .candidates
            .iter()
            .all(|c| c.size_bytes.unwrap() < 200_000)
    );
    f.delete(None, &[ids[0]], 2).unwrap();
    assert!(!f.exists(ids[0]));
    assert!(outside.path().join("precious.txt").exists());
}

#[test]
fn a_symlinked_releases_directory_or_site_directory_is_refused() {
    let f = Fixture::new();
    let outside = tempfile::tempdir().unwrap();
    let real = outside.path().join("elsewhere");
    fs::create_dir_all(real.join(release(1).to_string())).unwrap();
    fs::create_dir_all(f.releases_dir().parent().unwrap()).unwrap();
    symlink(&real, f.releases_dir()).unwrap();
    assert!(matches!(f.preview(None), Err(Error::Unreadable)));
    assert!(matches!(
        f.delete(None, &[release(1)], 2),
        Err(Error::Unreadable)
    ));
    assert!(real.join(release(1).to_string()).exists());

    let g = Fixture::new();
    let other = tempfile::tempdir().unwrap();
    fs::create_dir_all(other.path().join("releases").join(release(1).to_string())).unwrap();
    fs::create_dir_all(g.content_dir.path().join("sites")).unwrap();
    symlink(
        other.path(),
        g.content_dir.path().join(format!("sites/{SITE}")),
    )
    .unwrap();
    assert!(matches!(g.preview(None), Err(Error::Unreadable)));
    assert!(
        other
            .path()
            .join("releases")
            .join(release(1).to_string())
            .exists()
    );
}

#[test]
fn non_release_entries_are_left_alone() {
    let f = Fixture::new();
    let ids: Vec<ReleaseId> = (1..=7).map(|n| f.add(n)).collect();
    f.activate(ids[6]);
    fs::create_dir(f.releases_dir().join("staging-tmp")).unwrap();
    fs::write(f.releases_dir().join("notes.txt"), "x").unwrap();
    assert_eq!(f.preview(None).unwrap().ignored_entries, 2);
    f.delete(None, &[ids[0]], 2).unwrap();
    assert!(f.releases_dir().join("staging-tmp").exists());
    assert!(Path::new(&f.releases_dir().join("notes.txt")).exists());
}

#[test]
fn a_manifest_for_another_content_root_is_refused() {
    let f = Fixture::new();
    let mut wrong = manifest(None);
    wrong.content_root = SiteRelativePath::parse(format!("sites/{SITE}/other")).unwrap();
    assert!(matches!(
        preview(&f.context(), &wrong, &f.request(&[], 1)),
        Err(Error::ContentRootMismatch)
    ));
}
