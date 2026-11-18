//! Expired recovery-artifact cleanup for committed Meilisearch upgrades.
//! Only engine-written manifests are considered, and the retained source
//! volume is removed only while the manifest's target volume is still live.

use crate::{
    filesystem::ManagedRoot, meilisearch_upgrade::execute::RetainedArtifact, site::SiteRelativePath,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Driver {
    type Error: std::fmt::Debug;
    fn active_volume(&mut self) -> Result<String, Self::Error>;
    fn remove_volume(&mut self, volume: &str) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupResult {
    pub removed_source_volumes: Vec<String>,
    pub removed_backups: Vec<String>,
    pub skipped_manifests: u64,
}

pub fn cleanup_expired<D: Driver>(root: &ManagedRoot, now: u64, driver: &mut D) -> CleanupResult {
    let mut result = CleanupResult::default();
    let Some(artifacts_dir) = try_path("artifacts") else {
        return result;
    };
    let Ok(artifacts) = root.open_managed_dir(&artifacts_dir) else {
        return result;
    };
    let Ok(names) = artifacts.file_names() else {
        return result;
    };
    for name in names {
        if !name.ends_with(".json") {
            continue;
        }
        let Some(manifest_path) = try_path(&format!("artifacts/{name}")) else {
            result.skipped_manifests += 1;
            continue;
        };
        let Ok(json) = root.read_to_string(&manifest_path) else {
            result.skipped_manifests += 1;
            continue;
        };
        let Ok(manifest) = serde_json::from_str::<RetainedArtifact>(&json) else {
            result.skipped_manifests += 1;
            continue;
        };
        if now < manifest.expires_at_unix_secs
            || manifest.source_volume == manifest.target_volume
            || !valid_name(&manifest.source_volume)
            || !valid_name(&manifest.target_volume)
            || !valid_name(&manifest.backup_id)
            || driver.active_volume().ok().as_deref() != Some(&manifest.target_volume)
        {
            result.skipped_manifests += 1;
            continue;
        }
        if driver.remove_volume(&manifest.source_volume).is_err() {
            result.skipped_manifests += 1;
            continue;
        }
        result.removed_source_volumes.push(manifest.source_volume);

        let Some(backup) = try_path(&format!(
            "backups/{}/{}.dump",
            manifest.upgrade_request_id, manifest.backup_id
        )) else {
            result.skipped_manifests += 1;
            continue;
        };
        if root.exists(&backup) {
            if root.remove_file(&backup).is_err() {
                result.skipped_manifests += 1;
                continue;
            }
            result
                .removed_backups
                .push(backup.as_path().to_string_lossy().into_owned());
        }
        if root.remove_file(&manifest_path).is_err() {
            result.skipped_manifests += 1;
        }
    }
    result
}

pub fn cleanup_expired_now<D: Driver>(root: &ManagedRoot, driver: &mut D) -> CleanupResult {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    cleanup_expired(root, now, driver)
}

/// First character of every name the engine writes: an ASCII alphanumeric, so
/// `.`, `..`, `-flag`, `_x` and `.hidden` are never accepted. Shared by the
/// cleanup validator and the dump-uid writer so the two cannot drift.
const fn name_first_ok(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

/// Docker volume names as the engine writes them (defence in depth; see the
/// module tests).
fn valid_name(value: &str) -> bool {
    let rest = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.');
    crate::util::charset_ok(value, 255, name_first_ok, rest)
}

/// Dump uids the writer accepts (Meilisearch uids are timestamps such as
/// `20240101-120000123`). Always a subset of what `valid_name` accepts, so a
/// backup that is written can also be cleaned up.
pub(crate) fn valid_dump_uid(value: &str) -> bool {
    let rest = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_');
    crate::util::charset_ok(value, 128, name_first_ok, rest)
}

/// Builds a path from manifest-derived text; `None` when it is not a plain
/// relative path, so the manifest is skipped instead of panicking.
fn try_path(value: &str) -> Option<SiteRelativePath> {
    SiteRelativePath::parse(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> SiteRelativePath {
        SiteRelativePath::parse(value).expect("test path")
    }
    use crate::{
        meilisearch_upgrade::execute::RECOVERY_RETENTION_SECS, site::TrustedRoot,
        transaction::RequestId,
    };

    #[test]
    fn cleanup_valid_name_pins_its_accepted_and_rejected_characters_and_length() {
        crate::util::testing::pin_charset(
            "cleanup_valid_name",
            valid_name,
            255,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.",
        );
    }

    #[test]
    fn valid_name_rejects_dot_names_leading_dash_dot_and_separators() {
        for bad in [
            "", ".", "..", "-x", "-", ".x", "..x", "_x", "a/b", "/a", "a/", "../a", "a b", "a\\b",
        ] {
            assert!(!valid_name(bad), "{bad:?} must be rejected");
        }
        for good in [
            "x",
            "0",
            "dump-1",
            "20240101-120000123",
            "wcp_meilisearch_data",
            "wcp_meilisearch_1_29_abcdef012345",
            "a.b",
            "a..b",
            "a-",
            "a_.",
        ] {
            assert!(valid_name(good), "{good:?} must be accepted");
        }
        assert!(valid_name(&"a".repeat(255)));
        assert!(!valid_name(&"a".repeat(256)));
        assert!(!valid_name(&format!("-{}", "a".repeat(10))));
    }

    #[test]
    fn manifest_with_dot_dot_names_deletes_and_touches_nothing() {
        for (source, target, backup) in [
            ("source-volume", "target-volume", ".."),
            ("source-volume", "target-volume", "."),
            ("source-volume", "target-volume", "-x"),
            ("..", "target-volume", "dump-1"),
            ("-f", "target-volume", "dump-1"),
            ("source-volume", "..", "dump-1"),
        ] {
            let (_dir, root, mut artifact) = fixture();
            artifact.source_volume = source.into();
            artifact.target_volume = target.into();
            artifact.backup_id = backup.into();
            let manifest = path("artifacts/123e4567-e89b-12d3-a456-426614174000.json");
            root.write_atomic(&manifest, &serde_json::to_vec(&artifact).unwrap())
                .unwrap();
            // Files a traversal could reach: the legitimate dump, a sibling
            // of the request directory, and one beside the backups directory.
            let sentinels = [
                "backups/123e4567-e89b-12d3-a456-426614174000/dump-1.dump",
                "backups/123e4567-e89b-12d3-a456-426614174000/...dump",
                "backups/123e4567-e89b-12d3-a456-426614174000/..dump",
                "backups/123e4567-e89b-12d3-a456-426614174000/-x.dump",
                "backups/outside.dump",
                "outside.dump",
            ];
            for sentinel in sentinels {
                root.write_atomic(&path(sentinel), b"keep").unwrap();
            }
            let mut driver = Fake {
                active: target.into(),
                ..Fake::default()
            };
            let result = cleanup_expired(&root, artifact.expires_at_unix_secs, &mut driver);
            assert_eq!(result.skipped_manifests, 1, "{source} {target} {backup}");
            assert!(result.removed_backups.is_empty());
            assert!(result.removed_source_volumes.is_empty());
            assert!(driver.removed.is_empty());
            assert!(root.exists(&manifest));
            for sentinel in sentinels {
                assert!(root.exists(&path(sentinel)), "{sentinel} was touched");
                assert_eq!(root.read_to_string(&path(sentinel)).unwrap(), "keep");
            }
        }
    }

    #[test]
    fn dump_uid_writer_rule_is_a_subset_of_the_cleanup_rule() {
        let alphabet: Vec<char> = "azAZ09-_.:/ \\\0\u{e9}".chars().collect();
        let mut samples = vec![String::new(), "a".repeat(128), "a".repeat(129)];
        for &first in &alphabet {
            for &second in &alphabet {
                samples.push(format!("{first}{second}"));
                samples.push(format!("a{first}{second}"));
            }
        }
        for uid in &samples {
            if valid_dump_uid(uid) {
                assert!(valid_name(uid), "{uid:?} written but never cleaned");
            }
        }
        for first in ['-', '_', '.'] {
            assert!(!valid_dump_uid(&format!("{first}20240101")));
            assert!(!valid_name(&format!("{first}20240101")));
        }
        assert!(valid_dump_uid("20240101-120000123"));
        assert!(!valid_dump_uid("a.b"));
    }

    #[test]
    fn try_path_returns_none_for_unsafe_values_instead_of_panicking() {
        for bad in ["", "/abs", "a/../b", "../x", "a//b", "backups/../x.dump"] {
            assert!(try_path(bad).is_none(), "{bad:?}");
        }
        assert!(try_path("backups/id/dump-1.dump").is_some());
    }

    #[test]
    fn cleanup_does_not_panic_on_manifest_names_that_break_path_building() {
        // Names rejected by the validator, plus path-shaped values: each must
        // skip the manifest and keep it.
        for backup in ["a/../b", "../x", "a\0b", "", "x/y"] {
            let (_dir, root, mut artifact) = fixture();
            artifact.backup_id = backup.into();
            let manifest = path("artifacts/123e4567-e89b-12d3-a456-426614174000.json");
            root.write_atomic(&manifest, &serde_json::to_vec(&artifact).unwrap())
                .unwrap();
            let mut driver = Fake {
                active: "target-volume".into(),
                ..Fake::default()
            };
            let result = cleanup_expired(&root, artifact.expires_at_unix_secs, &mut driver);
            assert_eq!(result.skipped_manifests, 1, "{backup:?}");
            assert!(root.exists(&manifest));
        }
    }

    #[derive(Default)]
    struct Fake {
        active: String,
        removed: Vec<String>,
    }
    impl Driver for Fake {
        type Error = ();
        fn active_volume(&mut self) -> Result<String, ()> {
            Ok(self.active.clone())
        }
        fn remove_volume(&mut self, volume: &str) -> Result<(), ()> {
            self.removed.push(volume.into());
            Ok(())
        }
    }

    fn fixture() -> (tempfile::TempDir, ManagedRoot, RetainedArtifact) {
        let dir = tempfile::tempdir().unwrap();
        let trusted = TrustedRoot::parse(dir.path()).unwrap();
        let root = ManagedRoot::open(&trusted).unwrap();
        for child in ["artifacts", "backups/123e4567-e89b-12d3-a456-426614174000"] {
            root.create_dir_all(&path(child)).unwrap();
        }
        let artifact = RetainedArtifact {
            upgrade_request_id: RequestId::parse("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            source_volume: "source-volume".into(),
            target_volume: "target-volume".into(),
            backup_id: "dump-1".into(),
            retained_at_unix_secs: 100,
            expires_at_unix_secs: 100 + RECOVERY_RETENTION_SECS,
        };
        root.write_atomic(
            &path("artifacts/123e4567-e89b-12d3-a456-426614174000.json"),
            &serde_json::to_vec(&artifact).unwrap(),
        )
        .unwrap();
        root.write_atomic(
            &path("backups/123e4567-e89b-12d3-a456-426614174000/dump-1.dump"),
            b"dump",
        )
        .unwrap();
        (dir, root, artifact)
    }

    #[test]
    fn expired_artifacts_are_removed_only_when_the_target_is_still_active() {
        let (_dir, root, artifact) = fixture();
        let mut driver = Fake {
            active: "target-volume".into(),
            ..Fake::default()
        };
        let result = cleanup_expired(&root, artifact.expires_at_unix_secs, &mut driver);
        assert_eq!(result.removed_source_volumes, vec!["source-volume"]);
        assert_eq!(result.removed_backups.len(), 1);
        assert!(!root.exists(&path("artifacts/123e4567-e89b-12d3-a456-426614174000.json")));
    }

    #[test]
    fn recent_or_no_longer_active_targets_are_never_cleaned() {
        let (_dir, root, artifact) = fixture();
        let mut driver = Fake {
            active: "some-other-volume".into(),
            ..Fake::default()
        };
        assert_eq!(
            cleanup_expired(&root, artifact.expires_at_unix_secs, &mut driver).skipped_manifests,
            1
        );
        driver.active = "target-volume".into();
        assert_eq!(
            cleanup_expired(&root, artifact.expires_at_unix_secs - 1, &mut driver)
                .skipped_manifests,
            1
        );
        assert!(driver.removed.is_empty());
    }
}
