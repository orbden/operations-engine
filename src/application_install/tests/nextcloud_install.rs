//! Nextcloud through `execute` with the fake `docker` and a small archive
//! built with the system `tar`.
use super::*;

const NC_ADMIN_PASSWORD: &str = "Admin-password-123456";
const URL: &str = "https://download.nextcloud.com/server/releases/nextcloud-35.0.3.tar.bz2";

/// Writes `archive` in the fixture: a `.tar.bz2` of `nextcloud/` with
/// `version.php`, `index.php`, `occ` and Nextcloud's `.user.ini`, or of
/// `top` instead of `nextcloud`. Returns its SHA-256.
fn archive(f: &Fixture, top: &str) -> String {
    let src = f.dir.path().join("src");
    let tree = src.join(top);
    fs::create_dir_all(tree.join("lib")).unwrap();
    fs::write(
        tree.join("version.php"),
        "<?php \n$OC_Version = array(35,0,3,2);\n$OC_VersionString = '35.0.3';\n",
    )
    .unwrap();
    fs::write(tree.join("index.php"), "<?php").unwrap();
    fs::write(tree.join("occ"), "<?php").unwrap();
    fs::write(tree.join(".user.ini"), "output_buffering=0\n").unwrap();
    fs::write(tree.join("lib/base.php"), "<?php").unwrap();
    let out = std::process::Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .arg("-cjf")
        .arg(f.dir.path().join("archive"))
        .arg("-C")
        .arg(&src)
        .arg(top)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let bytes = fs::read(f.dir.path().join("archive")).unwrap();
    let digest = crate::util::sha256_hex(&bytes);
    *f.archive.borrow_mut() = bytes;
    digest
}

fn nextcloud_plan(f: &Fixture, sha256: &str) -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(&plan(f.site.to_str().unwrap(), f.uid, f.gid)).unwrap();
    value["application"] = "nextcloud".into();
    value["adminPassword"] = NC_ADMIN_PASSWORD.into();
    value["database"] = database("mariadb");
    value["archive"] = serde_json::json!({ "url": URL, "sha256": sha256 });
    value.to_string()
}

fn data_dir(f: &Fixture) -> PathBuf {
    f.site.with_file_name("example.com-data")
}

/// Nothing left in the engine's state but its own bookkeeping.
fn no_download_left(f: &Fixture) {
    let found = std::process::Command::new("find")
        .arg(f.dir.path().join("state"))
        .args(["-name", "download-*"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&found.stdout), "");
}

#[test]
fn the_archive_is_required_exactly_for_nextcloud_and_checked() {
    let f = fixture();
    let digest = "a".repeat(64);
    let parse = |json: &str| Request::parse(json, REQUEST_ID, None).is_ok();
    assert!(parse(&nextcloud_plan(&f, &digest)));
    let mut value: serde_json::Value = serde_json::from_str(&nextcloud_plan(&f, &digest)).unwrap();
    value.as_object_mut().unwrap().remove("archive");
    assert!(!parse(&value.to_string()), "no archive");
    let mut statamic: serde_json::Value =
        serde_json::from_str(&plan(f.site.to_str().unwrap(), f.uid, f.gid)).unwrap();
    statamic["archive"] = serde_json::json!({ "url": URL, "sha256": digest });
    assert!(!parse(&statamic.to_string()), "archive for statamic");
    for (url, sha) in [
        (
            "https://example.org/nextcloud-35.0.3.tar.bz2",
            digest.as_str(),
        ),
        (URL, "A".repeat(64).as_str()),
        (URL, "abc"),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_str(&nextcloud_plan(&f, &digest)).unwrap();
        value["archive"] = serde_json::json!({ "url": url, "sha256": sha });
        assert!(!parse(&value.to_string()), "{url} {sha}");
    }
    let mut value: serde_json::Value = serde_json::from_str(&nextcloud_plan(&f, &digest)).unwrap();
    value["archive"]["extra"] = true.into();
    assert!(!parse(&value.to_string()), "unknown archive field");
    // Nextcloud has an administrator and a database.
    let mut value: serde_json::Value = serde_json::from_str(&nextcloud_plan(&f, &digest)).unwrap();
    value.as_object_mut().unwrap().remove("database");
    assert!(!parse(&value.to_string()), "no database");
}

#[test]
fn installs_into_public_with_a_private_data_directory_beside_the_site() {
    let f = fixture();
    let digest = archive(&f, "nextcloud");
    let result = f
        .run_plan(&nextcloud_plan(&f, &digest), REQUEST_ID, None)
        .unwrap();
    assert_eq!(result.application, "nextcloud");
    assert_eq!(result.version, "35.0.3");
    assert_eq!(result.admin_url, "https://example.com/login");
    assert_eq!(f.names(""), ["public"]);
    // The site's own `.user.ini` stays; Nextcloud's is not unpacked over it.
    assert_eq!(
        f.names("public"),
        [
            ".user.ini",
            "config",
            "index.php",
            "lib",
            "occ",
            "version.php"
        ]
    );
    assert_eq!(
        fs::read_to_string(f.site.join("public/.user.ini")).unwrap(),
        "x"
    );
    let meta = fs::metadata(f.site.join("public/lib/base.php")).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (f.uid, f.gid));

    let data = data_dir(&f);
    let meta = fs::metadata(&data).unwrap();
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    assert_eq!((meta.uid(), meta.gid()), (f.uid, f.gid));
    assert!(data.join(".ncdata").exists(), "occ got the data directory");

    let calls = f.calls();
    // occ ran in the docroot with the data directory as an argument; the
    // passwords are only in the environment, named without a value.
    // (The fixture's paths are compared by suffix: macOS resolves the
    // temporary directory through a symlink.)
    assert!(
        calls.contains("/content/example.com/public -e NC_INSTALL_DB_PASSWORD")
            && calls.contains(" -- mysql mariadb 3306 site_db site_user admin@example.com /")
            && calls.contains("/content/example.com-data\n"),
        "{calls}"
    );
    assert!(
        calls.contains("-e NC_INSTALL_DB_PASSWORD -e NC_INSTALL_ADMIN_PASSWORD runtime-1 php -r"),
        "{calls}"
    );
    for secret in [NC_ADMIN_PASSWORD, DB_PASSWORD] {
        assert!(!calls.contains(secret), "{secret} in {calls}");
        assert!(!serde_json::to_string(&result).unwrap().contains(secret));
    }
    let seen = fs::read_to_string(f.dir.path().join("nextcloud.log")).unwrap();
    assert_eq!(seen.trim(), format!("{DB_PASSWORD}|{NC_ADMIN_PASSWORD}"));
    for line in [
        "config:system:set trusted_domains 1 --value=example.com",
        "config:system:set overwrite.cli.url --value=https://example.com",
        "config:system:set overwriteprotocol --value=https",
        "status --output=json",
    ] {
        assert!(calls.contains(line), "{line}: {calls}");
    }
    no_download_left(&f);
}

#[test]
fn a_tampered_archive_is_refused_before_anything_is_unpacked() {
    let f = fixture();
    archive(&f, "nextcloud");
    let wrong = "0".repeat(64);
    assert!(matches!(
        f.run_plan(&nextcloud_plan(&f, &wrong), REQUEST_ID, None),
        Err(Error::ArchiveDigest)
    ));
    assert_eq!(f.names(""), ["public"]);
    assert_eq!(f.names("public"), [".user.ini"]);
    assert!(
        !data_dir(&f).exists(),
        "the data directory it created is gone"
    );
    assert_eq!(f.calls(), "");
    no_download_left(&f);
}

#[test]
fn an_archive_of_another_layout_is_refused_and_undone() {
    let f = fixture();
    let digest = archive(&f, "owncloud");
    assert!(matches!(
        f.run_plan(&nextcloud_plan(&f, &digest), REQUEST_ID, None),
        Err(Error::ArchiveInvalid)
    ));
    assert_eq!(f.names(""), ["public"]);
    assert_eq!(f.names("public"), [".user.ini"]);
    assert!(!data_dir(&f).exists());
    no_download_left(&f);
}

#[test]
fn a_failed_occ_install_removes_the_files_and_the_data_directory() {
    let f = fixture();
    let digest = archive(&f, "nextcloud");
    fs::write(f.dir.path().join("fail-nextcloud"), "").unwrap();
    assert!(matches!(
        f.run_plan(&nextcloud_plan(&f, &digest), REQUEST_ID, None),
        Err(Error::SetupFailed(_))
    ));
    assert_eq!(f.names(""), ["public"]);
    assert_eq!(f.names("public"), [".user.ini"]);
    assert!(!data_dir(&f).exists());
    // Installable again once the cause is gone.
    fs::remove_file(f.dir.path().join("fail-nextcloud")).unwrap();
    assert!(
        f.run_plan(&nextcloud_plan(&f, &digest), OTHER_ID, None)
            .is_ok()
    );
}

#[test]
fn not_installed_after_occ_is_not_success() {
    let f = fixture();
    let digest = archive(&f, "nextcloud");
    fs::write(f.dir.path().join("not-installed"), "").unwrap();
    assert!(matches!(
        f.run_plan(&nextcloud_plan(&f, &digest), REQUEST_ID, None),
        Err(Error::Unverified)
    ));
    assert_eq!(f.names(""), ["public"]);
    assert!(!data_dir(&f).exists());
}

#[test]
fn a_data_directory_with_content_is_refused_before_anything_runs() {
    let f = fixture();
    let digest = archive(&f, "nextcloud");
    fs::create_dir(data_dir(&f)).unwrap();
    fs::write(data_dir(&f).join("someone.txt"), "kept").unwrap();
    assert!(matches!(
        f.run_plan(&nextcloud_plan(&f, &digest), REQUEST_ID, None),
        Err(Error::DataDirNotEmpty)
    ));
    assert_eq!(
        fs::read_to_string(data_dir(&f).join("someone.txt")).unwrap(),
        "kept"
    );
    assert_eq!(f.names("public"), [".user.ini"]);
    assert_eq!(f.calls(), "");
    // A symlink or a file in its place is refused the same way.
    let g = fixture();
    std::os::unix::fs::symlink(g.dir.path(), data_dir(&g)).unwrap();
    assert!(matches!(
        g.run_plan(&nextcloud_plan(&g, &digest), REQUEST_ID, None),
        Err(Error::DataDirNotEmpty)
    ));
    let h = fixture();
    fs::write(data_dir(&h), "file").unwrap();
    assert!(matches!(
        h.run_plan(&nextcloud_plan(&h, &digest), REQUEST_ID, None),
        Err(Error::DataDirNotEmpty)
    ));
}

#[test]
fn an_empty_data_directory_is_used_and_emptied_again_on_failure() {
    let f = fixture();
    let digest = archive(&f, "nextcloud");
    fs::create_dir(data_dir(&f)).unwrap();
    fs::write(f.dir.path().join("fail-nextcloud"), "").unwrap();
    assert!(
        f.run_plan(&nextcloud_plan(&f, &digest), REQUEST_ID, None)
            .is_err()
    );
    assert!(data_dir(&f).is_dir(), "a directory it did not create stays");
    assert_eq!(fs::read_dir(data_dir(&f)).unwrap().count(), 0);
}
