use super::*;

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

struct Fake {
    services: Result<Vec<Service>, Unavailable>,
    images: Vec<(String, ImageFacts)>,
}

impl Inventory for Fake {
    fn services(&self) -> Result<Vec<Service>, Unavailable> {
        self.services
            .as_ref()
            .map(Clone::clone)
            .map_err(|_| Unavailable)
    }
    fn image(&self, image_id: &str) -> Result<ImageFacts, Unavailable> {
        self.images
            .iter()
            .find(|(id, _)| id == image_id)
            .map(|(_, f)| f.clone())
            .ok_or(Unavailable)
    }
}

fn service(name: &str, image: &str, id: char) -> Service {
    Service {
        service: name.into(),
        declared_image: image.into(),
        image_id: digest(id),
        status: "running".into(),
    }
}

fn facts(digests: &[char], env: Option<(&str, &str)>, label: Option<&str>) -> ImageFacts {
    ImageFacts {
        platform: "linux/amd64".into(),
        digests: digests.iter().map(|c| digest(*c)).collect(),
        label_version: label.map(Into::into),
        env: env
            .map(|(k, v)| vec![(k.into(), v.into())])
            .unwrap_or_default(),
    }
}

fn cand(digest_char: Option<char>, version: Option<&str>) -> Candidate {
    Candidate {
        service: "svc".into(),
        digest: digest_char.map(digest),
        resolved_version: version.map(Into::into),
    }
}

fn one(image: &str, f: ImageFacts, c: Option<Candidate>) -> Row {
    let fake = Fake {
        services: Ok(vec![service("svc", image, 'a')]),
        images: vec![(digest('a'), f)],
    };
    let request = Request {
        candidates: c.into_iter().collect(),
    };
    evaluate(&fake, &request).services.remove(0)
}

const VALKEY: &str = "ghcr.io/orbden/valkey:9-alpine@sha256:aaaa";
const MARIA: &str = "ghcr.io/orbden/mariadb:11.4@sha256:aaaa";

#[test]
fn parses_versions() {
    assert_eq!(
        parse_version("1:11.4.5+maria~ubu2404"),
        Some(vec![11, 4, 5])
    );
    assert_eq!(parse_version("v1.53.3"), Some(vec![1, 53, 3]));
    assert_eq!(parse_version("18.1"), Some(vec![18, 1]));
    assert_eq!(parse_version("9"), None);
    assert_eq!(parse_version("latest"), None);
    assert_eq!(parse_version(""), None);
}

#[test]
fn same_digest_is_up_to_date_even_without_versions() {
    let row = one(
        VALKEY,
        facts(&['b'], None, None),
        Some(cand(Some('b'), None)),
    );
    assert_eq!(row.status, Status::UpToDate);
    assert_eq!(row.running_version, None);
}

#[test]
fn higher_patch_in_same_minor_is_pending() {
    let f = facts(&['b'], Some(("VALKEY_VERSION", "9.1.3")), None);
    let row = one(VALKEY, f, Some(cand(Some('c'), Some("9.1.4"))));
    assert_eq!(
        (row.status, row.reason),
        (Status::PatchPending, "newerPatch")
    );
    assert_eq!(row.running_version.as_deref(), Some("9.1.3"));
}

#[test]
fn rebuild_of_the_same_version_is_pending() {
    let f = facts(&['b'], Some(("VALKEY_VERSION", "9.1.3")), None);
    let row = one(VALKEY, f, Some(cand(Some('c'), Some("9.1.3"))));
    assert_eq!(row.reason, "sameVersionNewImage");
    assert_eq!(row.status, Status::PatchPending);
}

#[test]
fn another_minor_is_never_a_patch() {
    let f = facts(&['b'], Some(("VALKEY_VERSION", "9.1.3")), None);
    let row = one(VALKEY, f.clone(), Some(cand(Some('c'), Some("9.2.0"))));
    assert_eq!(row.status, Status::MinorOrMajor);
    let row = one(VALKEY, f, Some(cand(Some('c'), Some("10.0.1"))));
    assert_eq!(row.status, Status::MinorOrMajor);
}

#[test]
fn older_candidate_is_unknown() {
    let f = facts(&['b'], Some(("VALKEY_VERSION", "9.1.3")), None);
    assert_eq!(
        one(VALKEY, f.clone(), Some(cand(Some('c'), Some("9.1.2")))).reason,
        "candidateOlder"
    );
    assert_eq!(
        one(VALKEY, f, Some(cand(Some('c'), Some("9.0.9")))).status,
        Status::Unknown
    );
}

#[test]
fn missing_pieces_are_unknown_never_ok() {
    let f = facts(&['b'], Some(("VALKEY_VERSION", "9.1.3")), None);
    assert_eq!(one(VALKEY, f.clone(), None).reason, "noCandidate");
    assert_eq!(
        one(VALKEY, f.clone(), Some(cand(None, Some("9.1.4")))).reason,
        "candidateDigestMissing"
    );
    assert_eq!(
        one(VALKEY, f, Some(cand(Some('c'), None))).reason,
        "candidateVersionUnknown"
    );
    let none = facts(&['b'], None, None);
    let row = one(VALKEY, none, Some(cand(Some('c'), Some("9.1.4"))));
    assert_eq!(
        (row.status, row.reason),
        (Status::Unknown, "runningVersionUnknown")
    );
}

#[test]
fn label_wins_and_mariadb_epoch_is_stripped() {
    let f = facts(
        &['b'],
        Some(("MARIADB_VERSION", "1:11.4.5+maria~ubu2404")),
        None,
    );
    let row = one(MARIA, f, Some(cand(Some('c'), Some("11.4.7"))));
    assert_eq!(row.running_version.as_deref(), Some("11.4.5"));
    assert_eq!(row.status, Status::PatchPending);
    let f = facts(
        &['b'],
        Some(("MARIADB_VERSION", "1:11.4.5+maria~ubu2404")),
        Some("11.4.6"),
    );
    assert_eq!(
        one(MARIA, f, None).running_version.as_deref(),
        Some("11.4.6")
    );
}

#[test]
fn foreign_image_is_manual_and_unreadable_image_unknown() {
    let row = one(
        "nginx:1",
        facts(&['b'], None, None),
        Some(cand(Some('b'), Some("1.2.3"))),
    );
    assert_eq!((row.status, row.kind), (Status::Manual, None));
    let fake = Fake {
        services: Ok(vec![service("svc", VALKEY, 'a')]),
        images: vec![],
    };
    let rows = evaluate(&fake, &Request { candidates: vec![] }).services;
    assert_eq!(
        (rows[0].status, rows[0].reason),
        (Status::Unknown, "imageUnreadable")
    );
}

#[test]
fn docker_failure_claims_nothing() {
    let fake = Fake {
        services: Err(Unavailable),
        images: vec![],
    };
    let result = evaluate(&fake, &Request { candidates: vec![] });
    assert_eq!(result.inventory, "unavailable");
    assert!(result.services.is_empty());
}

#[test]
fn request_validation() {
    let ok = format!(
        r#"{{"candidates":[{{"service":"valkey","digest":"{}","resolvedVersion":"9.1.3"}},{{"service":"postgres"}}]}}"#,
        digest('a')
    );
    assert_eq!(Request::parse(&ok).unwrap().candidates.len(), 2);
    assert_eq!(Request::parse("{}"), Err(RequestError::Malformed));
    assert_eq!(
        Request::parse(r#"{"candidates":[],"x":1}"#),
        Err(RequestError::Malformed)
    );
    assert_eq!(
        Request::parse(r#"{"candidates":[{"service":"a b"}]}"#),
        Err(RequestError::InvalidService)
    );
    assert_eq!(
        Request::parse(r#"{"candidates":[{"service":"a","digest":"sha256:zz"}]}"#),
        Err(RequestError::InvalidDigest)
    );
    assert_eq!(
        Request::parse(r#"{"candidates":[{"service":"a","resolvedVersion":"latest"}]}"#),
        Err(RequestError::InvalidVersion)
    );
    assert_eq!(
        Request::parse(r#"{"candidates":[{"service":"a"},{"service":"a"}]}"#),
        Err(RequestError::DuplicateService)
    );
    assert_eq!(
        Request::parse(r#"{"candidates":[{"service":"a","extra":1}]}"#),
        Err(RequestError::Malformed)
    );
}

#[test]
fn parses_docker_output() {
    let inspect = format!(
        r#"[{{"Image":"{}","Config":{{"Image":"{VALKEY}","Labels":{{"com.docker.compose.service":"valkey"}}}},"State":{{"Status":"running"}}}},
           {{"Image":"{}","Config":{{"Image":"x","Labels":{{}}}},"State":{{"Status":"running"}}}}]"#,
        digest('a'),
        digest('b')
    );
    let services = parse_services(inspect.as_bytes()).unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].service, "valkey");
    let image = format!(
        r#"[{{"Os":"linux","Architecture":"arm64","RepoDigests":["ghcr.io/x/valkey@{}","bad@sha256:zz"],"Config":{{"Env":["PATH=/bin","VALKEY_VERSION=9.1.3","SECRET=hunter2"],"Labels":{{"org.opencontainers.image.version":"9.1.3"}}}}}}]"#,
        digest('c')
    );
    let facts = parse_image(image.as_bytes()).unwrap();
    assert_eq!(facts.platform, "linux/arm64");
    assert_eq!(facts.digests, vec![digest('c')]);
    assert_eq!(
        facts.env,
        vec![("VALKEY_VERSION".to_owned(), "9.1.3".to_owned())]
    );
    assert_eq!(facts.label_version.as_deref(), Some("9.1.3"));
    assert!(parse_services(b"nope").is_none());
}

#[test]
fn postgres_minor_releases_are_patches_of_the_major_line() {
    const PG: &str = "ghcr.io/orbden/postgres:18@sha256:aaaa";
    let f = facts(&['b'], Some(("PG_VERSION", "18.1")), None);
    let row = one(PG, f.clone(), Some(cand(Some('c'), Some("18.2"))));
    assert_eq!(
        (row.status, row.reason),
        (Status::PatchPending, "newerPatch")
    );
    let row = one(PG, f, Some(cand(Some('c'), Some("19.0"))));
    assert_eq!(row.status, Status::MinorOrMajor);
}

#[test]
fn parse_version_table() {
    // The Debian/apt-style grammar: optional numeric epoch, optional `v`,
    // two to four dot-separated numbers, then only an apt revision (`+x`, `-1`). It is
    // not semver and stays separate from the strict `x.y.z` checks elsewhere.
    for (raw, expected) in [
        ("1:11.4.5+maria~ubu2404", Some(vec![11, 4, 5])),
        ("v1.53.3", Some(vec![1, 53, 3])),
        ("18.1", Some(vec![18, 1])),
        ("1.2.3.4", Some(vec![1, 2, 3, 4])),
        ("1.2.3.4.", Some(vec![1, 2, 3, 4])),
        (" 18.1 ", Some(vec![18, 1])),
        ("18.1\n", Some(vec![18, 1])),
        ("18.1.", Some(vec![18, 1])),
        ("18.1rc1", None),
        ("18.1-beta", None),
        ("18.1-2", Some(vec![18, 1])),
        ("18.1~rc1", None),
        ("18.1+x", Some(vec![18, 1])),
        ("18.1~x", None),
        ("18.1+x~y", Some(vec![18, 1])),
        ("01.02", Some(vec![1, 2])),
        ("0.0", Some(vec![0, 0])),
        ("4294967295.1", Some(vec![4_294_967_295, 1])),
        (":18.1", Some(vec![18, 1])),
        ("1:v2.3", Some(vec![2, 3])),
        ("12:3.4", Some(vec![3, 4])),
        ("4294967296.1", None),
        ("1.2.3.4.5", None),
        ("1.2.3.4.5.", None),
        ("", None),
        ("   ", None),
        ("9", None),
        ("9.", None),
        ("latest", None),
        ("x:18.1", None),
        ("1:2:3.4", None),
        ("vv18.1", None),
        ("V18.1", None),
        ("+1.2", None),
        ("-1.2", None),
        (".18.1", None),
        ("18..1", None),
        ("1 .2", None),
        ("\u{ff11}.2", None),
        ("1.\u{663}", None),
        ("\0", None),
        ("1.2\0", None),
        ("1.2+a\0", None),
        ("1.2+a b", None),
    ] {
        assert_eq!(parse_version(raw), expected, "{raw:?}");
    }
}

#[test]
fn prerelease_versions_are_unknown_not_a_patch() {
    const PG: &str = "ghcr.io/orbden/postgres:18@sha256:aaaa";
    // A pre-release candidate used to parse as the release and offer a patch.
    let f = facts(&['b'], Some(("PG_VERSION", "18.1")), None);
    let row = one(PG, f, Some(cand(Some('c'), Some("18.2rc1"))));
    assert_eq!(
        (row.status, row.reason),
        (Status::Unknown, "candidateVersionUnknown")
    );
    // A pre-release running version is not shown as the release either.
    let f = facts(&['b'], Some(("PG_VERSION", "18.1rc1")), None);
    let row = one(PG, f, Some(cand(Some('c'), Some("18.2"))));
    assert_eq!(row.running_version, None);
    assert_eq!(
        (row.status, row.reason),
        (Status::Unknown, "runningVersionUnknown")
    );
}
