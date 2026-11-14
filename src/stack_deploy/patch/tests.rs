use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const ID_2: &str = "123e4567-e89b-12d3-a456-426614174001";
const OLD: &str = "ghcr.io/local-control-panel/valkey:9@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str = "ghcr.io/local-control-panel/valkey:9@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMPOSE: &str = "services:\n  ingress:\n    image: ${WCP_INGRESS_IMAGE:-ghcr.io/local-control-panel/frankenphp:1@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc}\n  valkey-9:\n    image: ${WCP_VALKEY_IMAGE:-ghcr.io/local-control-panel/valkey:9@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}\n    restart: unless-stopped\n";

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A fake host. The fake `docker` keeps the image "running" for the service in
/// `ctl/current` and moves it on `up -d --no-deps`. Flags in `ctl/`:
/// `unhealthy` (any image other than the original is unhealthy),
/// `fail-pull`, `bad-image`.
struct Fixture {
    dir: tempfile::TempDir,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new(compose: &str, env: &str, running_version: &str) -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        for child in ["state", "stack", "stack/stack", "ctl"] {
            fs::create_dir(dir.path().join(child)).unwrap();
        }
        fs::write(dir.path().join("stack/stack/docker-compose.yml"), compose).unwrap();
        fs::write(dir.path().join("stack/.env"), env).unwrap();
        fs::write(dir.path().join("ctl/current"), OLD).unwrap();
        let c = dir.path().join("ctl");
        let c = c.display();
        let script = format!(
            r#"#!/bin/sh
C='{c}'
OLD='{OLD}'
cur=$(cat "$C/current")
if [ "$1" = ps ]; then echo abc123; exit 0; fi
if [ "$1" = inspect ]; then
  health='"Health":{{"Status":"healthy"}},'
  if [ -e "$C/unhealthy" ] && [ "$cur" != "$OLD" ]; then health='"Health":{{"Status":"unhealthy"}},'; fi
  printf '[{{"Config":{{"Image":"%s","Labels":{{"com.docker.compose.service":"valkey-9"}}}},"Image":"sha256:%s","State":{{%s"Status":"running"}},"NetworkSettings":{{"Ports":{{}}}}}}]' "$cur" "$(printf 'd%.0s' $(seq 1 64))" "$health"
  exit 0
fi
if [ "$1" = image ]; then
  printf '[{{"Os":"linux","Architecture":"amd64","RepoDigests":["ghcr.io/local-control-panel/valkey@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"Config":{{"Env":["PATH=/bin","VALKEY_VERSION={running_version}"]}}}}]'
  exit 0
fi
shift 3
file=$4; shift 4
echo "$*" >> "$C/calls.log"
ref=$(sed -n 's/.*image: .*:-\(ghcr.io[^}}]*valkey[^}}]*\)}}.*/\1/p' "$file")
case "$*" in
  "config --quiet") exit 0 ;;
  "--profile * config --images")
    echo "$ref"
    [ -e "$C/bad-image" ] && echo "docker.io/library/nginx:latest"
    exit 0 ;;
  "pull --quiet valkey-9") [ -e "$C/fail-pull" ] && exit 1; exit 0 ;;
  "up -d --no-deps valkey-9") printf '%s' "$ref" > "$C/current"; exit 0 ;;
esac
exit 2
"#
        );
        let docker = dir.path().join("docker");
        fs::write(&docker, script).unwrap();
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            _serial: serial,
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn flag(&self, name: &str) {
        fs::write(self.path(&format!("ctl/{name}")), "").unwrap();
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.path("ctl/calls.log")).unwrap_or_default()
    }

    fn compose(&self) -> String {
        fs::read_to_string(self.path("stack/stack/docker-compose.yml")).unwrap()
    }

    fn current(&self) -> String {
        fs::read_to_string(self.path("ctl/current")).unwrap()
    }

    fn run(&self, id: &str, json: &str) -> Result<PatchResult, PatchError> {
        let state = ManagedRoot::open(&TrustedRoot::parse(self.path("state")).unwrap()).unwrap();
        let stack = TrustedRoot::parse(self.path("stack")).unwrap();
        let docker = self.path("docker");
        let ctx = Context {
            engine_state: &state,
            stack_root: &stack,
            docker: docker.to_str().unwrap(),
            timing: Timing {
                validate: Duration::from_secs(10),
                pull: Duration::from_secs(10),
                up: Duration::from_secs(10),
                health: Duration::from_millis(300),
                poll_interval: Duration::from_millis(20),
            },
            owner: None,
        };
        let request = Request::parse(json, id, Some("key-1")).unwrap();
        execute(&ctx, &request, &CancellationToken::default())
    }
}

fn request(version: &str) -> String {
    serde_json::json!({
        "service": "valkey-9",
        "image": NEW,
        "resolvedVersion": version,
        "sites": ["a.example.com", "b.example.com"],
        "confirm": "RESTART valkey-9",
    })
    .to_string()
}

const ENV: &str = "VALKEY_ADMIN_PASSWORD='s3cret'\n";

#[test]
fn a_patch_replaces_only_that_services_image_and_records_no_secret() {
    let fx = Fixture::new(COMPOSE, ENV, "9.1.3");
    let result = fx.run(ID, &request("9.1.4")).unwrap();
    assert!(result.changed);
    assert_eq!(result.previous_version.as_deref(), Some("9.1.3"));
    assert_eq!(result.version, "9.1.4");
    assert_eq!(result.previous_image, OLD);
    assert_eq!(result.sites, ["a.example.com", "b.example.com"]);
    assert_eq!(fx.current(), NEW);
    let compose = fx.compose();
    assert!(compose.contains(&format!("${{WCP_VALKEY_IMAGE:-{NEW}}}")));
    assert!(
        compose.contains("frankenphp:1@sha256:cccc"),
        "ingress untouched"
    );
    assert!(compose.contains("restart: unless-stopped"));
    let calls = fx.calls();
    assert!(calls.contains("pull --quiet valkey-9"), "{calls}");
    assert!(calls.contains("up -d --no-deps valkey-9"), "{calls}");
    assert!(
        !calls.contains("up -d\n"),
        "never a whole-stack up: {calls}"
    );
    // Nothing left behind and no secret in the recorded result or state.
    let mut left: Vec<String> = fs::read_dir(fx.path("stack/stack"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["docker-compose.yml"]);
    assert!(!fx.path("state/stacks/wcp/patch-journal.json").exists());
    let recorded =
        fs::read_to_string(fx.path(&format!("state/stacks/wcp/transactions/{ID}.json"))).unwrap();
    assert!(!recorded.contains("s3cret"), "{recorded}");
}

#[test]
fn a_replay_returns_the_recorded_result_without_touching_docker() {
    let fx = Fixture::new(COMPOSE, ENV, "9.1.3");
    let first = fx.run(ID, &request("9.1.4")).unwrap();
    let calls = fx.calls();
    let again = fx.run(ID, &request("9.1.4")).unwrap();
    assert_eq!(again.completed_at_unix_secs, first.completed_at_unix_secs);
    assert_eq!(fx.calls(), calls);
}

#[test]
fn an_unhealthy_service_is_rolled_back_to_the_previous_image() {
    let fx = Fixture::new(COMPOSE, ENV, "9.1.3");
    fx.flag("unhealthy");
    let error = fx.run(ID, &request("9.1.4")).unwrap_err();
    assert!(matches!(error, PatchError::NotUpRestored(_)), "{error:?}");
    assert_eq!(fx.compose(), COMPOSE, "the compose file is back");
    assert_eq!(fx.current(), OLD, "the previous image runs again");
    assert!(!fx.path("state/stacks/wcp/patch-journal.json").exists());
    let (code, message) = error.protocol();
    assert_eq!(code, ErrorCode::ConfigReloadFailed);
    assert!(message.contains("restored"), "{message}");
}

#[test]
fn a_failed_pull_changes_nothing() {
    let fx = Fixture::new(COMPOSE, ENV, "9.1.3");
    fx.flag("fail-pull");
    let error = fx.run(ID, &request("9.1.4")).unwrap_err();
    assert!(matches!(error, PatchError::PullFailed(_)), "{error:?}");
    assert_eq!(fx.compose(), COMPOSE);
    assert!(!fx.calls().contains("up -d"));
}

#[test]
fn another_minor_an_older_image_and_an_unreadable_version_are_refused() {
    for (version, running) in [
        ("9.2.0", "9.1.3"),
        ("9.1.2", "9.1.3"),
        ("9.1.4", "unreadable"),
    ] {
        let fx = Fixture::new(COMPOSE, ENV, running);
        let error = fx.run(ID, &request(version)).unwrap_err();
        assert!(
            matches!(error, PatchError::NotAPatch(_)),
            "{version}: {error:?}"
        );
        assert_eq!(fx.compose(), COMPOSE);
        assert!(fx.calls().is_empty(), "docker compose was never called");
    }
}

#[test]
fn the_same_image_is_a_no_op() {
    let fx = Fixture::new(COMPOSE, ENV, "9.1.3");
    let json = request("9.1.3").replace(NEW, OLD);
    let result = fx.run(ID, &json).unwrap();
    assert!(!result.changed);
    assert!(fx.calls().is_empty());
}

#[test]
fn an_env_override_or_a_foreign_compose_shape_is_refused() {
    let fx = Fixture::new(COMPOSE, "WCP_VALKEY_IMAGE=ghcr.io/x\n", "9.1.3");
    let error = fx.run(ID, &request("9.1.4")).unwrap_err();
    assert!(matches!(error, PatchError::NotRewritable(_)), "{error:?}");
    drop(fx);
    let fixed = COMPOSE
        .replace("${WCP_VALKEY_IMAGE:-", "")
        .replace("}\n    restart", "\n    restart");
    let fx = Fixture::new(&fixed, ENV, "9.1.3");
    assert!(matches!(
        fx.run(ID, &request("9.1.4")).unwrap_err(),
        PatchError::NotRewritable(_)
    ));
}

#[test]
fn an_image_outside_the_policy_never_reaches_docker() {
    let fx = Fixture::new(COMPOSE, ENV, "9.1.3");
    fx.flag("bad-image");
    let error = fx.run(ID, &request("9.1.4")).unwrap_err();
    assert!(matches!(error, PatchError::ImageRejected(_)), "{error:?}");
    assert_eq!(fx.compose(), COMPOSE);
    assert!(!fx.calls().contains("up -d"));
}

#[test]
fn an_interrupted_predecessor_is_rolled_back_first() {
    let fx = Fixture::new(COMPOSE, ENV, "9.1.3");
    // A predecessor stopped after activation: the live file is changed, the
    // backup and the journal remain.
    let changed = COMPOSE.replace(OLD, NEW);
    fs::write(fx.path("stack/stack/docker-compose.yml"), &changed).unwrap();
    fs::write(
        fx.path(&format!("stack/stack/docker-compose.yml.rollback-{ID}")),
        COMPOSE,
    )
    .unwrap();
    fs::create_dir_all(fx.path("state/stacks/wcp")).unwrap();
    fs::write(
        fx.path("state/stacks/wcp/patch-journal.json"),
        format!(r#"{{"requestId":"{ID}","service":"valkey-9"}}"#),
    )
    .unwrap();
    let result = fx.run(ID_2, &request("9.1.4")).unwrap();
    assert!(result.changed);
    assert_eq!(fx.compose(), COMPOSE.replace(OLD, NEW));
    assert!(
        !fx.path(&format!("stack/stack/docker-compose.yml.rollback-{ID}"))
            .exists()
    );
}

#[test]
fn the_request_needs_the_exact_confirmation_and_a_valid_image() {
    let ok = request("9.1.4");
    assert!(Request::parse(&ok, ID, None).is_ok());
    let wrong = ok.replace("RESTART valkey-9", "yes");
    assert_eq!(
        Request::parse(&wrong, ID, None).unwrap_err(),
        RequestError::ConfirmationMissing
    );
    let other = ok.replace("RESTART valkey-9", "RESTART postgres-18");
    assert_eq!(
        Request::parse(&other, ID, None).unwrap_err(),
        RequestError::ConfirmationMissing
    );
    let tag = ok.replace(&format!("@sha256:{}", "b".repeat(64)), "");
    assert_eq!(
        Request::parse(&tag, ID, None).unwrap_err(),
        RequestError::InvalidImage
    );
    let foreign = ok.replace("ghcr.io/local-control-panel/", "docker.io/");
    assert_eq!(
        Request::parse(&foreign, ID, None).unwrap_err(),
        RequestError::InvalidImage
    );
    let sites = ok.replace("a.example.com", "A b;rm");
    assert_eq!(
        Request::parse(&sites, ID, None).unwrap_err(),
        RequestError::InvalidSites
    );
    let missing = r#"{"service":"valkey-9","image":"x","resolvedVersion":"9.1.4","confirm":"RESTART valkey-9"}"#;
    assert_eq!(
        Request::parse(missing, ID, None).unwrap_err(),
        RequestError::Malformed
    );
    let version = ok.replace("9.1.4", "latest");
    assert_eq!(
        Request::parse(&version, ID, None).unwrap_err(),
        RequestError::InvalidVersion
    );
}

#[test]
fn rewrite_changes_one_default_and_nothing_else() {
    let (text, old) = rewrite_image(COMPOSE, "", "valkey-9", NEW).unwrap();
    assert_eq!(old, OLD);
    assert_eq!(text, COMPOSE.replace(OLD, NEW));
    assert_eq!(
        rewrite_image(COMPOSE, "", "postgres-18", NEW),
        Err(RewriteError::NoService)
    );
    let other = NEW.replace("valkey", "mariadb");
    assert_eq!(
        rewrite_image(COMPOSE, "", "valkey-9", &other),
        Err(RewriteError::OtherRepository)
    );
    assert_eq!(
        rewrite_image(COMPOSE, "WCP_VALKEY_IMAGE=x", "valkey-9", NEW),
        Err(RewriteError::EnvOverride)
    );
    // A commented-out or empty override does not count.
    assert!(
        rewrite_image(
            COMPOSE,
            "# WCP_VALKEY_IMAGE=x\nWCP_VALKEY_IMAGE=\n",
            "valkey-9",
            NEW
        )
        .is_ok()
    );
}
