//! `security.dockerImageReplace` on a synthetic fix: a FrankenPHP runtime on an
//! older digest and a catalog replacement digest. No real advisory is used.

use super::super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const ID_2: &str = "123e4567-e89b-12d3-a456-426614174001";
const OLD: &str = "ghcr.io/orbden/frankenphp:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str = "ghcr.io/orbden/frankenphp:1@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMPOSE: &str = "services:\n  ingress:\n    image: ${WCP_INGRESS_IMAGE:-ghcr.io/orbden/caddy:1@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc}\n  runtime-1:\n    image: ${WCP_FRANKENPHP_IMAGE:-ghcr.io/orbden/frankenphp:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}\n    restart: unless-stopped\n";
const ENV: &str = "DB_PASSWORD='s3cret'\n";

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

fn rule() -> ImageRule {
    ImageRule {
        fix_id: "synthetic-frankenphp".into(),
        advisory_id: "synthetic-advisory".into(),
        component: "php-runtime".into(),
        platforms: vec!["linux/amd64".into()],
        from_digests: vec![digest('a')],
        to_digest: digest('b'),
        to_image: NEW.into(),
    }
}

/// A fake host: `ctl/current` holds the image the runtime runs; `up -d
/// --no-deps` moves it unless `stay-old`; `unhealthy` makes the new image
/// unhealthy; `foreign` starts the runtime on a digest the rule does not list.
struct Fixture {
    dir: tempfile::TempDir,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        for child in ["state", "stack", "stack/stack", "ctl"] {
            fs::create_dir(dir.path().join(child)).unwrap();
        }
        fs::write(dir.path().join("stack/stack/docker-compose.yml"), COMPOSE).unwrap();
        fs::write(dir.path().join("stack/.env"), ENV).unwrap();
        fs::write(dir.path().join("ctl/current"), OLD).unwrap();
        let c = dir.path().join("ctl");
        let c = c.display();
        let script = format!(
            r#"#!/bin/sh
C='{c}'
cur=$(cat "$C/current")
case "$cur" in
  *aaaa*) id=1 ;;
  *bbbb*) id=2 ;;
  *) id=3 ;;
esac
idhex=$(printf "$id%.0s" $(seq 1 64))
if [ "$1" = ps ]; then echo abc123; exit 0; fi
if [ "$1" = inspect ]; then
  health='"Health":{{"Status":"healthy"}},'
  if [ -e "$C/unhealthy" ] && [ "$id" = 2 ]; then health='"Health":{{"Status":"unhealthy"}},'; fi
  printf '[{{"Config":{{"Image":"%s","Labels":{{"com.docker.compose.service":"runtime-1"}}}},"Image":"sha256:%s","State":{{%s"Status":"running"}},"NetworkSettings":{{"Ports":{{}}}}}}]' "$cur" "$idhex" "$health"
  exit 0
fi
if [ "$1" = image ]; then
  case "$id" in
    1) d=$(printf 'a%.0s' $(seq 1 64)) ;;
    2) d=$(printf 'b%.0s' $(seq 1 64)) ;;
    *) d=$(printf 'e%.0s' $(seq 1 64)) ;;
  esac
  printf '[{{"Os":"linux","Architecture":"amd64","RepoDigests":["ghcr.io/x/frankenphp@sha256:%s"]}}]' "$d"
  exit 0
fi
shift 3
file=$4; shift 4
echo "$*" >> "$C/calls.log"
ref=$(sed -n 's/.*WCP_FRANKENPHP_IMAGE:-\([^}}]*\)}}.*/\1/p' "$file")
case "$*" in
  "config --quiet") exit 0 ;;
  "--profile * config --images") echo "$ref"; exit 0 ;;
  "pull --quiet runtime-1") exit 0 ;;
  "up -d --no-deps runtime-1") [ -e "$C/stay-old" ] && [ "$ref" != "{OLD}" ] && exit 0; printf '%s' "$ref" > "$C/current"; exit 0 ;;
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

    fn set_current(&self, image: &str) {
        fs::write(self.path("ctl/current"), image).unwrap();
    }

    fn current(&self) -> String {
        fs::read_to_string(self.path("ctl/current")).unwrap()
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.path("ctl/calls.log")).unwrap_or_default()
    }

    fn compose(&self) -> String {
        fs::read_to_string(self.path("stack/stack/docker-compose.yml")).unwrap()
    }

    fn run(&self, id: &str) -> Result<PatchResult, PatchError> {
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
        let request =
            Request::parse_security(&request_json(), id, Some(id), &[rule()], true).unwrap();
        execute(&ctx, &request, &CancellationToken::default())
    }
}

fn request_json() -> String {
    serde_json::json!({
        "fixId": "synthetic-frankenphp",
        "service": "runtime-1",
        "sites": ["a.example.com"],
        "confirm": "RESTART runtime-1",
    })
    .to_string()
}

#[test]
fn the_fix_replaces_only_the_runtime_and_verifies_the_active_image() {
    let fx = Fixture::new();
    let result = fx.run(ID).unwrap();
    assert!(result.changed);
    assert_eq!(result.fix_id.as_deref(), Some("synthetic-frankenphp"));
    assert_eq!(result.previous_image, OLD);
    assert_eq!(fx.current(), NEW);
    let compose = fx.compose();
    assert!(compose.contains(&format!("${{WCP_FRANKENPHP_IMAGE:-{NEW}}}")));
    assert!(compose.contains("caddy:1@sha256:cccc"), "ingress untouched");
    let calls = fx.calls();
    assert!(calls.contains("up -d --no-deps runtime-1"), "{calls}");
    assert!(!calls.contains("up -d\n"), "{calls}");
    let recorded =
        fs::read_to_string(fx.path(&format!("state/stacks/wcp/transactions/{ID}.json"))).unwrap();
    assert!(!recorded.contains("s3cret"), "{recorded}");
    assert!(
        recorded.contains("security.dockerImageReplace"),
        "{recorded}"
    );
}

#[test]
fn an_unhealthy_replacement_is_rolled_back_and_the_advisory_stays_unresolved() {
    let fx = Fixture::new();
    fx.flag("unhealthy");
    let error = fx.run(ID).unwrap_err();
    assert!(matches!(error, PatchError::NotUpRestored(_)), "{error:?}");
    assert_eq!(fx.compose(), COMPOSE);
    assert_eq!(fx.current(), OLD, "the affected image runs again");
    assert!(!fx.path("state/stacks/wcp/patch-journal.json").exists());
    let (_, message) = error.protocol();
    assert!(message.contains("still unresolved"), "{message}");
}

#[test]
fn a_service_that_does_not_run_the_replacement_is_rolled_back() {
    let fx = Fixture::new();
    fx.flag("stay-old");
    let error = fx.run(ID).unwrap_err();
    assert!(
        matches!(error, PatchError::NotUpRestored(NotUp::WrongImage(_))),
        "{error:?}"
    );
    assert_eq!(fx.compose(), COMPOSE);
}

#[test]
fn an_image_the_fix_does_not_list_is_refused_without_touching_the_stack() {
    let fx = Fixture::new();
    fx.set_current("ghcr.io/orbden/frankenphp:1@sha256:eeee");
    let error = fx.run(ID).unwrap_err();
    assert!(matches!(error, PatchError::Refused(_)), "{error:?}");
    assert_eq!(fx.compose(), COMPOSE);
    assert!(fx.calls().is_empty());
}

#[test]
fn an_already_fixed_runtime_is_a_no_op_and_a_replay_does_not_run_again() {
    let fx = Fixture::new();
    let first = fx.run(ID).unwrap();
    let calls = fx.calls();
    let replay = fx.run(ID).unwrap();
    assert_eq!(replay.completed_at_unix_secs, first.completed_at_unix_secs);
    assert_eq!(fx.calls(), calls);
    // A new request on the fixed runtime changes nothing.
    let again = fx.run(ID_2).unwrap();
    assert!(!again.changed);
    assert_eq!(fx.calls(), calls, "no repeated destructive attempt");
}

#[test]
fn the_request_is_checked_against_the_accepted_catalog() {
    let ok = request_json();
    let parse = |json: &str, rules: &[ImageRule], fresh: bool| {
        Request::parse_security(json, ID, None, rules, fresh)
    };
    assert!(parse(&ok, &[rule()], true).is_ok());
    assert_eq!(
        parse(&ok, &[rule()], false).unwrap_err(),
        RequestError::CatalogNotFresh
    );
    assert_eq!(parse(&ok, &[], true).unwrap_err(), RequestError::UnknownFix);
    for bad in [
        "docker.io/library/frankenphp@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "ghcr.io/orbden/frankenphp:1",
        "ghcr.io/evil/frankenphp@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "",
    ] {
        let mut r = rule();
        r.to_image = bad.into();
        assert_eq!(
            parse(&ok, &[r], true).unwrap_err(),
            RequestError::NotCatalogImage,
            "{bad}"
        );
    }
    assert_eq!(
        parse(&ok.replace("RESTART runtime-1", "yes"), &[rule()], true).unwrap_err(),
        RequestError::ConfirmationMissing
    );
    let other = ok.replace("runtime-1", "valkey-9");
    assert_eq!(
        parse(&other, &[rule()], true).unwrap_err(),
        RequestError::InvalidService
    );
    let smuggled = ok.replace("\"fixId\"", "\"image\":\"docker.io/x\",\"fixId\"");
    assert_eq!(
        parse(&smuggled, &[rule()], true).unwrap_err(),
        RequestError::Malformed
    );
}
