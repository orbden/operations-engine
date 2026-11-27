//! The service patch window: a daily time at which the engine moves the
//! managed containers to the images the owner approved, by itself, while the
//! panel is closed. Off by default and switched on only with an explicit
//! confirmation (`AUTOMATIC RESTARTS`): restarting a shared PHP or database
//! container interrupts every site on it.
//!
//! What it may apply is fixed when the window is switched on: the panel sends
//! the exact digest-pinned images (and the versions it resolved them from)
//! that the owner saw and confirmed, the engine stores them in a root-only file
//! (`/etc/wcp/service-patch-window.json`), and the daily run applies only
//! those. Nothing that appears later (a newer catalog, a feed) enters the
//! window without a new confirmation. Each target goes through the same
//! sequence as a manual `runtime.patchUpdate` (patch judged by the engine from
//! the running image, health wait, restore of the previous image on failure).
//!
//! A target that fails is recorded with its reason and *blocked*: the next day
//! does not try the same image again, and the panel shows it. A target that is
//! not a patch (already current, another line) is skipped without blocking.
//! The run records what happened to each target, never a secret.

use std::{
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::stack_deploy::patch::{self, PatchError, PatchResult};

pub const SET_OPERATION: &str = "runtime.setPatchWindow";
pub const RUN_OPERATION: &str = "runtime.runPatchWindow";
pub const STATUS_OPERATION: &str = "runtime.patchWindowStatus";
pub const CONFIG_PATH: &str = "/etc/wcp/service-patch-window.json";
pub const CONFIRMATION: &str = "AUTOMATIC RESTARTS";
const UNIT_NAME: &str = "wcp-service-patch";
const MAX_TARGETS: usize = 20;
const MAX_BLOCKED: usize = 100;
const MAX_MESSAGE: usize = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    Malformed,
    InvalidTime,
    NoTargets,
    TooManyTargets,
    InvalidTarget(patch::RequestError),
    ConfirmationMissing,
}

impl RequestError {
    pub fn message(self) -> String {
        match self {
            Self::Malformed => "request-file is not a valid patch window request".into(),
            Self::InvalidTime => "hour must be 0-23 and minute 0-59".into(),
            Self::NoTargets => "a patch window needs at least one target".into(),
            Self::TooManyTargets => format!("at most {MAX_TARGETS} targets"),
            Self::InvalidTarget(error) => format!("a target is invalid: {}", error.message()),
            Self::ConfirmationMissing => format!(
                "confirm must be exactly `{CONFIRMATION}`: the window restarts shared services, \
                 which interrupts every site on them, without anyone present"
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Target {
    pub service: String,
    pub image: String,
    pub resolved_version: String,
    /// The sites the owner was told would be interrupted (recorded).
    pub sites: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Blocked {
    pub service: String,
    pub image: String,
    pub reason: String,
    pub at_unix_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub service: String,
    /// `updated`, `alreadyCurrent`, `skipped` or `failed`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastRun {
    pub at_unix_secs: u64,
    pub results: Vec<Outcome>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Window {
    pub schema_version: u32,
    pub enabled: bool,
    /// Server local time.
    pub hour: u8,
    pub minute: u8,
    pub approved_at_unix_secs: u64,
    pub targets: Vec<Target>,
    pub blocked: Vec<Blocked>,
    pub last: Option<LastRun>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Wire {
    enabled: bool,
    hour: u8,
    minute: u8,
    #[serde(default)]
    targets: Vec<Target>,
    #[serde(default)]
    confirm: String,
}

#[derive(Debug)]
pub struct SetRequest {
    pub enabled: bool,
    pub hour: u8,
    pub minute: u8,
    pub targets: Vec<Target>,
}

impl SetRequest {
    pub fn parse(json: &str) -> Result<Self, RequestError> {
        let wire: Wire = serde_json::from_str(json).map_err(|_| RequestError::Malformed)?;
        if wire.hour > 23 || wire.minute > 59 {
            return Err(RequestError::InvalidTime);
        }
        if wire.enabled {
            if wire.targets.is_empty() {
                return Err(RequestError::NoTargets);
            }
            if wire.targets.len() > MAX_TARGETS {
                return Err(RequestError::TooManyTargets);
            }
            for target in &wire.targets {
                patch::validate_target(
                    &target.service,
                    &target.image,
                    &target.resolved_version,
                    &target.sites,
                )
                .map_err(RequestError::InvalidTarget)?;
            }
            let mut seen = std::collections::HashSet::new();
            if !wire.targets.iter().all(|t| seen.insert(&t.service)) {
                return Err(RequestError::Malformed);
            }
            if wire.confirm != CONFIRMATION {
                return Err(RequestError::ConfirmationMissing);
            }
        }
        Ok(Self {
            enabled: wire.enabled,
            hour: wire.hour,
            minute: wire.minute,
            targets: if wire.enabled {
                wire.targets
            } else {
                Vec::new()
            },
        })
    }
}

/// The stored window; `None` when it was never configured.
pub fn load(path: &Path) -> io::Result<Option<Window>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_str(&text).map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the patch window file is invalid",
        )
    })
}

/// Root-only, atomically replaced.
pub fn store(path: &Path, window: &Window) -> io::Result<()> {
    let temporary = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(
        serde_json::to_string_pretty(window)
            .expect("serializes")
            .as_bytes(),
    )?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&temporary, path)
}

/// The window after `request`: switching it on stores the approved targets
/// and clears every block (a new confirmation is a new decision); switching
/// it off keeps the last run for the record and approves nothing.
pub fn after_set(previous: Option<Window>, request: &SetRequest, now: u64) -> Window {
    Window {
        schema_version: 1,
        enabled: request.enabled,
        hour: request.hour,
        minute: request.minute,
        approved_at_unix_secs: if request.enabled {
            now
        } else {
            previous.as_ref().map_or(0, |w| w.approved_at_unix_secs)
        },
        targets: request.targets.clone(),
        blocked: Vec::new(),
        last: previous.and_then(|w| w.last),
    }
}

/// The fixed systemd units of the daily run, for a server-local time. Only
/// the two numbers (validated) vary.
pub fn timer_units(hour: u8, minute: u8) -> (String, String) {
    let service = "[Unit]\n\
Description=OrbDen service patch window (approved images only)\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/bin/sh -c 'exec /usr/local/bin/ops-engine runtime run-patch-window --request-id \"$(cat /proc/sys/kernel/random/uuid)\"'\n\
TimeoutStartSec=3600\n"
        .to_owned();
    let timer = format!(
        "[Unit]\n\
Description=OrbDen service patch window, daily at {hour:02}:{minute:02} server time\n\
\n\
[Timer]\n\
OnCalendar=*-*-* {hour:02}:{minute:02}:00\n\
Persistent=false\n\
\n\
[Install]\n\
WantedBy=timers.target\n"
    );
    (service, timer)
}

pub fn sync_timer(
    window: &Window,
    unit_dir: &Path,
    run_dir: &Path,
    program: &str,
) -> crate::security_timer::Timer {
    let (service, timer) = timer_units(window.hour, window.minute);
    crate::security_timer::sync_units(
        UNIT_NAME,
        (&service, &timer),
        window.enabled,
        unit_dir,
        run_dir,
        program,
    )
}

/// Whether the daily timer's unit file is there (read-only).
pub fn timer_installed(unit_dir: &Path) -> bool {
    unit_dir.join(format!("{UNIT_NAME}.timer")).is_file()
}

/// The webhook channels the backup agents and the other agents already use:
/// `/root/.wcp/notify.conf`, written by the panel.
pub const NOTIFY_FILE: &str = "/root/.wcp/notify.conf";

/// What to tell the channels about a run: the services that failed, or
/// `None` when nothing failed (a successful or skipped run is not news).
/// Names and the engine's own short reason only; no image, no secret.
pub fn failure_summary(last: &LastRun) -> Option<(String, serde_json::Value)> {
    let failed: Vec<&Outcome> = last
        .results
        .iter()
        .filter(|r| r.outcome == "failed")
        .collect();
    if failed.is_empty() {
        return None;
    }
    let lines: Vec<String> = failed
        .iter()
        .map(|r| {
            format!(
                "{}: {}",
                r.service,
                r.message.as_deref().unwrap_or("failed")
            )
        })
        .collect();
    let text = format!(
        "Service patch window: {} update(s) failed and were rolled back. {}",
        failed.len(),
        lines.join("; ")
    );
    let payload = serde_json::json!({
        "event": "service-patch-window",
        "status": "failed",
        "atUnixSecs": last.at_unix_secs,
        "failed": failed.iter().map(|r| serde_json::json!({
            "service": r.service, "message": r.message,
        })).collect::<Vec<_>>(),
    });
    Some((text, payload))
}

/// Posts `text`/`payload` to every enabled channel of `notify_file` that wants
/// failures (the same file, gates and bodies as the agents' `notify()`), one
/// `post(url, body)` each. Returns how many were sent. A missing or broken
/// file sends nothing; a failed post is not retried and never fails the run.
pub fn notify_failure(
    notify_file: &Path,
    text: &str,
    payload: &serde_json::Value,
    post: &mut dyn FnMut(&str, &str) -> bool,
) -> usize {
    let Ok(raw) = std::fs::read_to_string(notify_file) else {
        return 0;
    };
    let Ok(conf) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return 0;
    };
    let mut sent = 0;
    for channel in conf["channels"].as_array().into_iter().flatten() {
        if channel["enabled"].as_bool() == Some(false)
            || channel["on_failure"].as_bool() == Some(false)
        {
            continue;
        }
        let Some(url) = channel["webhook_url"]
            .as_str()
            .filter(|u| u.starts_with("https://"))
        else {
            continue;
        };
        let body = match channel["type"].as_str().unwrap_or("webhook") {
            "slack" => serde_json::json!({"text": text, "username": "OrbDen Engine"}),
            "discord" => serde_json::json!({"content": text}),
            _ => payload.clone(),
        };
        if post(url, &body.to_string()) {
            sent += 1;
        }
    }
    sent
}

/// The production `post`: `curl` with the address and body in a config read
/// from stdin, so the webhook address (a secret) is in no argument list.
pub fn curl_post(url: &str, body: &str) -> bool {
    use crate::process::{self, CancellationToken, ProcessLimits, ProcessRequest};
    let quote = |value: &str| {
        format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        )
    };
    let config = format!(
        "url = {}\nrequest = \"POST\"\nheader = \"Content-Type: application/json\"\ndata = {}\nmax-time = 10\nsilent\n",
        quote(url),
        quote(body)
    );
    process::run_with_stdin_bytes(
        &ProcessRequest::new("curl").args(["-K", "-"]),
        config.as_bytes(),
        &ProcessLimits {
            timeout: std::time::Duration::from_secs(30),
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
        &CancellationToken::default(),
    )
    .is_ok_and(|output| process::error_code(&output.termination).is_none())
}

#[derive(Debug)]
pub enum RunError {
    NotEnabled,
    Io(io::Error),
}

fn short(message: &str) -> String {
    message.chars().take(MAX_MESSAGE).collect()
}

/// One daily run: every approved, unblocked target in turn through `apply`.
/// A failure blocks that image and goes on to the next target.
pub fn run(
    path: &Path,
    now: u64,
    apply: &mut dyn FnMut(&patch::Request) -> Result<PatchResult, PatchError>,
) -> Result<LastRun, RunError> {
    let mut window = load(path)
        .map_err(RunError::Io)?
        .ok_or(RunError::NotEnabled)?;
    if !window.enabled {
        return Err(RunError::NotEnabled);
    }
    let mut results = Vec::new();
    for target in window.targets.clone() {
        let is_blocked = window
            .blocked
            .iter()
            .any(|b| b.service == target.service && b.image == target.image);
        if is_blocked {
            results.push(Outcome {
                service: target.service.clone(),
                outcome: "skipped".into(),
                message: Some(
                    "this image failed before and is blocked until it is approved again".into(),
                ),
            });
            continue;
        }
        let request = match patch::Request::for_window(
            &target.service,
            &target.image,
            &target.resolved_version,
            &target.sites,
        ) {
            Ok(request) => request,
            Err(error) => {
                results.push(Outcome {
                    service: target.service.clone(),
                    outcome: "failed".into(),
                    message: Some(short(error.message())),
                });
                continue;
            }
        };
        match apply(&request) {
            Ok(result) => results.push(Outcome {
                service: target.service.clone(),
                outcome: if result.changed {
                    "updated"
                } else {
                    "alreadyCurrent"
                }
                .into(),
                message: None,
            }),
            Err(error @ (PatchError::NotAPatch(_) | PatchError::Preflight(_))) => {
                // Not a patch of what runs now, or another stack operation is
                // running: nothing changed, nothing is blocked.
                results.push(Outcome {
                    service: target.service.clone(),
                    outcome: "skipped".into(),
                    message: Some(short(&error.protocol().1)),
                });
            }
            Err(error) => {
                let reason = short(&error.protocol().1);
                window.blocked.push(Blocked {
                    service: target.service.clone(),
                    image: target.image.clone(),
                    reason: reason.clone(),
                    at_unix_secs: now,
                });
                results.push(Outcome {
                    service: target.service.clone(),
                    outcome: "failed".into(),
                    message: Some(reason),
                });
            }
        }
    }
    if window.blocked.len() > MAX_BLOCKED {
        let extra = window.blocked.len() - MAX_BLOCKED;
        window.blocked.drain(..extra);
    }
    let last = LastRun {
        at_unix_secs: now,
        results,
    };
    window.last = Some(last.clone());
    store(path, &window).map_err(RunError::Io)?;
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_A: &str = "ghcr.io/orbden/valkey:9@sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const IMAGE_B: &str = "ghcr.io/orbden/postgres:18@sha256:0000000000000000000000000000000000000000000000000000000000000002";

    fn request(enabled: bool, confirm: &str, services: &[(&str, &str)]) -> String {
        let targets: Vec<_> = services
            .iter()
            .map(|(service, image)| {
                serde_json::json!({
                    "service": service, "image": image,
                    "resolvedVersion": "9.1.4", "sites": ["a.example.test"]
                })
            })
            .collect();
        serde_json::json!({
            "enabled": enabled, "hour": 3, "minute": 30,
            "targets": targets, "confirm": confirm
        })
        .to_string()
    }

    #[test]
    fn switching_it_on_needs_the_exact_confirmation_and_valid_targets() {
        let ok = request(true, CONFIRMATION, &[("valkey-9", IMAGE_A)]);
        assert!(SetRequest::parse(&ok).is_ok());
        for (json, why) in [
            (request(true, "yes", &[("valkey-9", IMAGE_A)]), "confirm"),
            (request(true, CONFIRMATION, &[]), "no targets"),
            (
                request(
                    true,
                    CONFIRMATION,
                    &[("valkey-9", "docker.io/evil@sha256:00")],
                ),
                "image",
            ),
            (
                request(true, CONFIRMATION, &[("Valkey 9;", IMAGE_A)]),
                "service",
            ),
            (
                request(
                    true,
                    CONFIRMATION,
                    &[("valkey-9", IMAGE_A), ("valkey-9", IMAGE_A)],
                ),
                "duplicate",
            ),
            (r#"{"enabled":true,"hour":24,"minute":0}"#.into(), "hour"),
            (r#"{"enabled":true,"hour":1,"minute":60}"#.into(), "minute"),
            ("not json".into(), "json"),
        ] {
            assert!(SetRequest::parse(&json).is_err(), "{why}");
        }
        // Off needs neither targets nor a confirmation.
        let off = SetRequest::parse(r#"{"enabled":false,"hour":3,"minute":0}"#).unwrap();
        assert!(!off.enabled && off.targets.is_empty());
    }

    #[test]
    fn the_units_are_fixed_text_with_only_the_validated_time() {
        let (service, timer) = timer_units(3, 5);
        assert!(service.contains("runtime run-patch-window --request-id"));
        assert!(timer.contains("OnCalendar=*-*-* 03:05:00"));
        assert!(timer.contains("Persistent=false"));
        assert!(!service.contains("03:05"));
    }

    fn setup(targets: &[(&str, &str)]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("window.json");
        let set = SetRequest::parse(&request(true, CONFIRMATION, targets)).unwrap();
        store(&path, &after_set(None, &set, 100)).unwrap();
        (dir, path)
    }

    fn done(service: &str, changed: bool) -> PatchResult {
        PatchResult {
            service: service.into(),
            changed,
            previous_image: "old".into(),
            image: "new".into(),
            previous_version: None,
            version: "9.1.4".into(),
            sites: vec![],
            fix_id: None,
            completed_at_unix_secs: 1,
        }
    }

    #[test]
    fn a_run_updates_what_changes_skips_a_non_patch_and_blocks_what_fails() {
        let (_dir, path) = setup(&[("valkey-9", IMAGE_A), ("postgres-18", IMAGE_B)]);
        let mut calls = Vec::new();
        let last = run(&path, 200, &mut |request| {
            calls.push(request.service.clone());
            if request.service == "valkey-9" {
                Ok(done("valkey-9", true))
            } else {
                Err(PatchError::ServiceUnknown)
            }
        })
        .unwrap();
        assert_eq!(calls, ["valkey-9", "postgres-18"]);
        assert_eq!(last.results[0].outcome, "updated");
        assert_eq!(last.results[1].outcome, "failed");
        let window = load(&path).unwrap().unwrap();
        assert_eq!(window.blocked.len(), 1);
        assert_eq!(window.blocked[0].service, "postgres-18");
        assert_eq!(window.last.unwrap().at_unix_secs, 200);

        // The next day the failed image is not tried again; the other is
        // already current.
        let mut calls = Vec::new();
        let again = run(&path, 300, &mut |request| {
            calls.push(request.service.clone());
            Ok(done(&request.service, false))
        })
        .unwrap();
        assert_eq!(calls, ["valkey-9"], "a blocked image must not be retried");
        assert_eq!(again.results[0].outcome, "alreadyCurrent");
        assert_eq!(again.results[1].outcome, "skipped");

        // A new confirmation is a new decision: the block is gone.
        let set = SetRequest::parse(&request(
            true,
            CONFIRMATION,
            &[("valkey-9", IMAGE_A), ("postgres-18", IMAGE_B)],
        ))
        .unwrap();
        let renewed = after_set(load(&path).unwrap(), &set, 400);
        assert!(renewed.blocked.is_empty());
        assert!(
            renewed.last.is_some(),
            "the last run is kept for the record"
        );
    }

    #[test]
    fn something_that_is_not_a_patch_or_a_busy_stack_is_skipped_not_blocked() {
        let (_dir, path) = setup(&[("valkey-9", IMAGE_A)]);
        let last = run(&path, 200, &mut |_| {
            Err(PatchError::NotAPatch("older image"))
        })
        .unwrap();
        assert_eq!(last.results[0].outcome, "skipped");
        assert!(load(&path).unwrap().unwrap().blocked.is_empty());
    }

    #[test]
    fn a_run_without_an_enabled_window_does_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("window.json");
        let mut called = false;
        assert!(matches!(
            run(&path, 1, &mut |_| {
                called = true;
                Err(PatchError::ServiceUnknown)
            }),
            Err(RunError::NotEnabled)
        ));
        let off = SetRequest::parse(r#"{"enabled":false,"hour":3,"minute":0}"#).unwrap();
        store(&path, &after_set(None, &off, 1)).unwrap();
        assert!(matches!(
            run(&path, 1, &mut |_| unreachable!()),
            Err(RunError::NotEnabled)
        ));
        assert!(!called);
    }

    #[test]
    fn only_a_failed_run_is_news_and_the_channels_keep_their_gates() {
        let ok = LastRun {
            at_unix_secs: 1,
            results: vec![
                Outcome {
                    service: "a".into(),
                    outcome: "updated".into(),
                    message: None,
                },
                Outcome {
                    service: "b".into(),
                    outcome: "skipped".into(),
                    message: Some("busy".into()),
                },
            ],
        };
        assert!(failure_summary(&ok).is_none());
        let bad = LastRun {
            at_unix_secs: 7,
            results: vec![Outcome {
                service: "valkey-9".into(),
                outcome: "failed".into(),
                message: Some("did not become healthy".into()),
            }],
        };
        let (text, payload) = failure_summary(&bad).unwrap();
        assert!(text.contains("valkey-9: did not become healthy"), "{text}");
        assert_eq!(payload["event"], "service-patch-window");

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("notify.conf");
        std::fs::write(
            &file,
            serde_json::json!({"channels": [
                {"type": "slack", "webhook_url": "https://hooks.example/slack"},
                {"type": "discord", "webhook_url": "https://hooks.example/discord", "on_failure": true},
                {"type": "webhook", "webhook_url": "https://hooks.example/plain"},
                {"type": "slack", "webhook_url": "https://hooks.example/off", "enabled": false},
                {"type": "slack", "webhook_url": "https://hooks.example/quiet", "on_failure": false},
                {"type": "slack", "webhook_url": "http://insecure.example/x"},
                {"type": "slack", "webhook_url": ""},
            ]})
            .to_string(),
        )
        .unwrap();
        let mut posted = Vec::new();
        let sent = notify_failure(&file, &text, &payload, &mut |url, body| {
            posted.push((url.to_owned(), body.to_owned()));
            true
        });
        assert_eq!(sent, 3);
        let urls: Vec<&str> = posted.iter().map(|(u, _)| u.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://hooks.example/slack",
                "https://hooks.example/discord",
                "https://hooks.example/plain"
            ]
        );
        assert!(posted[0].1.contains("\"text\"") && posted[0].1.contains("OrbDen Engine"));
        assert!(posted[1].1.contains("\"content\""));
        assert!(posted[2].1.contains("\"event\":\"service-patch-window\""));
        // A failed post is not counted and nothing else breaks.
        assert_eq!(notify_failure(&file, &text, &payload, &mut |_, _| false), 0);
        // No file, no channels.
        assert_eq!(
            notify_failure(&dir.path().join("none"), &text, &payload, &mut |_, _| true),
            0
        );
    }

    #[test]
    fn the_curl_post_sends_the_exact_body_and_keeps_the_address_out_of_argv() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buffer = [0u8; 4096];
            // Read until the body (Content-Length) has arrived.
            loop {
                let n = stream.read(&mut buffer).unwrap();
                seen.extend_from_slice(&buffer[..n]);
                let text = String::from_utf8_lossy(&seen).into_owned();
                if let Some(at) = text.find("\r\n\r\n") {
                    let length = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if seen.len() >= at + 4 + length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        // Quotes, a backslash, a newline and a non-ASCII letter survive.
        let body = r#"{"text":"a \"quoted\" \\ line\nnext é"}"#;
        assert!(curl_post(
            &format!("http://127.0.0.1:{port}/hook/secret-token"),
            body
        ));
        let request = server.join().unwrap();
        assert!(
            request.starts_with("POST /hook/secret-token HTTP/1.1"),
            "{request}"
        );
        assert!(
            request
                .to_lowercase()
                .contains("content-type: application/json")
        );
        assert!(request.ends_with(body), "{request}");
        // Nothing listens: a failed post is false, not a panic.
        assert!(!curl_post("http://127.0.0.1:9/x", "{}"));
    }

    #[test]
    fn the_file_is_root_only_and_a_corrupt_one_is_an_error_not_an_empty_window() {
        let (_dir, path) = setup(&[("valkey-9", IMAGE_A)]);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&path, "{broken").unwrap();
        assert!(load(&path).is_err());
    }
}
