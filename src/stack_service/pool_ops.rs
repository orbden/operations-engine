use super::*;

pub fn reload(
    ctx: &Context<'_>,
    req: &ReloadRequest,
    cancel: &CancellationToken,
) -> Result<ReloadResult, Error> {
    run_admitted(
        ctx,
        RELOAD_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = req.service.name();
            compose(
                ctx,
                Stage::Reload,
                &[
                    "exec",
                    "-T",
                    &service,
                    "caddy",
                    "reload",
                    "--config",
                    LIVE_CONFIG_PATH,
                    "--adapter",
                    "caddyfile",
                ],
                RELOAD_TIMEOUT,
                cancel,
            )?;
            Ok(ReloadResult {
                service,
                reloaded_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn stop_idle_runtime(
    ctx: &Context<'_>,
    req: &StopRequest,
    cancel: &CancellationToken,
) -> Result<StopResult, Error> {
    run_admitted(
        ctx,
        STOP_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let site_configs = count_site_configs(ctx.runtime_root, &req.runtime_id)?;
            if site_configs == 0 {
                compose(ctx, Stage::Stop, &["stop", &service], STOP_TIMEOUT, cancel)?;
            }
            Ok(StopResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                stopped: site_configs == 0,
                site_configs,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn ensure_runtime(
    ctx: &Context<'_>,
    req: &EnsureRequest,
    cancel: &CancellationToken,
) -> Result<EnsureResult, Error> {
    run_admitted(
        ctx,
        ENSURE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let mut tail = Vec::new();
            if let Some(profile) = &req.profile {
                tail.extend(["--profile", profile.as_str()]);
            }
            tail.extend(["up", "-d", service.as_str()]);
            compose(ctx, Stage::Up, &tail, UP_TIMEOUT, cancel)?;
            wait_healthy(ctx, &service, cancel)?;
            Ok(EnsureResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                healthy_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

pub fn ensure_data_service(
    ctx: &Context<'_>,
    req: &EnsureDataServiceRequest,
    cancel: &CancellationToken,
) -> Result<EnsureDataServiceResult, Error> {
    run_admitted(
        ctx,
        ENSURE_DATA_SERVICE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let mut tail = Vec::new();
            if let Some(profile) = &req.profile {
                tail.extend(["--profile", profile.as_str()]);
            }
            tail.extend(["up", "-d", req.service.as_str()]);
            compose(ctx, Stage::Up, &tail, UP_TIMEOUT, cancel)?;
            wait_healthy(ctx, &req.service, cancel)?;
            Ok(EnsureDataServiceResult {
                service: req.service.clone(),
                healthy_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

/// Stops one PostgreSQL line, but only when it is provably empty: no database
/// besides the system ones and the bootstrap one, and no user table in the
/// bootstrap one. A line that is running but cannot be asked is left running
/// (the answer is unknown, never "empty"). A line that is not running is
/// already stopped.
pub fn stop_data_service(
    ctx: &Context<'_>,
    req: &StopDataServiceRequest,
    cancel: &CancellationToken,
) -> Result<StopDataServiceResult, Error> {
    run_admitted(
        ctx,
        STOP_DATA_SERVICE_OPERATION,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let running = !compose(
                ctx,
                Stage::Probe,
                &["ps", "-q", req.service.as_str()],
                PROBE_TIMEOUT,
                cancel,
            )?
            .trim()
            .is_empty();
            let (databases, bootstrap_tables) = if running {
                let out = compose(
                    ctx,
                    Stage::Probe,
                    &[
                        "exec",
                        "-T",
                        req.service.as_str(),
                        "sh",
                        "-c",
                        DATA_SERVICE_CONTENT_SCRIPT,
                    ],
                    PROBE_TIMEOUT,
                    cancel,
                )?;
                parse_content_counts(&out).ok_or(Error::ProbeUnexpected(
                    "the database list of the line could not be read",
                ))?
            } else {
                (0, 0)
            };
            let empty = databases == 0 && bootstrap_tables == 0;
            if running && empty {
                compose(
                    ctx,
                    Stage::Stop,
                    &["stop", req.service.as_str()],
                    STOP_TIMEOUT,
                    cancel,
                )?;
            }
            Ok(StopDataServiceResult {
                service: req.service.clone(),
                stopped: empty,
                databases,
                bootstrap_tables,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

/// `"<databases> <tables>"` as the content script prints it.
fn parse_content_counts(out: &str) -> Option<(u64, u64)> {
    let mut parts = out.split_whitespace();
    let databases = parts.next()?.parse().ok()?;
    let tables = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((databases, tables))
}

pub fn reload_workers(
    ctx: &Context<'_>,
    req: &RuntimeRequest,
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    runtime_action(
        ctx,
        RELOAD_WORKERS_OPERATION,
        Stage::ReloadWorkers,
        req,
        &["sh", "-c", RELOAD_WORKERS_SCRIPT],
        cancel,
    )
}

pub fn flush_fpc(
    ctx: &Context<'_>,
    req: &RuntimeRequest,
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    runtime_action(
        ctx,
        FLUSH_FPC_OPERATION,
        Stage::FlushFpc,
        req,
        &["sh", "-c", FLUSH_FPC_SCRIPT],
        cancel,
    )
}

/// `exec -T runtime-<id> <command>` under the stack lock.
pub(super) fn runtime_action(
    ctx: &Context<'_>,
    operation: &'static str,
    stage: Stage,
    req: &RuntimeRequest,
    command: &[&str],
    cancel: &CancellationToken,
) -> Result<RuntimeActionResult, Error> {
    run_admitted(
        ctx,
        operation,
        req.request_id,
        req.idempotency_key.as_ref(),
        || {
            let service = runtime_service(&req.runtime_id);
            let mut tail = vec!["exec", "-T", service.as_str()];
            tail.extend_from_slice(command);
            compose(ctx, stage, &tail, SIGNAL_TIMEOUT, cancel)?;
            Ok(RuntimeActionResult {
                runtime_id: req.runtime_id.as_str().to_owned(),
                service,
                completed_at_unix_secs: unix_now_secs(),
            })
        },
    )
}

#[cfg(test)]
mod count_tests {
    use super::parse_content_counts;

    #[test]
    fn counts_are_two_numbers_and_nothing_else() {
        for (out, want) in [
            ("0 0\n", Some((0, 0))),
            ("3 12", Some((3, 12))),
            ("", None),
            ("0", None),
            ("0 0 0", None),
            ("a 0", None),
            ("-1 0", None),
            ("psql: error", None),
        ] {
            assert_eq!(parse_content_counts(out), want, "{out:?}");
        }
    }
}
