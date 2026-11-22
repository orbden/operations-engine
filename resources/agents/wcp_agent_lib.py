"""Shared helpers for WCP bundled agent scripts.

Uploaded alongside every agent script into /root/.wcp/agents/ so any of them
can `sys.path.insert(0, WCP_DIR + "/agents"); import wcp_agent_lib`.

The library is shared by all agents and installing any one agent rewrites the
shared file, so every change must stay backward compatible with the agents
already installed.
"""

import json
import os
import re
import subprocess


def shell_quote(s):
    """Single-quote `s` for safe interpolation into a shell command string."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def run(cmd, timeout=60):
    """Run `cmd` (a shell string) and return the completed process."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def run_argv(argv, timeout=60):
    """Run `argv` (a list, no shell) and return the completed process.

    Use this instead of `run` for any argument that isn't fully trusted
    (e.g. a filename reported by a container) - there's no shell to
    re-parse it, so it can't break out of quoting.
    """
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def read_json(path, default=None):
    """Load JSON from `path`, returning `default` if missing/unreadable."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, data):
    """Write `data` as JSON to `path`, creating parent directories as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f)


def log_entry(log_file, entry, max_lines=2000):
    """Append `entry` as a JSON line to `log_file`, trimming to `max_lines`."""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "a") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    try:
        with open(log_file) as f:
            lines = f.readlines()
        if len(lines) > max_lines:
            with open(log_file, "w") as f:
                f.writelines(lines[-max_lines:])
    except Exception:
        pass


# The Compose project the panel manages; its services carry these labels.
COMPOSE_PROJECT = "wcp"


def compose_service_container(service, running=True):
    """Id of the container of `service` in the managed Compose project, or ""
    when there is none. With `running=False` a stopped container counts too,
    so "not running" and "never created" can be told apart. Raises when Docker
    cannot be asked: an unreadable answer is not "no container".
    """
    if not isinstance(service, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", service):
        raise ValueError("Invalid Compose service name")
    argv = ["docker", "ps", "-q"] + ([] if running else ["-a"]) + [
        "--filter", f"label=com.docker.compose.project={COMPOSE_PROJECT}",
        "--filter", f"label=com.docker.compose.service={service}",
    ]
    result = run_argv(argv)
    if result.returncode != 0:
        raise RuntimeError("Could not list the Compose containers")
    ids = result.stdout.split()
    return ids[0] if ids else ""


# Older installed agents and tests still reach for the private name.
_sh_esc = shell_quote


def make_logger(path, max_lines=2000):
    """Return `log(entry)` that appends to `path` through `log_entry`.

    Same file, line format and rotation as calling `log_entry(path, entry,
    max_lines)` directly; it only binds the path and the limit once.
    """
    def log(entry):
        log_entry(path, entry, max_lines)
    return log


def run_cmd(cmd, timeout=60, pipefail=False):
    """Run `cmd` and return the completed process.

    A string runs through the shell like `run`; a list runs without one like
    `run_argv`. `pipefail` runs a string under `bash -o pipefail -c` so a
    failing stage of a pipeline fails the whole command; it is for strings
    only.
    """
    if isinstance(cmd, (list, tuple)):
        if pipefail:
            raise ValueError("pipefail needs a shell string, not an argument list")
        return run_argv(list(cmd), timeout=timeout)
    if pipefail:
        cmd = "bash -o pipefail -c " + shell_quote(cmd)
    return run(cmd, timeout=timeout)


def notify(notify_file, is_failure, is_success, summary_text, event_payload, username="WCP Agent"):
    """Send `summary_text`/`event_payload` to every enabled channel in
    `notify_file` whose on_failure/on_success gate matches. `is_failure` and
    `is_success` are independent (not assumed complementary) so callers whose
    outcome can be neither (e.g. nothing to do) simply pass both False.
    """
    try:
        with open(notify_file) as f:
            notify_conf = json.load(f)
    except Exception:
        return

    for ch in notify_conf.get("channels", []):
        if not ch.get("enabled", True):
            continue
        send = (is_failure and ch.get("on_failure", True)) or \
               (is_success and ch.get("on_success", False))
        if not send:
            continue

        webhook_url = ch.get("webhook_url", "")
        if not webhook_url:
            continue

        ch_type = ch.get("type", "webhook")
        if ch_type == "slack":
            body = json.dumps({"text": summary_text, "username": username})
        elif ch_type == "discord":
            body = json.dumps({"content": summary_text})
        else:
            body = json.dumps(event_payload)

        subprocess.run(
            f"curl -s -m 10 -X POST -H 'Content-Type: application/json' "
            f"-d {shell_quote(body)} {shell_quote(webhook_url)}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )


def database_dump_command(db_type, container, password, database):
    """Stable SQL output allows a restore drill to compare the actual snapshot."""
    target = shell_quote(container)
    secret = shell_quote(password)
    name = shell_quote(database)
    if db_type == "mariadb":
        return (f"docker exec -e MYSQL_PWD={secret} {target} mariadb-dump -uroot "
                f"--single-transaction --routines --triggers --skip-comments "
                f"--skip-extended-insert --order-by-primary --skip-add-locks --skip-disable-keys {name}")
    if db_type == "postgres":
        return (f"docker exec -e PGPASSWORD={secret} {target} pg_dump -U postgres "
                f"--no-owner --no-privileges --inserts --rows-per-insert=1 {name}")
    raise ValueError("Unsupported database type")


def sql_digest(stream):
    """Ignore only pg_dump's random psql guard token, which is not SQL data."""
    import hashlib
    import re
    digest = hashlib.sha256()
    size = 0
    for line in stream:
        if re.fullmatch(rb"\\(?:un)?restrict [A-Za-z0-9]+\r?\n?", line):
            continue
        digest.update(line)
        size += len(line)
    if size == 0:
        raise ValueError("Empty SQL dump")
    return digest.hexdigest()
