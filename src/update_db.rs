//! The database steps every recovery-first update shares: a MySQL/MariaDB
//! client call inside the database container, the dump for a recovery bundle,
//! and emptying the site's database before an import. Used by the Drupal,
//! Joomla and Nextcloud updates.

use crate::{
    drupal_action::{DbConnection, MAX_OUTPUT},
    process::{self, CancellationToken, ProcessLimits, ProcessRequest},
};

/// Why emptying the database failed. The text is fixed; no tool output.
#[derive(Debug)]
pub enum DbError {
    Run(process::ProcessRunError),
    Failed(&'static str),
}

fn exited_ok(output: &process::ProcessOutput) -> bool {
    crate::drupal_action::exited_ok(output)
}

/// The container to `docker exec` into for a database host `host`. A site of
/// the managed stack names its database by the Compose service alias
/// (`mariadb-11`), which is not a container name; the one running container of
/// the stack project with that service label is used. Any other host (a plain
/// container) is its own container name. `host` has to be a valid container
/// name already; a lookup that does not give exactly one id is not guessed
/// at, the host stays as it is.
pub(crate) fn resolve_container(
    docker_program: &str,
    host: &str,
    cancel: &CancellationToken,
) -> String {
    let request = ProcessRequest::new(docker_program).args([
        "ps".to_owned(),
        "-q".into(),
        "--no-trunc".into(),
        "--filter".into(),
        format!(
            "label=com.docker.compose.project={}",
            crate::compose::COMPOSE_PROJECT
        ),
        "--filter".into(),
        format!("label=com.docker.compose.service={host}"),
    ]);
    let limits = ProcessLimits {
        timeout: std::time::Duration::from_secs(30),
        max_stdout_bytes: 4096,
        max_stderr_bytes: 4096,
    };
    let Ok(output) = process::run(&request, &limits, cancel) else {
        return host.to_owned();
    };
    let text = output.stdout.text();
    let ids: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    match ids.as_slice() {
        [id] if exited_ok(&output)
            && id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            (*id).to_owned()
        }
        _ => host.to_owned(),
    }
}

/// MySQL/MariaDB client call in the database container, with the password
/// only in the environment of that one `docker exec`.
pub(crate) fn db_client(docker_program: &str, connection: &DbConnection) -> ProcessRequest {
    ProcessRequest::new(docker_program)
        .env("MYSQL_PWD", &connection.password)
        .args([
            "exec".to_owned(),
            "-i".into(),
            "-e".into(),
            "MYSQL_PWD".into(),
            connection.host.clone(),
            "mariadb".into(),
            format!("-u{}", connection.user),
            connection.database.clone(),
        ])
}

/// Streams a `mariadb-dump` of the site's database into `file` through the
/// database container's own client; the password travels only in the
/// environment of that one `docker exec`. Used by the recovery bundles.
pub(crate) fn dump(
    docker_program: &str,
    connection: &DbConnection,
    file: std::fs::File,
    limits: &ProcessLimits,
    cancel: &CancellationToken,
) -> Result<(), DbError> {
    let request = ProcessRequest::new(docker_program)
        .env("MYSQL_PWD", &connection.password)
        .args([
            "exec".to_owned(),
            "-i".into(),
            "-e".into(),
            "MYSQL_PWD".into(),
            connection.host.clone(),
            "mariadb-dump".into(),
            format!("-u{}", connection.user),
            "--single-transaction".into(),
            "--routines".into(),
            "--triggers".into(),
            connection.database.clone(),
        ]);
    let output =
        process::run_with_stdout_file(&request, file, limits, cancel).map_err(DbError::Run)?;
    if !exited_ok(&output) {
        return Err(DbError::Failed("the database could not be dumped"));
    }
    Ok(())
}

/// Drops every table and view of the site's database through the database
/// container's own client (the PHP container usually has none, which rules
/// out `drush sql:drop`). Names are read back from `information_schema` and
/// quoted here; a name with a backslash or control character is refused
/// rather than guessed.
pub(crate) fn empty_database(
    docker_program: &str,
    connection: &DbConnection,
    limits: &ProcessLimits,
    cancel: &CancellationToken,
) -> Result<(), DbError> {
    let list_limits = ProcessLimits {
        timeout: limits.timeout,
        max_stdout_bytes: 4 * 1024 * 1024,
        max_stderr_bytes: MAX_OUTPUT,
    };
    let mut request = db_client(docker_program, connection);
    request = request.args([
        "-N".to_owned(),
        "-B".into(),
        "-e".into(),
        "SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = DATABASE()"
            .into(),
    ]);
    let listed = process::run(&request, &list_limits, cancel).map_err(DbError::Run)?;
    if !exited_ok(&listed) {
        return Err(DbError::Failed("the database tables could not be listed"));
    }
    let text = String::from_utf8(listed.stdout.bytes)
        .map_err(|_| DbError::Failed("the table list was unreadable"))?;
    let mut script = String::from("SET FOREIGN_KEY_CHECKS=0;\n");
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (name, kind) = line
            .split_once('\t')
            .ok_or(DbError::Failed("the table list was unreadable"))?;
        if name.chars().any(|c| c == '\\' || c.is_control()) {
            return Err(DbError::Failed("a table name cannot be quoted safely"));
        }
        let object = if kind == "VIEW" { "VIEW" } else { "TABLE" };
        script.push_str(&format!(
            "DROP {object} IF EXISTS `{}`;\n",
            name.replace('`', "``")
        ));
    }
    let dropped = process::run_with_stdin_bytes(
        &db_client(docker_program, connection),
        script.as_bytes(),
        limits,
        cancel,
    )
    .map_err(DbError::Run)?;
    if !exited_ok(&dropped) {
        return Err(DbError::Failed("the database tables could not be dropped"));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A fake `docker` whose `ps` answers `reply` and exits `code`.
    fn docker(dir: &std::path::Path, reply: &str, code: i32) -> String {
        let path = dir.join("docker");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nprintf '%s' '{reply}'\nexit {code}\n",
                log = dir.join("calls.log").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    #[test]
    fn a_stack_service_alias_becomes_its_one_running_container() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = CancellationToken::default();
        let program = docker(dir.path(), &format!("{ID}\n"), 0);
        assert_eq!(resolve_container(&program, "mariadb-11", &cancel), ID);
        let calls = std::fs::read_to_string(dir.path().join("calls.log")).unwrap();
        assert!(
            calls.contains("label=com.docker.compose.project=wcp"),
            "{calls}"
        );
        assert!(
            calls.contains("label=com.docker.compose.service=mariadb-11"),
            "{calls}"
        );
    }

    #[test]
    fn anything_but_exactly_one_container_leaves_the_host_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = CancellationToken::default();
        for (reply, code) in [
            ("", 0),
            (&format!("{ID}\n{ID}\n"), 0),
            ("not-an-id\n", 0),
            (&ID.to_uppercase(), 0),
            (&ID[..63], 0),
            (ID, 1),
        ] {
            let program = docker(dir.path(), reply, code);
            assert_eq!(
                resolve_container(&program, "plain-db", &cancel),
                "plain-db",
                "{reply:?} {code}"
            );
        }
        assert_eq!(
            resolve_container("/nonexistent/docker", "plain-db", &cancel),
            "plain-db"
        );
    }
}
