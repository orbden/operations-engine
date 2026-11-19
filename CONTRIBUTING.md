# Contributing

Operations Engine is at an early stage. Protocol and security decisions should
be made explicitly before adding mutating server operations.

## Local checks

Run all checks before opening a pull request:

```console
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

After pushing, `scripts/ci-local.sh` runs the same checks and the minimum
supported Rust version check declared in `Cargo.toml`, reports them as the two
commit statuses branch protection requires, and keeps one result comment on the
pull request. Checks are not run in GitHub Actions.

## Design rules

- Keep stdout reserved for protocol output after CLI arguments are accepted.
- Send diagnostic information to stderr.
- Do not expose secrets, credentials, private keys, or raw environment dumps.
- Use stable, documented operation names and error codes.
- Keep protocol compatibility independent from the crate version.
- Start subprocesses with an executable and explicit arguments. Avoid `sh -c`.
- Run subprocesses through the bounded runner in `src/process.rs`; do not call
  `std::process::Command` directly from operation modules.
- Validate all identifiers and paths again at the server execution boundary.
- Add integration tests for every command's public JSON shape.
- Do not advertise an operation through `capabilities` before it is implemented.

## Shared helpers: use them, do not re-create them

Before writing a helper, grep for it. If one exists and almost fits, extend it
with a test instead of making a copy.

| Need | Use | Where |
| --- | --- | --- |
| Lowercase hex text | `hex` | `src/util.rs` |
| SHA-256 of bytes or a reader | `sha256_hex`, `sha256_reader` | `src/util.rs` |
| Generated secret text | `random_alnum` | `src/util.rs` |
| PHP single-quoted literal | `php_single_quote` | `src/util.rs` |
| Cut text at a byte limit on a char boundary | `truncate_utf8_head`, `truncate_utf8_tail` | `src/util.rs` |
| Refuse an oversized input without buffering it | `read_bounded` | `src/util.rs` |
| First/rest character-class loop of a validator | `charset_ok` | `src/util.rs` |
| Set keys in a Compose `.env` atomically | `update_env_atomic` | `src/util.rs` |
| Unix time now, civil date to days | `unix_now_secs`, `unix_now_secs_i64`, `days_from_civil` | `src/clock.rs` |
| DNS name or IPv4 of a network peer | `is_dns_name_or_ipv4` | `src/host_name.rs` |
| Captured subprocess output as text | `CapturedOutput::text` | `src/process.rs` |
| Meilisearch backup name rules | `name_first_ok`, `valid_dump_uid` | `src/meilisearch_upgrade/cleanup.rs` |
| Shell word in a unit-test fake program | `shell_quote` | `src/test_support.rs` |
| `OWNER/NAME` from a remote URL in scripts | `repo_slug_from_url` | `scripts/repo-slug.sh` |

- Each validator keeps its own limits and character set and shares only the
  loop (`charset_ok`). Do not widen one validator to match another, and do not
  copy the loop.
- Validation, escaping and quoting helpers change only together with table
  tests of accepted and rejected inputs.
- `tests/contributing_helpers.rs` fails when a name in the table is no longer
  defined in its file. Update the table when you move or rename a helper.

## Adding a command

1. Define its CLI shape in `src/cli.rs`.
2. Implement it in a dedicated module under `src/commands`.
3. Return a protocol `Response`; do not print from the command module.
4. Register the operation in `capabilities` only when it is usable.
5. Add integration tests under `tests/`.
6. Document security boundaries, failure states, and recovery behavior for any
   mutation.

Mutating commands additionally require an idempotency strategy, locking rules,
an audit event shape, interruption tests, and an explicit recovery procedure.

See [`docs/subprocess.md`](./docs/subprocess.md) before adding an external
process.

Filesystem operations beneath configured roots must use the capability-based
`ManagedRoot` API in `src/filesystem.rs`. `TrustedRoot::join` is for display and
planning only; it is not mutation authorization.
