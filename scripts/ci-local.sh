#!/usr/bin/env bash
# Local CI: runs the checks of the old hosted workflow and reports each one as
# a commit status on HEAD, so a pull request shows the same two checks that
# branch protection requires. Hosted Actions are no longer used.
#
# Besides the two commit statuses it keeps one comment on the branch's open pull
# request (found by a hidden marker, edited in place on every run) with the
# result and time per step (test counts included), the full commit, whether it
# is pushed, how far behind main it is, the Rust versions and the host; a failed
# step adds the tail of its output.
#
# Usage: scripts/ci-local.sh [--no-report]
# Needs a clean tree (the result is attached to the commit, not the working
# copy), a pushed HEAD and an authenticated `gh` for reporting. Run it after
# every push; a new commit has no statuses until it is run again.
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

report=1
[[ "${1:-}" == "--no-report" ]] && report=0

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ci-local: the working tree is not clean; commit or stash first" >&2
  exit 2
fi

sha="$(git rev-parse HEAD)"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
if [[ $report -eq 1 && -z "$repo" ]]; then
  echo "ci-local: cannot resolve the GitHub repository (gh auth status)" >&2
  exit 2
fi

post() { # context state description
  [[ $report -eq 1 ]] || return 0
  gh api "repos/$repo/statuses/$sha" -f state="$1" -f context="$2" \
    -f description="$3" >/dev/null
}

rows=()      # one table row per step
failure_tail=""
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# step NAME SUMMARY_FN CMD...: runs CMD with its output kept in $log (and shown),
# adds a row with the time and, on success, what SUMMARY_FN prints about the log
# (for example the number of tests that ran). A failing step keeps the last
# lines of its output for the comment.
step() {
  local name="$1" summary="$2"
  shift 2
  local started=$SECONDS rc=0
  "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  local took=$((SECONDS - started))
  if [[ $rc -eq 0 ]]; then
    rows+=("| $name | passed | $("$summary") | $took s |")
  else
    rows+=("| $name | **FAILED** | exit $rc | $took s |")
    failure_tail="$(tail -n 25 "$log" | sed 's/\x1b\[[0-9;]*m//g')"
  fi
  return $rc
}

none() { :; }
# Sums every "test result" line of the log (the library, the integration
# binaries and the doc tests).
test_counts() {
  awk '/^test result: /{p+=$4; f+=$6; i+=$8} END{printf "%d passed, %d failed, %d ignored", p, f, i}' "$log"
}

run_check() { # context command...
  local context="$1"
  shift
  post pending "$context" "running locally"
  if "$@"; then
    post success "$context" "passed locally on $(date -u +%Y-%m-%dT%H:%MZ)"
    echo "ci-local: $context passed"
  else
    post failure "$context" "failed locally"
    echo "ci-local: $context FAILED" >&2
    return 1
  fi
}

lint_and_test() {
  step "cargo fmt --check" none cargo fmt --all --check &&
    step "cargo clippy -D warnings" none cargo clippy --all-targets --all-features -- -D warnings &&
    step "cargo test --all-features" test_counts cargo test --all-features
}

msrv_check() {
  step "cargo +1.88.0 check" none cargo +1.88.0 check --all-features
}

# One comment per pull request, found by its marker and edited in place, so
# repeated runs do not pile up. Never changes the exit code.
comment() {
  [[ $report -eq 1 ]] || return 0
  local branch pr marker body id verdict behind pushed
  branch="$(git rev-parse --abbrev-ref HEAD)"
  pr="$(gh pr list --head "$branch" --state open --json number --jq '.[0].number' 2>/dev/null || true)"
  [[ -n "$pr" ]] || return 0
  git fetch -q origin main "$branch" 2>/dev/null || true
  behind="$(git rev-list --count HEAD..origin/main 2>/dev/null || echo '?')"
  [[ "$(git rev-parse "origin/$branch" 2>/dev/null)" == "$sha" ]] && pushed=yes || pushed=NO
  verdict=$([[ $failed -eq 0 ]] && echo "all checks passed" || echo "FAILED")
  marker='<!-- ci-local -->'
  body="$marker
**Local checks: $verdict** on commit \`$sha\` ($(date -u +%Y-%m-%dT%H:%MZ))

| Step | Result | Detail | Time |
| --- | --- | --- | --- |
$(printf '%s\n' "${rows[@]}")

| What | Value |
| --- | --- |
| Commit | \`$sha\` on \`$branch\` |
| Tree | clean (the script refuses a dirty tree) |
| Pushed | $pushed (the commit above is the branch head on GitHub) |
| Behind \`main\` | $behind commit(s) |
| Rust | $(rustc --version) / MSRV $(rustc +1.88.0 --version 2>/dev/null || echo unavailable) |
| Host | $(uname -sm) |

Run by \`scripts/ci-local.sh\` on the author's machine; hosted CI is not used. The two required statuses on the commit say the same."
  if [[ -n "$failure_tail" ]]; then
    body="$body

<details><summary>Last output of the failing step</summary>

\`\`\`
$failure_tail
\`\`\`

</details>"
  fi
  id="$(gh api "repos/$repo/issues/$pr/comments" --paginate \
    --jq "[.[] | select(.body | startswith(\"$marker\"))][0].id // empty" 2>/dev/null || true)"
  if [[ -n "$id" ]]; then
    gh api -X PATCH "repos/$repo/issues/comments/$id" -f body="$body" >/dev/null 2>&1 ||
      echo "ci-local: could not update the PR comment" >&2
  else
    gh api "repos/$repo/issues/$pr/comments" -f body="$body" >/dev/null 2>&1 ||
      echo "ci-local: could not post the PR comment" >&2
  fi
}

failed=0
run_check "Format, lint, and test" lint_and_test || failed=1
run_check "Minimum Rust version" msrv_check || failed=1
comment
exit $failed
