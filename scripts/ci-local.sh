#!/usr/bin/env bash
# Local CI: runs the checks of the old hosted workflow and reports each one as
# a commit status on HEAD, so a pull request shows the same two checks that
# branch protection requires. Hosted Actions are no longer used.
#
# Besides the two commit statuses it keeps one comment on the branch's open pull
# request (found by a hidden marker, edited in place on every run) with the
# result per check, the commit and the time.
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

results=()

run_check() { # context command...
  local context="$1"
  shift
  post pending "$context" "running locally"
  local started=$SECONDS
  if "$@"; then
    post success "$context" "passed locally on $(date -u +%Y-%m-%dT%H:%MZ)"
    results+=("| $context | passed | $((SECONDS - started)) s |")
    echo "ci-local: $context passed"
  else
    post failure "$context" "failed locally"
    results+=("| $context | **FAILED** | $((SECONDS - started)) s |")
    echo "ci-local: $context FAILED" >&2
    return 1
  fi
}

# One comment per pull request, found by its marker and edited in place, so
# repeated runs do not pile up. Never changes the exit code.
comment() {
  [[ $report -eq 1 ]] || return 0
  local branch pr marker body id
  branch="$(git rev-parse --abbrev-ref HEAD)"
  pr="$(gh pr list --head "$branch" --state open --json number --jq '.[0].number' 2>/dev/null || true)"
  [[ -n "$pr" ]] || return 0
  marker='<!-- ci-local -->'
  body="$marker
**Local checks** on \`${sha:0:8}\` ($(date -u +%Y-%m-%dT%H:%MZ)): $([[ $failed -eq 0 ]] && echo passed || echo FAILED)

| Check | Result | Time |
| --- | --- | --- |
$(printf '%s\n' "${results[@]}")

Run on the author's machine by \`scripts/ci-local.sh\`; hosted CI is not used."
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

lint_and_test() {
  cargo fmt --all --check &&
    cargo clippy --all-targets --all-features -- -D warnings &&
    cargo test --all-features
}

failed=0
run_check "Format, lint, and test" lint_and_test || failed=1
run_check "Minimum Rust version" cargo +1.88.0 check --all-features || failed=1
comment
exit $failed
