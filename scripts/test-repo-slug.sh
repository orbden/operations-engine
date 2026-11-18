#!/usr/bin/env bash
# Tests repo_slug_from_url from scripts/repo-slug.sh.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/repo-slug.sh"
fail=0
ok() { # url expected
  local got
  got="$(repo_slug_from_url "$1")"
  [[ "$got" == "$2" ]] || { echo "FAIL $1: got '$got', want '$2'" >&2; fail=1; }
}
bad() {
  if repo_slug_from_url "$1" >/dev/null; then echo "FAIL $1: accepted" >&2; fail=1; fi
}
ok https://github.com/orbden/operations-engine.git orbden/operations-engine
ok https://github.com/orbden/operations-engine orbden/operations-engine
ok https://github.com/orbden/operations-engine/ orbden/operations-engine
ok https://user:token@github.com/orbden/operations-engine.git orbden/operations-engine
ok git@github.com:orbden/operations-engine.git orbden/operations-engine
ok git@github.com:orbden/operations-engine orbden/operations-engine
ok ssh://git@github.com/orbden/operations-engine.git orbden/operations-engine
ok ssh://git@github.com:22/orbden/operations-engine.git orbden/operations-engine
ok https://github.com/or.bden/my.repo.name.git or.bden/my.repo.name
bad ""
bad "not a url"
bad https://github.com/onlyowner
bad https://github.com/a/b/c
bad /local/path/repo.git
bad "git@github.com:a b/c"
[[ $fail -eq 0 ]] && echo "repo-slug tests passed"
exit $fail
