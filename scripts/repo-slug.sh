# Sourced by ci-local.sh. repo_slug_from_url prints OWNER/NAME for a GitHub
# remote URL (https, ssh:// or scp-style git@host:owner/name, with or without
# a trailing .git or slash, optional credentials) and fails for anything else.
repo_slug_from_url() {
  local url="${1%/}" rest
  url="${url%.git}"
  case "$url" in
    https://* | http://* | ssh://* | git://*)
      rest="${url#*://}"
      rest="${rest#*@}" # drop credentials or the ssh user
      rest="${rest#*/}" # drop host[:port]
      ;;
    *@*:*) rest="${url#*:}" ;;
    *) return 1 ;;
  esac
  [[ "$rest" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || return 1
  printf '%s\n' "$rest"
}

# Prefers `gh`; when it cannot answer (no pull request or default repository
# yet, a fresh push) falls back to the origin remote URL.
resolve_repo() {
  local repo
  repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
  if [[ -z "$repo" ]]; then
    repo="$(repo_slug_from_url "$(git remote get-url origin 2>/dev/null || true)" 2>/dev/null || true)"
  fi
  printf '%s\n' "$repo"
}
