#!/usr/bin/env bash
set -euo pipefail

# prune_branches.sh
# Lists (and optionally prunes) remote feature branches that have been inactive for more than
# the configured number of seconds. The script tolerates branches without committer timestamps
# and skips protected namespaces by default.

usage() {
  cat <<'USAGE'
Usage: scripts/prune_branches.sh [--prune]

Without arguments the script prints the inactive remote branches. Passing --prune deletes the
listed branches after an interactive confirmation.
USAGE
}

maybe_confirm() {
  local prompt=$1
  read -r -p "${prompt} [y/N] " reply || return 1
  case ${reply} in
    [yY][eE][sS]|[yY])
      return 0
      ;;
    *)
      echo "Aborted" >&2
      return 1
      ;;
  esac
}

main() {
  local prune=false
  if [[ $# -gt 0 ]]; then
    case $1 in
      --prune)
        prune=true
        shift
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        usage >&2
        return 1
        ;;
    esac
  fi

  if ! command -v gh >/dev/null 2>&1; then
    echo "The GitHub CLI (gh) is required" >&2
    return 1
  fi

  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required" >&2
    return 1
  fi

  local repo
  repo=$(gh repo view --json nameWithOwner -q .nameWithOwner)

  local cutoff
  cutoff=${CARGO_WARDEN_PRUNE_AGE:-172800}

  mapfile -t branches < <(
    gh api "repos/${repo}/branches" --paginate \
      | jq --argjson cutoff "${cutoff}" -r '
          .[]
          | select(.name | test("^(main|master|develop|prod|production|stable|release($|[-/_0-9].*))$"; "i") | not)
          | select(.commit != null and .commit.committer != null and .commit.committer.date != null)
          | select((now - (.commit.committer.date | fromdateiso8601)) > $cutoff)
          | "\(.name)\t\(.commit.committer.date)"
        '
  )

  if [[ ${#branches[@]} -eq 0 ]]; then
    echo "No candidate branches found"
    return 0
  fi

  printf "Candidate branches older than %s seconds:\n" "${cutoff}"
  printf '  %s\n' "${branches[@]}"

  if [[ ${prune} == true ]]; then
    maybe_confirm "Delete the listed branches from origin?" || return 1
    for entry in "${branches[@]}"; do
      local name
      name=${entry%%$'\t'*}
      echo "Deleting origin/${name}"
      gh api "repos/${repo}/git/refs/heads/${name}" -X DELETE >/dev/null
    done
  fi
}

main "$@"
