#!/usr/bin/env bash
set -euo pipefail

release_tag="${RELEASE_TAG:-}"
if [[ -z "${release_tag}" ]]; then
  echo "::error::RELEASE_TAG is not set." >&2
  exit 1
fi

if git rev-parse --verify --quiet "${release_tag}"; then
  echo "::error::Tag '${release_tag}' already exists" >&2
  exit 1
fi

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

commit_sha="${GITHUB_SHA:-}"
if [[ -z "${commit_sha}" ]]; then
  commit_sha="$(git rev-parse HEAD)"
fi

git tag -a "${release_tag}" "${commit_sha}" -m "Release ${release_tag}"
git push origin "refs/tags/${release_tag}"

echo "::notice::Created and pushed tag ${release_tag} at ${commit_sha}."

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_STEP_SUMMARY}")"
  {
    echo
    echo "## Release tag pushed"
    echo
    echo "- Tag: ${release_tag}"
    echo "- Commit: ${commit_sha}"
  } >> "${GITHUB_STEP_SUMMARY}"
fi
