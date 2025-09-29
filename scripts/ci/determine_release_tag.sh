#!/usr/bin/env bash
set -euo pipefail

prefix="${RELEASE_PREFIX:-}"
if [[ -n "${prefix}" ]]; then
  if [[ ! "${prefix}" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "::error::RELEASE_PREFIX must match <major>.<minor>, got '${prefix}'." >&2
    exit 1
  fi
fi

mapfile -t existing_tags < <(git tag --list 'v*' | sort -V)

next_tag=""
if [[ -n "${prefix}" ]]; then
  base="v${prefix}."
  latest=""
  for tag in "${existing_tags[@]}"; do
    if [[ "${tag}" == "${base}"* ]]; then
      latest="${tag}"
    fi
  done
  if [[ -z "${latest}" ]]; then
    patch=1
  else
    version_body="${latest#${base}}"
    if [[ ! "${version_body}" =~ ^[0-9]+$ ]]; then
      echo "::error::Existing tag '${latest}' does not have an integer patch component." >&2
      exit 1
    fi
    patch=$((version_body + 1))
  fi
  next_tag="${base}${patch}"
else
  if [[ ${#existing_tags[@]} -eq 0 ]]; then
    next_tag="v0.0.1"
  else
    latest="${existing_tags[-1]}"
    if [[ ! "${latest}" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
      echo "::error::Cannot parse existing tag '${latest}'." >&2
      exit 1
    fi
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"
    next_tag="v${major}.${minor}.$((patch + 1))"
  fi
fi

echo "Next release tag: ${next_tag}" >&2

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_OUTPUT}")"
  {
    echo "release_tag=${next_tag}"
  } >> "${GITHUB_OUTPUT}"
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_ENV}")"
  {
    echo "RELEASE_TAG=${next_tag}"
  } >> "${GITHUB_ENV}"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_STEP_SUMMARY}")"
  {
    echo "## Release tag"
    echo
    echo "- Selected tag: ${next_tag}"
    if [[ -n "${prefix}" ]]; then
      echo "- Prefix override: ${prefix}"
    fi
  } >> "${GITHUB_STEP_SUMMARY}"
fi
