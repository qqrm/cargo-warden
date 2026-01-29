#!/usr/bin/env bash
set -euo pipefail

plan_path="${PUBLISH_PLAN_PATH:-target/publish-plan.log}"
plan_tmp="$(mktemp)"

if cargo workspaces publish \
  --from-git \
  --skip-published \
  --no-verify \
  --dry-run \
  >"${plan_tmp}" 2>&1; then
  cat "${plan_tmp}"
else
  cat "${plan_tmp}"
  exit 1
fi

mkdir -p "$(dirname "${plan_path}")"
mv "${plan_tmp}" "${plan_path}"

echo "Publish plan written to ${plan_path}" >&2

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_STEP_SUMMARY}")"
  {
    echo "## Publish plan"
    echo
    echo '```text'
    cat "${plan_path}"
    echo '```'
  } >> "${GITHUB_STEP_SUMMARY}"
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_OUTPUT}")"
  echo "plan-path=${plan_path}" >> "${GITHUB_OUTPUT}"
fi
