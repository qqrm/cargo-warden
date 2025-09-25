#!/usr/bin/env bash
set -euo pipefail

plan_tmp="$(mktemp)"
if cargo workspaces publish \
  --all \
  --skip-published \
  --no-verify \
  --allow-dirty \
  --dry-run \
  >"${plan_tmp}" 2>&1; then
  cat "${plan_tmp}"
else
  cat "${plan_tmp}"
  exit 1
fi

mv "${plan_tmp}" publish-plan.log

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_STEP_SUMMARY}")"
  {
    echo "## Publish plan"
    echo
    echo '```text'
    cat publish-plan.log
    echo '```'
  } >> "${GITHUB_STEP_SUMMARY}"
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_OUTPUT}")"
  echo "plan-path=publish-plan.log" >> "${GITHUB_OUTPUT}"
fi
