#!/usr/bin/env bash
set -euo pipefail

ca_bundle="/etc/ssl/certs/ca-certificates.crt"
if [[ -f "${ca_bundle}" ]]; then
  if ! git config --global --get http.sslCAInfo >/dev/null 2>&1; then
    git config --global http.sslCAInfo "${ca_bundle}" >/dev/null 2>&1 || true
  fi
  if ! git config --global --get http.cainfo >/dev/null 2>&1; then
    git config --global http.cainfo "${ca_bundle}" >/dev/null 2>&1 || true
  fi
  export GIT_SSL_CAINFO="${ca_bundle}"
  export CARGO_HTTP_CAINFO="${ca_bundle}"
fi

plan_tmp="$(mktemp)"
if cargo workspaces plan \
  --skip-published \
  --long \
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
