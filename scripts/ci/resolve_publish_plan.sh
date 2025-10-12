#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${CARGO_HTTP_CAINFO:-}" ]]; then
  default_cainfo="${SSL_CERT_FILE:-}"
  if [[ -z "$default_cainfo" ]]; then
    for candidate in \
      /etc/ssl/certs/ca-certificates.crt \
      /etc/pki/tls/certs/ca-bundle.crt \
      /etc/ssl/ca-bundle.pem; do
      if [[ -f "$candidate" ]]; then
        default_cainfo="$candidate"
        break
      fi
    done
  fi

  if [[ -n "$default_cainfo" ]]; then
    export CARGO_HTTP_CAINFO="$default_cainfo"
  else
    echo "::warning::No CA bundle detected; crates.io access may fail" >&2
  fi
fi

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
