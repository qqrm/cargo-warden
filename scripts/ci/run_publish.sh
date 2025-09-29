#!/usr/bin/env bash
set -euo pipefail

interval="${PUBLISH_INTERVAL:-60}"
if [[ ! "${interval}" =~ ^[0-9]+$ ]]; then
  interval="60"
fi

ref_name="${GITHUB_REF_NAME:-}"
if [[ -z "${ref_name}" ]]; then
  ref_name="$(git describe --tags --exact-match 2>/dev/null || git rev-parse --abbrev-ref HEAD)"
fi

echo "::notice::Publishing crates to crates.io"
echo "::notice::Publish ref: ${ref_name}"
echo "::notice::Publish interval: ${interval}s"

set -- \
  --from-git \
  --skip-published \
  --no-verify \
  --yes
if [[ "${interval}" != "0" ]]; then
  set -- "$@" --publish-interval "${interval}"
fi
if [[ -n "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  set -- "$@" --token "${CARGO_REGISTRY_TOKEN}"
fi

cargo workspaces publish "$@"

echo "::notice::Publish completed at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
