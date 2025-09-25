#!/usr/bin/env bash
set -euo pipefail

interval="${PUBLISH_INTERVAL:-60}"
if [[ ! "${interval}" =~ ^[0-9]+$ ]]; then
  interval="60"
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${branch}" != "main" ]]; then
  echo "::warning::Publishing from non-main branch '${branch}'."
fi

echo "::notice::Publishing crates to crates.io"
echo "::notice::Publish interval: ${interval}s"

set -- \
  --allow-branch "${branch}" \
  --all \
  --skip-published \
  --no-verify \
  -y
if [[ "${interval}" != "0" ]]; then
  set -- "$@" --publish-interval "${interval}"
fi

cargo workspaces publish "$@"

echo "::notice::Publish completed at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
