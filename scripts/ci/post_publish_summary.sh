#!/usr/bin/env bash
set -euo pipefail

dry_run="${DRY_RUN:-true}"
interval="${PUBLISH_INTERVAL:-60}"

if [[ -f publish-plan.log && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  mkdir -p "$(dirname "${GITHUB_STEP_SUMMARY}")"
  {
    echo
    echo "## Publish outcome"
    echo
    if [[ "${dry_run}" == "true" ]]; then
      echo "- Dry run completed at $(date -u '+%Y-%m-%dT%H:%M:%SZ')."
    else
      echo "- Crates published successfully at $(date -u '+%Y-%m-%dT%H:%M:%SZ')."
      echo "- Publish interval: ${interval}s."
    fi
  } >> "${GITHUB_STEP_SUMMARY}"
fi

if [[ "${dry_run}" == "true" ]]; then
  echo "::notice::Dry run completed; no crates were published."
else
  echo "::notice::Crates published successfully."
fi
