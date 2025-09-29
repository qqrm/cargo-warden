#!/usr/bin/env bash
set -euo pipefail

failures_file="$(mktemp)"
trap 'rm -f "$failures_file"' EXIT

record_outcome() {
  local outcome="$1"
  local label="$2"
  if [[ "$outcome" == "failure" || "$outcome" == "cancelled" ]]; then
    printf '%s (%s)\n' "$label" "$outcome" >>"$failures_file"
  fi
}

record_outcome "${CARGO_FMT_OUTCOME}" "cargo fmt --all -- --check"
record_outcome "${CARGO_CHECK_OUTCOME}" "cargo check --tests --benches"
record_outcome "${CARGO_CLIPPY_OUTCOME}" "cargo clippy --all-targets --all-features -- -D warnings"
record_outcome "${CARGO_NEXTEST_OUTCOME}" "cargo nextest run"
record_outcome "${CARGO_MACHETE_OUTCOME}" "cargo machete"
record_outcome "${CARGO_AUDIT_OUTCOME}" "cargo audit"
record_outcome "${CARGO_DENY_OUTCOME}" "cargo deny check --disable-fetch"
record_outcome "${CARGO_UDEPS_OUTCOME}" "cargo +nightly udeps --all-targets --all-features"

if [[ -s "$failures_file" ]]; then
  {
    echo "## Failed checks"
    while IFS= read -r line; do
      echo "- $line"
    done <"$failures_file"
  } >>"$GITHUB_STEP_SUMMARY"

  echo "The following checks failed:"
  while IFS= read -r line; do
    echo "  - $line"
  done <"$failures_file"
  exit 1
fi
