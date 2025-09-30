#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/run_ci_checks.sh [--skip-install]

Run the same validation commands as the CI workflow. By default the script
installs any missing system packages and cargo subcommands before executing the
checks. Pass --skip-install to require all dependencies to be present already.
USAGE
}

log_step() {
  printf '\n[%s] %s\n' "$(date -u '+%H:%M:%S')" "$1"
}

ensure_apt_packages() {
  local install=${1}
  shift

  if ! command -v apt-get >/dev/null 2>&1; then
    echo "error: apt-get is required to install system dependencies" >&2
    exit 1
  fi

  local missing=()
  for pkg in "$@"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done

  if ((${#missing[@]} == 0)); then
    return
  fi

  if ! ${install}; then
    echo "error: missing packages: ${missing[*]}" >&2
    echo "hint: rerun without --skip-install or install them manually" >&2
    exit 1
  fi

  if ((EUID != 0)); then
    echo "error: missing packages: ${missing[*]}" >&2
    echo "hint: rerun as root or install manually using apt-get" >&2
    exit 1
  fi

  apt-get update
  apt-get install -y "${missing[@]}"
}

ensure_cargo_tool() {
  local install=${1}
  local binary="$2"
  local crate="$3"

  if command -v "$binary" >/dev/null 2>&1; then
    return
  fi

  if ! ${install}; then
    echo "error: missing cargo binary '$binary'" >&2
    echo "hint: rerun without --skip-install or install it manually via 'cargo install ${crate} --locked'" >&2
    exit 1
  fi

  cargo install "$crate" --locked
}

ensure_nightly() {
  local install=${1}
  if rustup toolchain list | grep -q '^nightly'; then
    return
  fi

  if ! ${install}; then
    echo "error: nightly toolchain is required" >&2
    echo "hint: rerun without --skip-install or run 'rustup toolchain install nightly --profile minimal'" >&2
    exit 1
  fi

  rustup toolchain install nightly --profile minimal >/dev/null
}

main() {
  local install_tools=true
  while (($#)); do
    case "$1" in
      --skip-install)
        install_tools=false
        ;;
      --help|-h)
        usage
        return 0
        ;;
      *)
        echo "error: unknown argument: $1" >&2
        usage >&2
        return 1
        ;;
    esac
    shift
  done

  local repo_root
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  cd "$repo_root"

  log_step "Ensuring required apt packages"
  ensure_apt_packages "${install_tools}" pkg-config libseccomp-dev protobuf-compiler jq xxhash

  log_step "Ensuring Rust components"
  rustup component add rustfmt clippy llvm-tools-preview >/dev/null

  log_step "Ensuring cargo subcommands"
  ensure_cargo_tool "${install_tools}" cargo-machete cargo-machete
  ensure_cargo_tool "${install_tools}" cargo-audit cargo-audit
  ensure_cargo_tool "${install_tools}" cargo-nextest cargo-nextest
  ensure_cargo_tool "${install_tools}" cargo-udeps cargo-udeps
  ensure_cargo_tool "${install_tools}" cargo-fuzz cargo-fuzz

  log_step "Ensuring nightly toolchain"
  ensure_nightly "${install_tools}"

  log_step "Ensuring actionlint"
  if ! command -v actionlint >/dev/null 2>&1; then
    echo "error: actionlint is required but not found on PATH" >&2
    echo "hint: run './repo-setup.sh' or install actionlint manually" >&2
    exit 1
  fi

  log_step "Running actionlint"
  actionlint

  log_step "Running scripts/check_path_versions.sh"
  ./scripts/check_path_versions.sh

  log_step "Running cargo fmt --all -- --check"
  cargo fmt --all -- --check

  log_step "Running cargo check --tests --benches"
  cargo check --tests --benches

  log_step "Running cargo clippy --all-targets --all-features -- -D warnings"
  cargo clippy --all-targets --all-features -- -D warnings

  log_step "Running cargo nextest run"
  cargo nextest run

  log_step "Running cargo test"
  cargo test

  log_step "Running cargo machete"
  cargo machete

  log_step "Running cargo audit"
  cargo audit

  log_step "Running cargo +nightly udeps --all-targets --all-features"
  cargo +nightly udeps --all-targets --all-features

  log_step "Running run_examples.sh"
  ./run_examples.sh

  log_step "Building fuzz target 'net' with cargo fuzz"
  cargo +nightly fuzz build net

  log_step "CI parity checks completed successfully"
}

main "$@"
