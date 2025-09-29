#!/usr/bin/env bash
set -euo pipefail

REMOTE_NAME="${REMOTE_NAME:-origin}"
FETCH_URL="${REMOTE_FETCH_URL:-}"
PUSH_URL="${REMOTE_PUSH_URL:-}"
BASE_URL="${REMOTE_URL:-}"
DEFAULT_BRANCH="${REMOTE_BRANCH:-}"

ensure_apt_packages() {
  if ! command -v dpkg >/dev/null 2>&1; then
    return
  fi

  local -a missing=()
  for pkg in "$@"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done

  if ((${#missing[@]} == 0)); then
    return
  fi

  if ! command -v apt-get >/dev/null 2>&1; then
    echo "The following packages are required but apt-get is unavailable: ${missing[*]}" >&2
    echo "Please install them manually." >&2
    return
  fi

  local -a runner=()
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      runner+=(sudo)
    else
      echo "The following packages are required but root privileges are unavailable: ${missing[*]}" >&2
      echo "Please install them manually." >&2
      return
    fi
  fi

  if [[ -z "${DEBIAN_FRONTEND:-}" ]]; then
    runner+=(env DEBIAN_FRONTEND=noninteractive)
  fi

  echo "Installing missing apt packages: ${missing[*]}" >&2
  "${runner[@]}" apt-get update
  "${runner[@]}" apt-get install -y "${missing[@]}"
}

install_actionlint() {
  if command -v actionlint >/dev/null 2>&1; then
    return
  fi

  echo "Installing actionlint..." >&2
  curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash \
    | bash -s -- latest "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
}

ensure_apt_packages pkg-config libseccomp-dev protobuf-compiler jq xxhash
install_actionlint

ensure_rust_components() {
  if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is required to install Rust components." >&2
    exit 1
  fi

  rustup component add rustfmt clippy llvm-tools-preview >/dev/null
}

ensure_cargo_tool() {
  local binary="$1"
  local crate="$2"

  if command -v "$binary" >/dev/null 2>&1; then
    return
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required to install $crate." >&2
    exit 1
  fi

  echo "Installing $crate via cargo install..." >&2
  cargo install "$crate" --locked
}

ensure_cargo_tools() {
  ensure_cargo_tool cargo-machete cargo-machete
  ensure_cargo_tool cargo-audit cargo-audit
  ensure_cargo_tool cargo-deny cargo-deny
  ensure_cargo_tool cargo-nextest cargo-nextest
  ensure_cargo_tool cargo-udeps cargo-udeps
  ensure_cargo_tool cargo-fuzz cargo-fuzz
}

ensure_nightly_toolchain() {
  if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is required to install the nightly toolchain." >&2
    exit 1
  fi

  if rustup toolchain list | grep -q '^nightly'; then
    return
  fi

  echo "Installing Rust nightly toolchain..." >&2
  rustup toolchain install nightly --profile minimal >/dev/null
}

ensure_rust_components
ensure_cargo_tools
ensure_nightly_toolchain

current_fetch=""
if git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
  current_fetch=$(git remote get-url "$REMOTE_NAME")
fi

if [[ -z "$FETCH_URL" ]]; then
  if [[ -n "$BASE_URL" ]]; then
    FETCH_URL="$BASE_URL"
  elif [[ -n "$current_fetch" ]]; then
    FETCH_URL="$current_fetch"
  elif [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" ]]; then
    FETCH_URL="${GITHUB_SERVER_URL%/}/${GITHUB_REPOSITORY}.git"
  else
    FETCH_URL="https://github.com/qqrm/cargo-warden.git"
  fi
fi

if [[ "${FETCH_URL}" != *.git ]]; then
  FETCH_URL="${FETCH_URL%.git}.git"
fi

declare -r FETCH_URL

if [[ -z "$BASE_URL" ]]; then
  BASE_URL="$FETCH_URL"
fi

default_push() {
  if [[ -n "$PUSH_URL" ]]; then
    echo "$PUSH_URL"
    return
  fi

  if [[ -n "$BASE_URL" ]]; then
    if [[ "$BASE_URL" =~ ^https://([^/]+)/(.+)$ ]]; then
      local host="${BASH_REMATCH[1]}"
      local path="${BASH_REMATCH[2]%.git}"
      echo "git@${host}:${path}.git"
      return
    fi
    echo "$BASE_URL"
    return
  fi

  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    local host="github.com"
    if [[ -n "${GITHUB_SERVER_URL:-}" ]]; then
      host="${GITHUB_SERVER_URL#https://}"
      host="${host#http://}"
    fi
    echo "git@${host}:${GITHUB_REPOSITORY}.git"
    return
  fi

  echo "$FETCH_URL"
}

PUSH_URL=$(default_push)

if git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
  git remote set-url "$REMOTE_NAME" "$FETCH_URL"
else
  git remote add "$REMOTE_NAME" "$FETCH_URL"
fi

git remote set-url --push "$REMOTE_NAME" "$PUSH_URL"

echo "Configured remote '$REMOTE_NAME'" >&2
echo "  fetch: $FETCH_URL" >&2
echo "  push:  $PUSH_URL" >&2

fetch_args=("$REMOTE_NAME" "--tags" "--prune")
if [[ -n "$DEFAULT_BRANCH" ]]; then
  fetch_args+=("$DEFAULT_BRANCH")
fi

git fetch "${fetch_args[@]}"

current_branch=""
if current_branch=$(git symbolic-ref --quiet --short HEAD 2>/dev/null); then
  :
else
  current_branch=""
fi

if [[ -z "$DEFAULT_BRANCH" ]]; then
  DEFAULT_BRANCH="$current_branch"
fi

if [[ -z "$current_branch" ]]; then
  echo "HEAD is detached; skipping branch synchronization" >&2
  exit 0
fi

if [[ -z "$DEFAULT_BRANCH" ]]; then
  DEFAULT_BRANCH="$current_branch"
fi

if ! git rev-parse --verify "$REMOTE_NAME/$DEFAULT_BRANCH" >/dev/null 2>&1; then
  echo "Remote branch '$REMOTE_NAME/$DEFAULT_BRANCH' not found; skipping branch synchronization" >&2
  exit 0
fi

git branch --set-upstream-to "$REMOTE_NAME/$DEFAULT_BRANCH" "$current_branch" 2>/dev/null || true

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean; skipping branch synchronization" >&2
  exit 0
fi

if git merge-base --is-ancestor HEAD "$REMOTE_NAME/$DEFAULT_BRANCH" 2>/dev/null; then
  if ! git merge --ff-only "$REMOTE_NAME/$DEFAULT_BRANCH" >/dev/null 2>&1; then
    git reset --hard "$REMOTE_NAME/$DEFAULT_BRANCH"
  fi
else
  git reset --hard "$REMOTE_NAME/$DEFAULT_BRANCH"
fi

echo "Synchronized '$current_branch' with '$REMOTE_NAME/$DEFAULT_BRANCH'" >&2
