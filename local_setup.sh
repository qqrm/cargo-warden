#!/usr/bin/env bash
set -euo pipefail

# Install actionlint for GitHub Actions workflow linting.
if ! command -v actionlint >/dev/null 2>&1; then
  echo "Installing actionlint..."
  curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash | bash -s -- latest "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
fi

# Ensure libseccomp is available for integration tests that link against it.
ensure_libseccomp() {
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libseccomp; then
    return
  fi

  if command -v dpkg-query >/dev/null 2>&1 && dpkg-query --show --showformat='${Status}' libseccomp-dev 2>/dev/null | grep -q "install ok installed"; then
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    echo "Installing libseccomp-dev..."
    apt-get update -y
    apt-get install -y --no-install-recommends libseccomp-dev
    return
  fi

  echo "Warning: libseccomp not found and could not be installed automatically." >&2
}

ensure_libseccomp

# Ensure the repository remote is configured before working on tasks.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_setup="$script_dir/repo-setup.sh"
if [[ -x "$repo_setup" ]]; then
  "$repo_setup"
fi
