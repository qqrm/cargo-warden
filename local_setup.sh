#!/usr/bin/env bash
set -euo pipefail

# Install actionlint for GitHub Actions workflow linting.
if ! command -v actionlint >/dev/null 2>&1; then
  echo "Installing actionlint..."
  curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash | bash -s -- latest "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
fi

# Ensure libseccomp is available for sandbox runtime tests.
needs_libseccomp=1
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libseccomp 2>/dev/null; then
  needs_libseccomp=0
elif command -v dpkg >/dev/null 2>&1 && dpkg -s libseccomp-dev >/dev/null 2>&1; then
  needs_libseccomp=0
fi

if [[ "$needs_libseccomp" -eq 1 ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "Installing libseccomp-dev..."
    apt-get update
    apt-get install -y --no-install-recommends libseccomp-dev
  else
    echo "libseccomp not detected and apt-get unavailable; install libseccomp-dev manually." >&2
  fi
fi

# Ensure the repository remote is configured before working on tasks.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_setup="$script_dir/repo-setup.sh"
if [[ -x "$repo_setup" ]]; then
  "$repo_setup"
fi
