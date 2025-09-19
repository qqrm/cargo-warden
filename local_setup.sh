#!/usr/bin/env bash
set -euo pipefail

# Install actionlint for GitHub Actions workflow linting.
if ! command -v actionlint >/dev/null 2>&1; then
  echo "Installing actionlint..."
  curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash | bash -s -- latest "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
fi

# Install libseccomp development headers required for the real sandbox build.
if ! dpkg -s libseccomp-dev >/dev/null 2>&1; then
  echo "Installing libseccomp-dev..."
  apt-get update
  apt-get install -y libseccomp-dev
fi

# Ensure the repository remote is configured before working on tasks.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_setup="$script_dir/repo-setup.sh"
if [[ -x "$repo_setup" ]]; then
  "$repo_setup"
fi
