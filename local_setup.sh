#!/usr/bin/env bash
set -euo pipefail

# Install actionlint for GitHub Actions workflow linting.
if ! command -v actionlint >/dev/null 2>&1; then
  echo "Installing actionlint..."
  curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash | bash -s -- latest "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
fi
