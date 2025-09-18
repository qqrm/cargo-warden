#!/usr/bin/env bash
set -euo pipefail

# Install actionlint for GitHub Actions workflow linting.
if ! command -v actionlint >/dev/null 2>&1; then
  echo "Installing actionlint..."
  curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash \
    | bash -s -- latest "$HOME/.local/bin"
  export PATH="$HOME/.local/bin:$PATH"
fi

has_libseccomp() {
  if command -v pkg-config >/dev/null 2>&1; then
    if pkg-config --exists libseccomp; then
      return 0
    fi
    return 1
  fi
  if command -v ldconfig >/dev/null 2>&1; then
    if ldconfig -p 2>/dev/null | grep -q "libseccomp"; then
      return 0
    fi
  fi
  return 1
}

ensure_libseccomp() {
  if has_libseccomp; then
    return 0
  fi

  echo "Installing libseccomp development package..."
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is unavailable; install libseccomp manually." >&2
    return 0
  fi

  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      if ! sudo apt-get update; then
        echo "Failed to update package lists via sudo apt-get; install libseccomp-dev manually." >&2
        return 0
      fi
      if ! sudo apt-get install -y --no-install-recommends libseccomp-dev; then
        echo "Failed to install libseccomp-dev; install it manually." >&2
      fi
    else
      echo "libseccomp-dev is missing and sudo is unavailable; install it manually." >&2
    fi
    return 0
  fi

  if ! apt-get update; then
    echo "Failed to update package lists; install libseccomp-dev manually." >&2
    return 0
  fi
  if ! apt-get install -y --no-install-recommends libseccomp-dev; then
    echo "Failed to install libseccomp-dev; install it manually." >&2
  fi
}

ensure_libseccomp

# Ensure the repository remote is configured before working on tasks.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_setup="$script_dir/repo-setup.sh"
if [[ -x "$repo_setup" ]]; then
  "$repo_setup"
fi
