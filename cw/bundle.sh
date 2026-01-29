#!/usr/bin/env bash
set -euo pipefail

# bundle.sh — WSL-side bundler
# - tracked + untracked, respects .gitignore via git ls-files --exclude-standard
# - hard-excludes: .git/, target/, bundle*.zip
# - creates bundle.zip then renames to bundle_<md5-8>.zip
# - deterministic ordering

if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: git not found" >&2
  exit 1
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT}" || ! -d "${ROOT}" ]]; then
  echo "ERROR: not a git repository (git rev-parse failed)" >&2
  exit 1
fi

python3 - <<'PY'
import os, subprocess, zipfile, hashlib, sys

root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
out_tmp = os.path.join(root, "bundle.zip")

def hard_exclude(rel: str) -> bool:
    # rel uses forward slashes from git
    parts = rel.split("/")
    if ".git" in parts:
        return True
    if "target" in parts:
        return True
    leaf = parts[-1]
    if leaf.lower().startswith("bundle") and leaf.lower().endswith(".zip"):
        return True
    return False

# Get tracked + untracked, respecting .gitignore
raw = subprocess.check_output(
    ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
)

paths = [p.decode("utf-8", "surrogateescape") for p in raw.split(b"\x00") if p]
paths = [p for p in paths if p and not hard_exclude(p)]
paths.sort()  # deterministic

# Create zip
if os.path.exists(out_tmp):
    os.remove(out_tmp)

with zipfile.ZipFile(out_tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for rel in paths:
        full = os.path.join(root, rel)
        # Only regular files
        if not os.path.isfile(full):
            continue
        zf.write(full, arcname=rel)

# Hash and rename
h = hashlib.md5()
with open(out_tmp, "rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
short = h.hexdigest()[:8].lower()

dst = os.path.join(root, f"bundle_{short}.zip")
if os.path.exists(dst):
    os.remove(dst)
os.replace(out_tmp, dst)

print(f"OK: {dst}")
PY
