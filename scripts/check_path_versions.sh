#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required" >&2
  exit 1
fi

metadata_tmp="$(mktemp)"
trap 'rm -f "$metadata_tmp"' EXIT

if ! cargo metadata --format-version 1 --no-deps >"$metadata_tmp"; then
  echo "error: failed to invoke 'cargo metadata'" >&2
  exit 1
fi

python3 - "$metadata_tmp" <<'PY'
import json
import pathlib
import sys

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - legacy fallback
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        print("error: python module 'tomllib' (or 'tomli') is required", file=sys.stderr)
        sys.exit(1)

metadata_path = pathlib.Path(sys.argv[1])

try:
    with metadata_path.open("rb") as fp:
        metadata = json.load(fp)
except json.JSONDecodeError as exc:
    print(f"error: failed to parse cargo metadata: {exc}", file=sys.stderr)
    sys.exit(1)

workspace_root = pathlib.Path(metadata.get("workspace_root", "."))
packages = {pkg["id"]: pkg for pkg in metadata.get("packages", [])}
workspace_members = set(metadata.get("workspace_members", []))

problems: list[tuple[pathlib.Path, str, str | None, str]] = []

def stringify_path_value(value: object) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "<unknown>"
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        import json as _json

        return _json.dumps(value)
    except Exception:  # pragma: no cover - best effort fallback
        return repr(value)

for member_id in workspace_members:
    package = packages.get(member_id)
    if not package:
        continue

    manifest_path = pathlib.Path(package["manifest_path"])

    try:
        with manifest_path.open("rb") as fp:
            manifest = tomllib.load(fp)
    except FileNotFoundError as exc:
        print(f"error: failed to read {manifest_path}: {exc}", file=sys.stderr)
        sys.exit(1)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"error: failed to parse {manifest_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    def check_dependency_table(table: object, target: str | None) -> None:
        if not isinstance(table, dict):
            return
        for name, spec in table.items():
            if not isinstance(spec, dict):
                continue
            if "path" not in spec or "version" in spec:
                continue
            problems.append(
                (
                    manifest_path,
                    name,
                    target,
                    stringify_path_value(spec.get("path")),
                )
            )

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        check_dependency_table(manifest.get(section), None)

    target_table = manifest.get("target")
    if isinstance(target_table, dict):
        for target_name, target_config in target_table.items():
            if isinstance(target_config, dict):
                for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                    check_dependency_table(target_config.get(section), str(target_name))

if not problems:
    sys.exit(0)

for manifest_path, dependency, target, path_value in problems:
    try:
        relative = manifest_path.relative_to(workspace_root)
    except ValueError:
        relative = manifest_path
    location = str(relative)
    if target:
        location = f"{location} ({target})"
    print(
        f"{location}: dependency '{dependency}' uses path '{path_value}' without a version",
        file=sys.stderr,
    )

print("error: add an explicit version alongside each path dependency", file=sys.stderr)
sys.exit(1)
PY
