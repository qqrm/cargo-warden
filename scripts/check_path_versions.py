#!/usr/bin/env python3
"""Validate that path dependencies declare versions for publishing."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, MutableMapping

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Problem:
    manifest: Path
    dependency: str
    target: str | None
    path_value: str

    def format(self) -> str:
        location = f"{self.manifest.relative_to(ROOT)}"
        if self.target:
            location = f"{location} ({self.target})"
        return (
            f"{location}: dependency '{self.dependency}' uses path '{self.path_value}' without a version"
        )


def load_workspace_manifests() -> Iterable[Path]:
    metadata = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    data = json.loads(metadata.stdout)
    members = set(data["workspace_members"])
    for package in data["packages"]:
        if package["id"] in members:
            yield Path(package["manifest_path"])


def check_dependency_table(
    table: Mapping[str, object],
    *,
    manifest: Path,
    target: str | None,
    problems: List[Problem],
) -> None:
    for name, raw_spec in table.items():
        if not isinstance(raw_spec, MutableMapping):
            # Specifications that are strings or numbers cannot contain path dependencies.
            continue
        spec = dict(raw_spec)
        if "path" in spec and "version" not in spec:
            problems.append(
                Problem(
                    manifest=manifest,
                    dependency=name,
                    target=target,
                    path_value=str(spec["path"]),
                )
            )


def collect_problems(manifest_path: Path) -> List[Problem]:
    with manifest_path.open("rb") as fh:
        data = tomllib.load(fh)  # type: ignore[name-defined]

    problems: List[Problem] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        table = data.get(section)
        if isinstance(table, Mapping):
            check_dependency_table(
                table, manifest=manifest_path, target=None, problems=problems
            )

    target_tables = data.get("target")
    if isinstance(target_tables, Mapping):
        for target_name, target_table in target_tables.items():
            if not isinstance(target_table, Mapping):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                table = target_table.get(section)
                if isinstance(table, Mapping):
                    check_dependency_table(
                        table,
                        manifest=manifest_path,
                        target=target_name,
                        problems=problems,
                    )

    return problems


try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
    import tomli as tomllib  # type: ignore[no-redef]


def main() -> int:
    problems: List[Problem] = []
    for manifest in load_workspace_manifests():
        problems.extend(collect_problems(manifest))

    if problems:
        for problem in problems:
            print(problem.format(), file=sys.stderr)
        print(
            "error: add an explicit version alongside each path dependency", file=sys.stderr
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
