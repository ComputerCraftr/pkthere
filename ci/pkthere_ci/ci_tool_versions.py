"""Load the repository authority for pinned CI tool versions."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CiToolVersions:
    actionlint_image: str
    cross_revision: str
    mypy: str
    miri_toolchain: str
    pipx: str
    prettier: str
    ruff: str
    shfmt_image: str
    taplo_cli: str
    yamllint: str


def load_ci_tool_versions(root: Path) -> CiToolVersions:
    configuration = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    table = configuration.get("tool", {}).get("pkthere", {}).get("ci-tools")
    if not isinstance(table, dict):
        raise TypeError("pyproject.toml must define [tool.pkthere.ci-tools]")

    values = {field: _required_string(table, field) for field in _FIELD_NAMES}
    return CiToolVersions(**values)


def _required_string(table: dict[object, object], name: str) -> str:
    value = table.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"CI tool version {name!r} must be a nonempty string")
    return value


_FIELD_NAMES = tuple(CiToolVersions.__dataclass_fields__)
