"""Platform normalization and immutable CI test selection."""

from __future__ import annotations

import sys
from collections.abc import Iterable
from enum import StrEnum
from typing import Protocol


class PlatformSelection(Protocol):
    @property
    def platforms(self) -> frozenset[str]: ...


class NativePlatform(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    FREEBSD = "freebsd"

    @property
    def requires_raw_capability_grant(self) -> bool:
        return self is not NativePlatform.WINDOWS

    def executable_name(self, stem: str) -> str:
        suffix = ".exe" if self is NativePlatform.WINDOWS else ""
        return f"{stem}{suffix}"


def native_platform(sys_platform: str | None = None) -> NativePlatform:
    candidate = sys.platform if sys_platform is None else sys_platform
    if candidate.startswith("linux"):
        return NativePlatform.LINUX
    if candidate in {"win32", "cygwin"}:
        return NativePlatform.WINDOWS
    if candidate == "darwin":
        return NativePlatform.MACOS
    if candidate.startswith("freebsd"):
        return NativePlatform.FREEBSD
    raise RuntimeError(f"unsupported native CI platform: {candidate}")


def selections_for_platform[Selection: PlatformSelection](
    selections: Iterable[Selection], platform: str | NativePlatform
) -> tuple[Selection, ...]:
    normalized = (
        platform.value if isinstance(platform, NativePlatform) else platform.lower()
    )
    return tuple(
        selection for selection in selections if normalized in selection.platforms
    )
