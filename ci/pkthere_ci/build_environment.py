"""Build-environment sanitization for reproducible CI artifacts."""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping

_EXACT_BUILD_VARIABLES = frozenset(
    {
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_RUSTDOCFLAGS",
        "CARGO_BUILD_TARGET",
        "CC",
        "CXX",
        "AR",
        "CFLAGS",
        "CXXFLAGS",
        "LDFLAGS",
        "HOST_CC",
        "HOST_CXX",
        "HOST_AR",
        "HOST_CFLAGS",
        "HOST_CXXFLAGS",
        "HOST_LDFLAGS",
        "TARGET_CC",
        "TARGET_CXX",
        "TARGET_AR",
        "TARGET_CFLAGS",
        "TARGET_CXXFLAGS",
        "TARGET_LDFLAGS",
    }
)
_BUILD_VARIABLE_PATTERNS = (
    "CARGO_TARGET_*_RUSTFLAGS",
    "CARGO_TARGET_*_RUSTDOCFLAGS",
    "CARGO_TARGET_*_LINKER",
    "CARGO_TARGET_*_RUNNER",
    "CC_*",
    "CXX_*",
    "AR_*",
    "CFLAGS_*",
    "CXXFLAGS_*",
    "LDFLAGS_*",
)


def sanitize_environment(
    source: Mapping[str, str],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Remove ambient compiler policy without exposing variable values."""

    environment = dict(source)
    removed = tuple(
        sorted(
            name
            for name in environment
            if name in _EXACT_BUILD_VARIABLES
            or any(
                fnmatch.fnmatchcase(name, pattern)
                for pattern in _BUILD_VARIABLE_PATTERNS
            )
        )
    )
    for name in removed:
        del environment[name]
    return environment, removed
