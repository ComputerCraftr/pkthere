"""Command-line dispatch for the canonical cross-platform CI runner."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .command_runner import exception_details, exception_exit_code
from .macos_profile import SUPPORTED_TARGETS
from .runner import TestRunner


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "aarch64-musl",
            "alpine-build",
            "alpine-runtime",
            "authority-audit",
            "ci-tool-outputs",
            "macos-profile",
            "miri-boundaries",
            "msrv",
            "native",
            "platform-ci",
            "platform-ci-result",
            "platform-ci-vm",
            "quality",
            "bootstrap-quality-tools",
            "raw-reality",
            "release-stress",
        ),
    )
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument(
        "--cpu-policy",
        choices=("portable", "native"),
        default="portable",
    )
    parser.add_argument("--target", choices=sorted(SUPPORTED_TARGETS))
    parser.add_argument("--app-bin", type=Path)
    parser.add_argument("--privileged-app-bin", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path("macos-profile-artifacts"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    runner = TestRunner(args.log.resolve())
    if args.command == "quality":
        runner.quality()
    elif args.command == "ci-tool-outputs":
        runner.ci_tool_outputs()
    elif args.command == "aarch64-musl":
        runner.aarch64_musl()
    elif args.command == "alpine-build":
        runner.alpine_build()
    elif args.command == "alpine-runtime":
        runner.alpine_runtime()
    elif args.command == "bootstrap-quality-tools":
        runner.quality_bootstrap()
    elif args.command == "msrv":
        runner.msrv()
    elif args.command == "release-stress":
        runner.release_stress()
    elif args.command == "platform-ci":
        runner.platform_ci(
            app_bin=args.app_bin,
            privileged_app_bin=args.privileged_app_bin,
        )
    elif args.command == "platform-ci-vm":
        if args.result is None:
            raise RuntimeError("platform-ci-vm requires --result")
        runner.platform_ci_vm(
            args.result,
            app_bin=args.app_bin,
            privileged_app_bin=args.privileged_app_bin,
        )
    elif args.command == "platform-ci-result":
        if args.result is None:
            raise RuntimeError("platform-ci-result requires --result")
        runner.verify_platform_ci_result(args.result)
    elif args.command == "native":
        runner.native()
    elif args.command == "authority-audit":
        runner.authority_audit()
    elif args.command == "miri-boundaries":
        runner.miri_boundaries()
    elif args.command == "macos-profile":
        runner.macos_profile(
            cpu_policy=args.cpu_policy,
            target=args.target,
            evidence_root=args.evidence_dir,
        )
    else:
        runner.standalone_raw_reality()


if __name__ == "__main__":
    try:
        main()
    except (
        subprocess.CalledProcessError,
        ExceptionGroup,
        RuntimeError,
        OSError,
    ) as error:
        for detail in exception_details(error):
            print(f"CI failure: {detail}", file=sys.stderr)
        raise SystemExit(exception_exit_code(error)) from None
