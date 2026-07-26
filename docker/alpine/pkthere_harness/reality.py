"""Privilege-isolated Alpine socket-reality lifecycle."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from ci.pkthere_ci.evidence_types import ArtifactIdentity
from ci.pkthere_ci.selection_arguments import CargoTestSelection
from ci.pkthere_ci.test_manifest import (
    RAW_ICMP_TEST_ENVIRONMENT,
    RAW_SOCKET_REALITY_TEST,
    UNPRIVILEGED_SOCKET_REALITY_TESTS,
    alpine_concurrency_tests_for_platform,
    privileged_icmp_tests_for_platform,
)
from ci.pkthere_ci.timing import (
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
    DOCKER_SUITE_TIMEOUT_SECONDS,
)

from .config import (
    ICMP_INTEGRATION_TEST,
    LOG_DIR,
    PKTHERE,
    PKTHERE_AUTHORITY_AUDIT,
    PKTHERE_TEST_SUPPORT_TEST,
    PKTHERE_UNIT_TEST,
    PRIVILEGED_SOCKET_REALITY_TEST,
    SOCKET_REALITY_TEST,
    STRESS_TEST,
    TEST_APP,
    WORKER_MODES_TEST,
)
from .lifecycle import audit_forwarder_lifecycle
from .processes import require_rust_tests, run, rust_test_listing

PRIVILEGE_LIFECYCLE_ERRORS = (
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
    subprocess.SubprocessError,
)


def run_reality_test(
    label: str,
    command: Sequence[str],
    timeout_seconds: float,
    environment: Mapping[str, str],
) -> None:
    started = time.monotonic()
    print(f"=== Alpine reality start: {label} ===", flush=True)
    primary: BaseException | None = None
    try:
        run(command, timeout_seconds=timeout_seconds, env=environment)
    except (
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
        SystemExit,
    ) as error:
        primary = error
    try:
        audit_forwarder_lifecycle(label)
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyboardInterrupt,
        SystemExit,
    ) as lifecycle_error:
        if primary is None:
            primary = lifecycle_error
        else:
            primary.add_note(f"secondary process lifecycle failure: {lifecycle_error}")
    if primary is not None:
        elapsed = time.monotonic() - started
        print(
            f"=== Alpine reality failed: {label} after {elapsed:.3f}s ===",
            flush=True,
        )
        raise primary
    elapsed = time.monotonic() - started
    print(f"=== Alpine reality passed: {label} in {elapsed:.3f}s ===", flush=True)


def run_exact_reality_test(
    selection: CargoTestSelection,
    executable: str,
    command: Sequence[str],
    timeout_seconds: float,
    environment: Mapping[str, str],
) -> None:
    listing = rust_test_listing(
        executable,
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
        env=environment,
    )
    selection.bind_discovered_test(listing, executable)
    run_reality_test(selection.evidence_id, command, timeout_seconds, environment)


def _linux_capability(path: Path) -> str:
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        raise RuntimeError("Alpine privilege evidence requires os.getxattr")
    try:
        capability = getxattr(path, "security.capability")
    except OSError as error:
        missing_attribute_codes = {
            getattr(os, "ENODATA", 61),
            getattr(os, "ENOATTR", 93),
        }
        if error.errno in missing_attribute_codes:
            return ""
        raise
    if not isinstance(capability, bytes):
        raise TypeError("Alpine capability metadata was not returned as bytes")
    return capability.hex()


def _artifact_identity(path: str) -> ArtifactIdentity:
    artifact = Path(path)
    return ArtifactIdentity.inspect(artifact, _linux_capability(artifact))


def _identity_payload(identity: ArtifactIdentity) -> dict[str, object]:
    return identity.evidence_payload()


def _require_unprivileged(identity: ArtifactIdentity) -> None:
    if identity.mode & stat.S_ISUID or identity.privilege_metadata:
        raise RuntimeError(f"base artifact is privileged: {identity.path}")


def _require_unchanged(expected: ArtifactIdentity) -> ArtifactIdentity:
    observed = _artifact_identity(str(expected.path))
    if observed != expected:
        raise RuntimeError(
            f"base artifact changed during privileged phase: {expected.path}"
        )
    return observed


def _record_privilege_evidence(
    base: tuple[ArtifactIdentity, ArtifactIdentity],
    privileged: tuple[ArtifactIdentity, ArtifactIdentity],
    final: tuple[ArtifactIdentity, ArtifactIdentity],
) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 1,
        "phases": {
            "base": [_identity_payload(identity) for identity in base],
            "privileged": [_identity_payload(identity) for identity in privileged],
            "post_teardown": [_identity_payload(identity) for identity in final],
        },
    }
    (LOG_DIR / "privilege-isolation.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _prepare_privileged_copy(source: str, destination: str) -> ArtifactIdentity:
    if source == destination:
        raise RuntimeError("privileged artifact path must differ from its base path")
    shutil.copy2(source, destination)
    run(
        ["setcap", "cap_net_raw+ep", destination],
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
    )
    identity = _artifact_identity(destination)
    if not identity.privilege_metadata:
        raise RuntimeError(f"privileged artifact has no capability: {destination}")
    if identity.sha256 != _artifact_identity(source).sha256:
        raise RuntimeError(f"privileged artifact bytes differ from base: {destination}")
    return identity


def _destroy_privileged_copy(path: str) -> None:
    artifact = Path(path)
    if not artifact.exists():
        return
    run(["setcap", "-r", path], timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS)
    artifact.unlink()


def _run_unprivileged_reality(environment: Mapping[str, str]) -> None:
    for selection in UNPRIVILEGED_SOCKET_REALITY_TESTS:
        run_exact_reality_test(
            selection,
            SOCKET_REALITY_TEST,
            [
                "su-exec",
                "pkthere",
                *selection.executable_arguments(SOCKET_REALITY_TEST),
            ],
            DOCKER_SUITE_TIMEOUT_SECONDS,
            environment,
        )


def _run_privileged_reality(environment: Mapping[str, str]) -> None:
    run_exact_reality_test(
        RAW_SOCKET_REALITY_TEST,
        PRIVILEGED_SOCKET_REALITY_TEST,
        [
            "su-exec",
            "pkthere",
            *RAW_SOCKET_REALITY_TEST.executable_arguments(
                PRIVILEGED_SOCKET_REALITY_TEST
            ),
        ],
        DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
        environment,
    )
    executables = {
        "icmp-integration-test": ICMP_INTEGRATION_TEST,
        "pkthere-test-support-test": PKTHERE_TEST_SUPPORT_TEST,
    }
    for selection in privileged_icmp_tests_for_platform("linux"):
        executable = executables[selection.staged_executable]
        run_exact_reality_test(
            selection,
            executable,
            ["su-exec", "pkthere", *selection.executable_arguments(executable)],
            DOCKER_EXACT_TEST_TIMEOUT_SECONDS,
            environment,
        )


def _run_ordinary_suites(environment: Mapping[str, str]) -> None:
    run_reality_test(
        "native socket-reality suite",
        ["su-exec", "pkthere", SOCKET_REALITY_TEST, "--nocapture"],
        DOCKER_SUITE_TIMEOUT_SECONDS,
        environment,
    )
    run_reality_test(
        "worker-mode suite",
        ["su-exec", "pkthere", WORKER_MODES_TEST, "--nocapture"],
        DOCKER_SUITE_TIMEOUT_SECONDS,
        environment,
    )
    authority_environment = {**environment, "TEST_APP_BIN": PKTHERE_AUTHORITY_AUDIT}
    concurrency_executables = {
        "pkthere-unit-test": PKTHERE_UNIT_TEST,
        "stress-test": STRESS_TEST,
    }
    for selection in alpine_concurrency_tests_for_platform("linux"):
        executable = concurrency_executables[selection.staged_executable]
        selection_environment = (
            authority_environment
            if selection.staged_executable == "stress-test"
            else environment
        )
        run_exact_reality_test(
            selection,
            executable,
            ["su-exec", "pkthere", *selection.executable_arguments(executable)],
            (
                DOCKER_SUITE_TIMEOUT_SECONDS
                if selection.staged_executable == "stress-test"
                else DOCKER_EXACT_TEST_TIMEOUT_SECONDS
            ),
            selection_environment,
        )
    run_reality_test(
        "non-privileged ICMP integration suite",
        ["su-exec", "pkthere", ICMP_INTEGRATION_TEST, "--nocapture"],
        DOCKER_SUITE_TIMEOUT_SECONDS,
        environment,
    )


def reality() -> None:
    base_app = _artifact_identity(PKTHERE)
    base_reality = _artifact_identity(SOCKET_REALITY_TEST)
    _require_unprivileged(base_app)
    _require_unprivileged(base_reality)

    environment = os.environ.copy()
    environment["TEST_APP_BIN"] = PKTHERE
    for executable in (SOCKET_REALITY_TEST, WORKER_MODES_TEST, ICMP_INTEGRATION_TEST):
        require_rust_tests(
            executable,
            timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
            env=environment,
        )
    _run_unprivileged_reality(environment)

    privileged_app: ArtifactIdentity | None = None
    privileged_reality: ArtifactIdentity | None = None
    failures: list[Exception] = []
    try:
        privileged_app = _prepare_privileged_copy(PKTHERE, TEST_APP)
        privileged_reality = _prepare_privileged_copy(
            SOCKET_REALITY_TEST, PRIVILEGED_SOCKET_REALITY_TEST
        )
        _run_privileged_reality(
            {
                **environment,
                **RAW_ICMP_TEST_ENVIRONMENT,
                "TEST_APP_BIN": TEST_APP,
            }
        )
    except PRIVILEGE_LIFECYCLE_ERRORS as error:
        failures.append(error)
    finally:
        for path in (PRIVILEGED_SOCKET_REALITY_TEST, TEST_APP):
            try:
                _destroy_privileged_copy(path)
            except PRIVILEGE_LIFECYCLE_ERRORS as error:
                failures.append(error)

    final_app = _require_unchanged(base_app)
    final_reality = _require_unchanged(base_reality)
    if privileged_app is not None and privileged_reality is not None:
        _record_privilege_evidence(
            (base_app, base_reality),
            (privileged_app, privileged_reality),
            (final_app, final_reality),
        )
    if failures:
        raise ExceptionGroup("privileged Alpine reality failures", failures)

    _run_ordinary_suites(environment)
