"""Container-local process evidence and stale-forwarder cleanup."""

from __future__ import annotations

import json
import os
import signal
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from ci.pkthere_ci.timing import (
    EVENT_POLL_SECONDS,
    PROCESS_LIFECYCLE_CLEANUP_TIMEOUT_SECONDS,
)

from .config import LOG_DIR, PKTHERE, TEST_APP

FORWARDER_EXECUTABLES = frozenset((Path(PKTHERE).resolve(), Path(TEST_APP).resolve()))
PROCESS_LIFECYCLE_EVIDENCE = LOG_DIR / "process-lifecycle.jsonl"


@dataclass(frozen=True)
class ProcessEvidence:
    pid: int
    parent_pid: int
    process_group: int
    session: int
    state: str
    start_ticks: int
    executable: str
    command: tuple[str, ...]
    wait_channel: str


class StaleForwarderError(RuntimeError):
    def __init__(
        self,
        label: str,
        found: tuple[ProcessEvidence, ...],
        remaining: tuple[ProcessEvidence, ...],
    ) -> None:
        self.label = label
        self.found = found
        self.remaining = remaining
        status = (
            f"{len(remaining)} process(es) resisted bounded cleanup"
            if remaining
            else "all survivors required forced harness cleanup"
        )
        super().__init__(
            f"{label} left {len(found)} stale pkthere process(es); {status}; "
            f"evidence: {PROCESS_LIFECYCLE_EVIDENCE}"
        )


class ProcessLifecycleAuditError(RuntimeError):
    pass


def audit_forwarder_lifecycle(
    label: str,
    *,
    proc_root: Path = Path("/proc"),
) -> None:
    """Fail on forwarders that outlive a test, after bounded best-effort cleanup."""
    try:
        found = snapshot_forwarders(proc_root=proc_root)
    except OSError as error:
        _append_evidence(label, "audit-error", (), (), error=str(error))
        raise ProcessLifecycleAuditError(
            f"{label} could not inspect container processes at {proc_root}: {error}"
        ) from error
    if not found:
        _append_evidence(label, "clean", (), ())
        return

    _signal_matching(found, signal.SIGTERM, proc_root)
    remaining = _wait_for_exit(
        found,
        time.monotonic() + PROCESS_LIFECYCLE_CLEANUP_TIMEOUT_SECONDS,
        proc_root,
    )
    if remaining:
        _signal_matching(remaining, signal.SIGKILL, proc_root)
        remaining = _wait_for_exit(
            remaining,
            time.monotonic() + PROCESS_LIFECYCLE_CLEANUP_TIMEOUT_SECONDS,
            proc_root,
        )
    _append_evidence(label, "stale", found, remaining)
    raise StaleForwarderError(label, found, remaining)


def snapshot_forwarders(
    *,
    proc_root: Path = Path("/proc"),
) -> tuple[ProcessEvidence, ...]:
    records: list[ProcessEvidence] = []
    process_directories = sorted(
        (path for path in proc_root.iterdir() if path.name.isdecimal()),
        key=lambda path: int(path.name),
    )
    for process_directory in process_directories:
        record = _read_process(process_directory)
        if record is not None and Path(record.executable) in FORWARDER_EXECUTABLES:
            records.append(record)
    return tuple(records)


def _read_process(process_directory: Path) -> ProcessEvidence | None:
    try:
        executable = str(process_directory.joinpath("exe").resolve(strict=True))
        stat_text = process_directory.joinpath("stat").read_text(encoding="utf-8")
        command_end = stat_text.rfind(")")
        if command_end < 0:
            return None
        stat_fields = stat_text[command_end + 2 :].split()
        command_bytes = process_directory.joinpath("cmdline").read_bytes()
        wait_channel = (
            process_directory.joinpath("wchan").read_text(encoding="utf-8").strip()
        )
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None
    if len(stat_fields) < 20:
        return None
    command = tuple(
        part.decode(errors="replace") for part in command_bytes.split(b"\0") if part
    )
    return ProcessEvidence(
        pid=int(process_directory.name),
        parent_pid=int(stat_fields[1]),
        process_group=int(stat_fields[2]),
        session=int(stat_fields[3]),
        state=stat_fields[0],
        start_ticks=int(stat_fields[19]),
        executable=executable,
        command=command,
        wait_channel=wait_channel,
    )


def _signal_matching(
    records: tuple[ProcessEvidence, ...],
    requested_signal: signal.Signals,
    proc_root: Path,
) -> None:
    for record in records:
        if not _same_process(record, proc_root):
            continue
        try:
            os.kill(record.pid, requested_signal)
        except ProcessLookupError:
            continue


def _wait_for_exit(
    records: tuple[ProcessEvidence, ...],
    deadline: float,
    proc_root: Path,
) -> tuple[ProcessEvidence, ...]:
    while True:
        remaining = tuple(
            record for record in records if _same_process(record, proc_root)
        )
        if not remaining or time.monotonic() >= deadline:
            return remaining
        time.sleep(min(EVENT_POLL_SECONDS, max(0.0, deadline - time.monotonic())))


def _same_process(record: ProcessEvidence, proc_root: Path) -> bool:
    current = _read_process(proc_root / str(record.pid))
    return current is not None and current.start_ticks == record.start_ticks


def _append_evidence(
    label: str,
    outcome: str,
    found: tuple[ProcessEvidence, ...],
    remaining: tuple[ProcessEvidence, ...],
    *,
    error: str | None = None,
) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    event = {
        "found": [asdict(record) for record in found],
        "label": label,
        "outcome": outcome,
        "remaining": [asdict(record) for record in remaining],
        "timestamp_unix_seconds": time.time(),
    }
    if error is not None:
        event["error"] = error
    with PROCESS_LIFECYCLE_EVIDENCE.open("a", encoding="utf-8") as evidence:
        evidence.write(json.dumps(event, sort_keys=True))
        evidence.write("\n")
