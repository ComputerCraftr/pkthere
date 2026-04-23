"""Cross-namespace four-ID and timeout profiles."""

from __future__ import annotations

import socket
import threading
import time

from .command_runner import CommandResult, CommandRunner
from .config import LOG_DIR, TOPOLOGY_VERIFIER, required, required_int
from .processes import exec_forwarder, run, wait_for
from .timing import (
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    FLOW_REPLY_TIMEOUT_SECONDS,
    FLOW_RETRY_SECONDS,
    FORWARDER_NODE_TIMEOUT_SECONDS,
    HANDSHAKE_TIMEOUT_SECONDS,
    TOPOLOGY_EVENT_TIMEOUT_SECONDS,
    VERIFIER_TIMEOUT_SECONDS,
)

FLOW_DEADLINE_SECONDS = TOPOLOGY_EVENT_TIMEOUT_SECONDS
RUNNER = CommandRunner()


def node_a() -> None:
    exec_forwarder(
        "node-a",
        [
            "--here",
            f"UDP:0.0.0.0:{required_int('CLIENT_UDP_PORT')}",
            "--there",
            f"ICMP:{required('NODE_B_IP')}:{required_int('SERVER_DESTINATION_ID')}",
            "--there-source-id",
            required("CLIENT_SOURCE_ID"),
            "--there-reply-id",
            required("CLIENT_REPLY_ID"),
            "--workers",
            str(required_int("NODE_A_WORKERS")),
            "--worker-flow-mode",
            "shared-flow",
            "--timeout-secs",
            str(FORWARDER_NODE_TIMEOUT_SECONDS),
            "--on-timeout",
            "exit",
        ],
    )


def node_b() -> None:
    exec_forwarder(
        "node-b",
        [
            "--here",
            f"ICMP:0.0.0.0:{required_int('SERVER_DESTINATION_ID')}",
            "--here-source-id",
            required("SERVER_SOURCE_ID"),
            "--there",
            f"UDP:{required('ECHO_IP')}:{required_int('ECHO_UDP_PORT')}",
            "--workers",
            str(required_int("NODE_B_WORKERS")),
            "--worker-flow-mode",
            "single-flow",
            "--timeout-secs",
            str(FORWARDER_NODE_TIMEOUT_SECONDS),
            "--on-timeout",
            "exit",
        ],
    )


def udp_echo() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
        echo.bind(("0.0.0.0", required_int("ECHO_UDP_PORT")))
        while True:
            payload, peer = echo.recvfrom(65_535)
            echo.sendto(payload, peer)


def driver() -> None:
    payload = required("FOUR_ID_PAYLOAD").encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        require_udp_echo(client, payload, "initial four-ID flow")

        (LOG_DIR / "legitimate-flow-ready").touch()
        wait_for(lambda: (LOG_DIR / "attacker-finished").exists(), "attacker")
        require_udp_echo(
            client,
            required("POST_ATTACK_PAYLOAD").encode(),
            "post-injection locked flow",
        )

    wait_for_verifier("four-id", "topology-verdict.json")


def require_udp_echo(client: socket.socket, payload: bytes, context: str) -> None:
    deadline = time.monotonic() + FLOW_DEADLINE_SECONDS
    last_reply: bytes | None = None
    client.settimeout(FLOW_REPLY_TIMEOUT_SECONDS)
    while time.monotonic() < deadline:
        client.sendto(
            payload,
            (required("NODE_A_IP"), required_int("CLIENT_UDP_PORT")),
        )
        try:
            reply, _ = client.recvfrom(65_535)
            last_reply = reply
            if reply == payload:
                return
        except TimeoutError:
            pass
        time.sleep(FLOW_RETRY_SECONDS)
    raise AssertionError(f"{context} returned {last_reply!r}, expected {payload!r}")


def blackhole() -> None:
    run(
        ["iptables", "-A", "INPUT", "-p", "icmp", "-j", "DROP"],
        timeout_seconds=DOCKER_CONTROL_TIMEOUT_SECONDS,
    )
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "blackhole-ready").touch()
    threading.Event().wait()


def timeout_node() -> None:
    wait_for(lambda: (LOG_DIR / "blackhole-ready").exists(), "blackhole")
    (LOG_DIR / "timeout-node-started").touch()
    exec_forwarder(
        "timeout-node",
        [
            "--here",
            f"UDP:0.0.0.0:{required_int('TIMEOUT_UDP_PORT')}",
            "--there",
            f"ICMP:{required('BLACKHOLE_IP')}:{required_int('SERVER_DESTINATION_ID')}",
            "--there-source-id",
            required("CLIENT_SOURCE_ID"),
            "--there-reply-id",
            required("CLIENT_REPLY_ID"),
            "--icmp-handshake-timeout-secs",
            str(HANDSHAKE_TIMEOUT_SECONDS),
            "--timeout-secs",
            str(FORWARDER_NODE_TIMEOUT_SECONDS),
            "--on-timeout",
            "drop",
        ],
    )


def timeout_driver() -> None:
    wait_for(lambda: (LOG_DIR / "blackhole-ready").exists(), "blackhole")
    wait_for(lambda: (LOG_DIR / "timeout-node-started").exists(), "timeout node")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        deadline = time.monotonic() + TOPOLOGY_EVENT_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            client.sendto(
                required("TIMEOUT_PAYLOAD").encode(),
                (required("TIMEOUT_NODE_IP"), required_int("TIMEOUT_UDP_PORT")),
            )
            if run_verifier("timeout", "timeout-verdict.json"):
                return
            time.sleep(FLOW_RETRY_SECONDS)
    raise verifier_timeout(
        "timeout", "typed verifier did not observe the timeout lifecycle"
    )


def wait_for_verifier(profile: str, verdict_name: str) -> None:
    try:
        wait_for(
            lambda: run_verifier(profile, verdict_name),
            f"{profile} verifier verdict",
        )
    except TimeoutError as error:
        raise verifier_timeout(profile, str(error)) from error


def verifier_timeout(profile: str, context: str) -> TimeoutError:
    error_path = LOG_DIR / f"{profile}-verifier.err"
    if error_path.is_file():
        detail = error_path.read_text(encoding="utf-8").strip()
    else:
        detail = "verifier did not preserve a failure diagnostic"
    return TimeoutError(f"{context}\nlast verifier failure:\n{detail}")


def verifier_failure_output(completed: CommandResult) -> str:
    sections: list[str] = []
    if completed.stdout.strip():
        sections.append(f"stdout:\n{completed.stdout.strip()}")
    if completed.stderr.strip():
        sections.append(f"stderr:\n{completed.stderr.strip()}")
    if not sections:
        sections.append(f"verifier exited with status {completed.returncode}")
    return "\n".join(sections) + "\n"


def run_verifier(profile: str, verdict_name: str) -> bool:
    completed = RUNNER.run(
        [TOPOLOGY_VERIFIER, profile, "--log-dir", str(LOG_DIR)],
        timeout_seconds=VERIFIER_TIMEOUT_SECONDS,
        check=False,
        capture_output=True,
    )
    if completed.returncode == 0:
        (LOG_DIR / verdict_name).write_text(completed.stdout, encoding="utf-8")
        (LOG_DIR / f"{profile}-verifier.err").unlink(missing_ok=True)
        return True
    (LOG_DIR / f"{profile}-verifier.err").write_text(
        verifier_failure_output(completed), encoding="utf-8"
    )
    return False
