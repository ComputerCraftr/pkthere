"""Exact Miri boundary-test ownership for local and CI runners."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MiriBoundarySelection:
    label: str
    package: str
    target_flag: str
    target_name: str | None
    test_name: str

    def target_arguments(self) -> tuple[str, ...]:
        if self.target_name is None:
            return (self.target_flag,)
        return (self.target_flag, self.target_name)

    def miri_listing_arguments(self, toolchain: str) -> tuple[str, ...]:
        return (
            "cargo",
            f"+{toolchain}",
            "miri",
            "test",
            "--locked",
            "-p",
            self.package,
            *self.target_arguments(),
            "--",
            "--list",
        )

    def miri_arguments(self, toolchain: str) -> tuple[str, ...]:
        return (
            "cargo",
            f"+{toolchain}",
            "miri",
            "test",
            "--locked",
            "-p",
            self.package,
            *self.target_arguments(),
            self.test_name,
            "--",
            "--exact",
            "--nocapture",
        )


MIRI_BOUNDARY_TESTS = (
    MiriBoundarySelection(
        "Receive sequence wrap boundary",
        "pkthere",
        "--bin",
        "pkthere",
        "net::icmp_sequence::tests::receive_sequence_space_never_wraps_within_one_session",
    ),
    MiriBoundarySelection(
        "Sequence generation exhaustion boundary",
        "pkthere",
        "--bin",
        "pkthere",
        "net::icmp_sequence::tests::client_lock_sequence_reset_preflights_both_directions_before_mutation",
    ),
    MiriBoundarySelection(
        "Handshake receive-time deadline boundary",
        "pkthere",
        "--bin",
        "pkthere",
        "flow_state::tests::handshake_closure::initial_ack_uses_packet_observation_time_and_preserves_expired_state",
    ),
    MiriBoundarySelection(
        "Reserve ACK receive-time deadline boundary",
        "pkthere",
        "--bin",
        "pkthere",
        "flow_state::session_pool_tests::reserve_ack_deadline_uses_observation_time_without_removing_candidate",
    ),
    MiriBoundarySelection(
        "Directional session allocator wrap boundary",
        "pkthere",
        "--bin",
        "pkthere",
        "net::framing_shim::tests::directional_session_allocation_fails_before_response_identity_wraps",
    ),
    MiriBoundarySelection(
        "Production IPv6 extension parser boundaries",
        "pkthere-wire",
        "--lib",
        None,
        "packet_headers::kernels::kernels_tests::production_ipv6_parser_rejects_extension_chains_fragments_and_truncations",
    ),
)
