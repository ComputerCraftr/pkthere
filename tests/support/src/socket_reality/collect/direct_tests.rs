use super::direct::{RAW_DISJOINT_SOURCE_ID, RAW_PROBE_SESSION_ID, collect_udp_connected_filter};
use super::direct_icmp::build_disjoint_echo;
use super::icmp_dgram::ICMP_SEQUENCE;
use crate::socket_reality::case::{RealityCase, RealityOperation, RealitySocketPath};
use crate::socket_reality::evidence::SocketCall;
use crate::timing::{DRAIN_WAIT_MS, SOCKET_REALITY_RECEIVE_WAIT};
use pkthere_socket_policy::SocketRole;
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::parse_icmp_v4_transport;
use socket2::{Domain, Type};

#[test]
fn connected_udp_positive_receive_has_its_own_deadline() {
    for policy_role in [SocketRole::Listener, SocketRole::Upstream] {
        let case = RealityCase {
            domain: Domain::IPV4,
            target_domain: None,
            protocol: SupportedProtocol::UDP,
            socket_type: Type::DGRAM,
            socket_path: RealitySocketPath::Datagram,
            policy_role,
            connection_scenario: crate::socket_reality::case::ConnectionScenario::DirectConnected,
            operation: RealityOperation::ConnectedPeerFiltering,
        };
        let evidence = collect_udp_connected_filter(&case)
            .unwrap_or_else(|error| panic!("collect {policy_role:?} evidence: {error}"));
        let receiver = evidence
            .direct
            .socket(evidence.receiver)
            .expect("receiver evidence");
        let timeouts = receiver
            .calls
            .iter()
            .filter_map(|call| match call.call {
                SocketCall::SetReadTimeout { milliseconds, .. } => Some(milliseconds),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            timeouts,
            [
                DRAIN_WAIT_MS.as_millis() as u64,
                SOCKET_REALITY_RECEIVE_WAIT.as_millis() as u64,
            ],
            "{policy_role:?} positive receive inherited its negative-filter timeout"
        );
    }
}

#[test]
fn raw_disjoint_probe_uses_the_production_v3_data_shape() {
    let destination_id = 0x6111;
    let packet = build_disjoint_echo(
        Domain::IPV4,
        RAW_DISJOINT_SOURCE_ID,
        destination_id,
        ICMP_SEQUENCE,
        pkthere_socket_policy::IcmpChecksumMode::ApplicationComputed,
    );
    let parsed = parse_icmp_v4_transport(&packet);
    let icmp = parsed.icmp.expect("valid protocol-v3 RAW probe");

    assert_eq!(icmp.identity.source_id, Some(RAW_DISJOINT_SOURCE_ID));
    assert_eq!(icmp.identity.destination_id, destination_id);
    assert_eq!(icmp.session_id, RAW_PROBE_SESSION_ID);
    assert_eq!(icmp.seq, ICMP_SEQUENCE);
}
