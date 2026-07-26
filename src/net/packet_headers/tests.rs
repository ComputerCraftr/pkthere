use super::{IcmpMalformedReason, ParsedTransport, select_packet_parser};
use crate::cli::{SupportedProtocol, TimeoutAction};
use pkthere_socket_policy::{
    IcmpPolicyIntent, ProtocolPolicyIntent, ResolvedSocketPolicy, SocketRole,
    current_icmp_platform_capabilities, resolve_socket_policy_with_protocol_intent,
};
use pkthere_wire::packet_headers::{Ipv4PacketLengthEncoding, ReceiveHeaderMode};
use socket2::{Domain, Type};

fn test_policy(
    role: SocketRole,
    proto: SupportedProtocol,
    socket_type: Type,
    timeout: TimeoutAction,
    debug_unconnected: bool,
    family: Domain,
    icmp: IcmpPolicyIntent,
) -> ResolvedSocketPolicy {
    let intent = match proto {
        SupportedProtocol::UDP => {
            assert_eq!(icmp, IcmpPolicyIntent::default());
            ProtocolPolicyIntent::Udp
        }
        SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(icmp),
    };
    resolve_socket_policy_with_protocol_intent(
        role,
        intent,
        socket_type,
        timeout,
        debug_unconnected,
        family,
    )
}

fn parser_name(proto: SupportedProtocol, socket_type: Type, family: Domain) -> &'static str {
    let policy = test_policy(
        SocketRole::Upstream,
        proto,
        socket_type,
        TimeoutAction::Exit,
        false,
        family,
        IcmpPolicyIntent::default(),
    );
    select_packet_parser(proto, family, policy)
        .expect("resolved parser")
        .name()
}

#[test]
fn parser_selector_covers_production_socket_layouts() {
    assert_eq!(
        parser_name(SupportedProtocol::UDP, Type::DGRAM, Domain::IPV4),
        "udp-datagram-payload"
    );
    assert_eq!(
        parser_name(SupportedProtocol::ICMP, Type::DGRAM, Domain::IPV4),
        match current_icmp_platform_capabilities().icmp_v4_dgram_receive_header {
            ReceiveHeaderMode::IpHeaderIncluded => "ipv4-icmp-packet",
            ReceiveHeaderMode::TransportHeaderOnly => "icmpv4-transport",
            ReceiveHeaderMode::PayloadOnly => {
                panic!("ICMP DGRAM policy cannot select payload-only parsing")
            }
        }
    );
    assert_eq!(
        parser_name(SupportedProtocol::ICMP, Type::DGRAM, Domain::IPV6),
        "icmpv6-transport"
    );
    assert_eq!(
        parser_name(SupportedProtocol::ICMP, Type::RAW, Domain::IPV4),
        "ipv4-icmp-packet"
    );
    assert_eq!(
        parser_name(SupportedProtocol::ICMP, Type::RAW, Domain::IPV6),
        "icmpv6-transport"
    );
}

#[test]
fn parser_selector_rejects_invalid_policy_combinations() {
    let mut policy = test_policy(
        SocketRole::Upstream,
        SupportedProtocol::UDP,
        Type::DGRAM,
        TimeoutAction::Exit,
        false,
        Domain::IPV4,
        IcmpPolicyIntent::default(),
    );
    policy.receive_header = ReceiveHeaderMode::TransportHeaderOnly;
    assert!(select_packet_parser(SupportedProtocol::UDP, Domain::IPV4, policy).is_err());
}

#[test]
fn selected_specialized_kernels_preserve_malformed_reason_precedence() {
    for (family, socket_type, packet) in [
        (
            Domain::IPV4,
            Type::DGRAM,
            vec![
                8,
                0,
                0,
                0,
                0x12,
                0x34,
                0,
                1,
                super::SHIM_SOURCE_ID_EQUALS_HEADER,
            ],
        ),
        (
            Domain::IPV6,
            Type::DGRAM,
            vec![
                128,
                0,
                0,
                0,
                0x12,
                0x34,
                0,
                1,
                super::SHIM_SOURCE_ID_EQUALS_HEADER,
            ],
        ),
    ] {
        let policy = test_policy(
            SocketRole::Upstream,
            SupportedProtocol::ICMP,
            socket_type,
            TimeoutAction::Exit,
            false,
            family,
            IcmpPolicyIntent::default(),
        );
        let packet = if policy.receive_header == ReceiveHeaderMode::IpHeaderIncluded {
            if family == Domain::IPV4 {
                let mut ip_packet = vec![0u8; 20];
                ip_packet[0] = 0x45;
                let declared = match policy.ipv4_receive_length {
                    Ipv4PacketLengthEncoding::NetworkTotal => u16::try_from(20 + packet.len())
                        .expect("test IPv4 total length")
                        .to_be_bytes(),
                    Ipv4PacketLengthEncoding::DarwinHostPayload => u16::try_from(packet.len())
                        .expect("test Darwin IPv4 payload length")
                        .to_ne_bytes(),
                };
                ip_packet[2..4].copy_from_slice(&declared);
                ip_packet[9] = 1;
                ip_packet.extend_from_slice(&packet);
                ip_packet
            } else {
                let mut ip_packet = vec![0u8; 40];
                ip_packet[0] = 0x60;
                ip_packet[4..6].copy_from_slice(
                    &u16::try_from(packet.len())
                        .expect("test IPv6 payload length")
                        .to_be_bytes(),
                );
                ip_packet[6] = 58;
                ip_packet.extend_from_slice(&packet);
                ip_packet
            }
        } else {
            packet
        };
        let parser =
            select_packet_parser(SupportedProtocol::ICMP, family, policy).expect("selected parser");
        let network = parser.parse_network(&packet);
        let parsed = parser.parse_transport(&packet, network);
        assert_eq!(parsed.transport, ParsedTransport::MalformedIcmp);
        assert_eq!(
            parsed.icmp_malformed_reason,
            Some(IcmpMalformedReason::InvalidSessionControlFlags)
        );
    }
}
