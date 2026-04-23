pub(crate) use pkthere_wire::packet_headers::{
    IcmpMalformedReason, IpVersion, ParsedIcmpEcho, ParsedPacketHeaders, ParsedTransport,
    ReceiveParserKernel, SHIM_ACK_REPLY_ID, SHIM_HAS_REPLY_ID, SHIM_IS_DATA,
    SHIM_NEGOTIATE_REPLY_ID, SHIM_SOURCE_ID_EQUALS_HEADER, WireIcmpIdentity,
};

use crate::cli::SupportedProtocol;
use pkthere_socket_policy::ResolvedSocketPolicy;
#[cfg(test)]
pub(crate) use pkthere_wire::packet_headers::{ParsedUdpHeader, parse_packet_headers};
use socket2::Domain;
use std::io;

pub(crate) fn ip_version_for_domain(domain: Domain) -> io::Result<IpVersion> {
    if domain == Domain::IPV4 {
        Ok(IpVersion::V4)
    } else if domain == Domain::IPV6 {
        Ok(IpVersion::V6)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported socket domain for packet parsing: {domain:?}"),
        ))
    }
}

pub(crate) fn select_packet_parser(
    proto: SupportedProtocol,
    family: Domain,
    policy: ResolvedSocketPolicy,
) -> io::Result<ReceiveParserKernel> {
    pkthere_wire::packet_headers::select_receive_parser(
        proto,
        ip_version_for_domain(family)?,
        policy.receive_header,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

#[cfg(test)]
mod tests {
    use super::{IcmpMalformedReason, ParsedTransport, select_packet_parser};
    use crate::cli::{SupportedProtocol, TimeoutAction};
    use pkthere_socket_policy::{
        IcmpPolicyIntent, SocketRole, resolve_socket_policy_with_icmp_intent,
    };
    use pkthere_wire::packet_headers::ReceiveHeaderMode;
    use socket2::{Domain, Type};

    fn parser_name(proto: SupportedProtocol, socket_type: Type, family: Domain) -> &'static str {
        let policy = resolve_socket_policy_with_icmp_intent(
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
            if cfg!(any(target_os = "macos", target_os = "ios")) {
                "ipv4-icmp-packet"
            } else {
                "icmpv4-transport"
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
        let mut policy = resolve_socket_policy_with_icmp_intent(
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
                    super::SHIM_NEGOTIATE_REPLY_ID | super::SHIM_SOURCE_ID_EQUALS_HEADER,
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
                    super::SHIM_NEGOTIATE_REPLY_ID | super::SHIM_SOURCE_ID_EQUALS_HEADER,
                ],
            ),
        ] {
            let policy = resolve_socket_policy_with_icmp_intent(
                SocketRole::Upstream,
                SupportedProtocol::ICMP,
                socket_type,
                TimeoutAction::Exit,
                false,
                family,
                IcmpPolicyIntent::default(),
            );
            let packet = if policy.receive_header == ReceiveHeaderMode::IpHeaderIncluded {
                let mut ip_packet = vec![0u8; 20];
                ip_packet[0] = 0x45;
                ip_packet[2..4].copy_from_slice(&((20 + packet.len()) as u16).to_be_bytes());
                ip_packet[9] = 1;
                ip_packet.extend_from_slice(&packet);
                ip_packet
            } else {
                packet
            };
            let parsed = select_packet_parser(SupportedProtocol::ICMP, family, policy)
                .expect("selected parser")
                .parse(&packet);
            assert_eq!(parsed.transport, ParsedTransport::Malformed);
            assert_eq!(
                parsed.icmp_malformed_reason,
                Some(IcmpMalformedReason::SessionControlMissingReplyId)
            );
        }
    }
}
