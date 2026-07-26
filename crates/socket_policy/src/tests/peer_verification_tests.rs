use crate::{
    IcmpPolicyIntent, PeerVerification, ProtocolPolicyIntent, SocketRole, TimeoutAction,
    ip_version_for_domain, resolve_socket_policy_with_protocol_intent,
};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::IpVersion;
use socket2::{Domain, Type};

fn resolved_peer_verification(
    role: SocketRole,
    protocol: SupportedProtocol,
    socket_type: Type,
    domain: Domain,
) -> PeerVerification {
    resolve_socket_policy_with_protocol_intent(
        role,
        match protocol {
            SupportedProtocol::UDP => ProtocolPolicyIntent::Udp,
            SupportedProtocol::ICMP => ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
        },
        socket_type,
        TimeoutAction::Drop,
        false,
        domain,
    )
    .peer_verification
}

#[test]
fn resolved_peer_verification_preserves_protocol_specific_kernel_evidence() {
    for role in [SocketRole::Listener, SocketRole::Upstream] {
        for domain in [Domain::IPV4, Domain::IPV6] {
            assert_eq!(
                resolved_peer_verification(role, SupportedProtocol::ICMP, Type::DGRAM, domain),
                PeerVerification::ConnectSuccess
            );
            assert_eq!(
                resolved_peer_verification(role, SupportedProtocol::UDP, Type::DGRAM, domain),
                PeerVerification::RequirePeerAddr
            );
            assert_eq!(
                resolved_peer_verification(role, SupportedProtocol::ICMP, Type::RAW, domain),
                PeerVerification::RequirePeerNetworkAddress
            );
        }
    }
}

#[test]
fn peer_observation_validation_is_path_specific_without_weakening_unconnected_state() {
    use std::net::{Ipv4Addr, SocketAddr};

    let expected = SocketAddr::from((Ipv4Addr::LOCALHOST, 41_000));
    let kernel_zero_id = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let other_address = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 41_000));

    assert!(PeerVerification::RequirePeerAddr.accepts_observation(Some(expected), Some(expected)));
    assert!(
        !PeerVerification::RequirePeerAddr
            .accepts_observation(Some(expected), Some(kernel_zero_id))
    );
    assert!(
        PeerVerification::RequirePeerNetworkAddress
            .accepts_observation(Some(expected), Some(kernel_zero_id))
    );
    assert!(
        !PeerVerification::RequirePeerNetworkAddress
            .accepts_observation(Some(expected), Some(other_address))
    );
    assert!(PeerVerification::ConnectSuccess.accepts_observation(Some(expected), None));
    assert!(!PeerVerification::ConnectSuccess.accepts_observation(None, Some(expected)));
}

#[test]
fn socket_domain_has_one_checked_wire_ip_version_adapter() {
    assert_eq!(
        ip_version_for_domain(Domain::IPV4).expect("IPv4 domain"),
        IpVersion::V4
    );
    assert_eq!(
        ip_version_for_domain(Domain::IPV6).expect("IPv6 domain"),
        IpVersion::V6
    );
    assert!(ip_version_for_domain(Domain::from(i32::MAX)).is_err());
}

#[test]
fn kernel_local_id_trust_is_resolved_once_for_endpoint_and_id_consumers() {
    for domain in [Domain::IPV4, Domain::IPV6] {
        let raw = resolve_socket_policy_with_protocol_intent(
            SocketRole::Upstream,
            ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
            Type::RAW,
            TimeoutAction::Drop,
            false,
            domain,
        )
        .icmp
        .expect("RAW ICMP policy");
        assert_eq!(raw.trusted_kernel_local_id(0), None);
        assert_eq!(raw.trusted_kernel_local_id(1), None);
        assert_eq!(raw.trusted_kernel_local_id(58), None);

        let dgram = resolve_socket_policy_with_protocol_intent(
            SocketRole::Upstream,
            ProtocolPolicyIntent::Icmp(IcmpPolicyIntent::default()),
            Type::DGRAM,
            TimeoutAction::Drop,
            false,
            domain,
        )
        .icmp
        .expect("DGRAM ICMP policy");
        assert_eq!(dgram.trusted_kernel_local_id(0), None);
        assert_eq!(dgram.trusted_kernel_local_id(1234), Some(1234));
    }
}
