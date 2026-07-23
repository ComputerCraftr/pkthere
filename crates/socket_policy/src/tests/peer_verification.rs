use crate::{PeerVerification, SocketCreationPath, ip_version_for_domain, peer_verification};
use pkthere_wire::SupportedProtocol;
use pkthere_wire::packet_headers::IpVersion;
use socket2::{Domain, Type};

#[test]
fn relaxed_peer_verification_is_limited_to_icmp_datagram_creation() {
    assert_eq!(
        peer_verification(
            SupportedProtocol::ICMP,
            Type::DGRAM,
            SocketCreationPath::Datagram,
        ),
        PeerVerification::ConnectSuccess
    );
    assert_eq!(
        peer_verification(
            SupportedProtocol::UDP,
            Type::DGRAM,
            SocketCreationPath::Datagram,
        ),
        PeerVerification::RequirePeerAddr
    );
    assert_eq!(
        peer_verification(
            SupportedProtocol::ICMP,
            Type::RAW,
            SocketCreationPath::RawIcmp,
        ),
        PeerVerification::RequirePeerAddr
    );
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
