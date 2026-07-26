use crate::{SocketEvidenceKey, SocketRole};
use socket2::Domain;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn replacement_changes_domain_and_generation_but_not_slot() {
    let original = SocketEvidenceKey::initial(
        SocketRole::Upstream,
        7,
        "[::1]:0".parse().expect("IPv6 socket address"),
    );
    let replacement = original
        .replacement("127.0.0.1:0".parse().expect("IPv4 socket address"))
        .expect("replacement generation");

    assert_eq!(replacement.process_id, original.process_id);
    assert_eq!(replacement.role, original.role);
    assert_eq!(replacement.socket_slot, original.socket_slot);
    assert_eq!(replacement.generation, original.generation + 1);
    assert_eq!(original.domain, Domain::IPV6);
    assert_eq!(replacement.domain, Domain::IPV4);
}

#[test]
fn generation_changes_only_on_replacement_and_fails_before_reuse() {
    let initial = SocketEvidenceKey::initial(
        SocketRole::Upstream,
        7,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
    let replacement = initial
        .replacement(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .expect("replacement generation");
    assert_eq!(replacement.process_id, initial.process_id);
    assert_eq!(replacement.role, initial.role);
    assert_eq!(replacement.socket_slot, initial.socket_slot);
    assert_eq!(replacement.generation, initial.generation + 1);
    assert_eq!(replacement.domain, Domain::IPV6);

    let exhausted = SocketEvidenceKey {
        generation: u64::MAX,
        ..initial
    };
    assert_eq!(
        exhausted
            .replacement(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect_err("generation must not saturate or wrap")
            .generation,
        u64::MAX
    );
}
