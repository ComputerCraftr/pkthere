use super::{ReceiverRegistry, ReceiverRole};
use crate::net::managed_socket::ManagedSocket;
use pkthere_socket_policy::{PeerVerification, SocketRole};
use socket2::{Domain, Protocol, Socket, Type};

fn socket(role: ReceiverRole, generation: u64) -> ManagedSocket {
    let socket = ManagedSocket::from_unconnected(
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .expect("create receiver-slot socket"),
        PeerVerification::RequirePeerAddr,
        std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
    )
    .expect("wrap receiver-slot socket");
    socket
        .configure_worker_io_lanes(16)
        .expect("configure receiver-slot descriptor cache lane");
    socket
        .bind_authority_identity(
            match role {
                ReceiverRole::Listener => SocketRole::Listener,
                ReceiverRole::Upstream => SocketRole::Upstream,
            },
            0,
            generation,
            false,
        )
        .expect("bind receiver-slot descriptor generation");
    socket
}

#[test]
fn receiver_has_one_owner_and_replacement_is_claimed_once() {
    let first = socket(ReceiverRole::Listener, 1);
    let registry = ReceiverRegistry::new(ReceiverRole::Listener, 0, &first);
    let mut claim = registry.claim(7).expect("claim initial receiver");
    assert!(registry.claim(8).is_err(), "second owner must be rejected");
    assert_eq!(claim.generation(), 1);

    let second = socket(ReceiverRole::Listener, 2);
    registry
        .publish_socket(&second)
        .expect("publish replacement receiver");
    claim
        .prepare_for_receive()
        .expect("refresh receiver and prepare descriptor cache");
    assert_eq!(claim.generation(), 2);
    claim
        .prepare_for_receive()
        .expect("same generation preparation is idempotent");
    assert_eq!(claim.generation(), 2);
    assert_eq!(registry.snapshot(), (2, Some(7), false, false));
}

#[test]
fn old_worker_drop_cannot_leave_claimable_receive_authority() {
    let registry = ReceiverRegistry::new(
        ReceiverRole::Upstream,
        0,
        &socket(ReceiverRole::Upstream, 1),
    );
    let claim = registry.claim(3).expect("claim receiver");
    drop(claim);
    assert_eq!(registry.snapshot(), (1, None, false, true));
    assert!(registry.claim(4).is_err());
}

#[test]
fn multiple_unclaimed_replacements_publish_only_the_latest_generation() {
    let registry = ReceiverRegistry::new(
        ReceiverRole::Listener,
        0,
        &socket(ReceiverRole::Listener, 1),
    );
    registry
        .publish_socket(&socket(ReceiverRole::Listener, 2))
        .expect("publish first replacement");
    registry
        .publish_socket(&socket(ReceiverRole::Listener, 3))
        .expect("publish second replacement");
    let claim = registry.claim(5).expect("claim latest receiver");
    assert_eq!(claim.generation(), 3);
}

#[test]
fn owner_exit_after_precheck_rejects_replacement_without_publishing_an_empty_generation() {
    let first = socket(ReceiverRole::Listener, 1);
    let registry = ReceiverRegistry::new(ReceiverRole::Listener, 0, &first);
    registry
        .precheck_publication()
        .expect("precheck receiver publication");
    let claim = registry.claim(9).expect("claim receiver");
    drop(claim);

    assert!(
        registry
            .publish_socket(&socket(ReceiverRole::Listener, 2))
            .is_err(),
        "owner exit invalidates the precheck and must fail closed"
    );
    assert_eq!(registry.snapshot(), (1, None, false, true));
    assert!(registry.claim(10).is_err());
}
