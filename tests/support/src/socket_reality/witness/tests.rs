use super::{UdpWitness, payload_digest, probe_payload};
use crate::timing::{SOCKET_WITNESS_WAIT, TEST_POLL_INTERVAL};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Instant;

#[test]
fn witness_records_exact_probe_and_digest() {
    let witness = UdpWitness::spawn(
        "endpoint-a",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("spawn witness");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind client");
    client
        .set_read_timeout(Some(SOCKET_WITNESS_WAIT))
        .expect("timeout");
    let payload = probe_payload(42);
    client
        .send_to(&payload, witness.local_addr())
        .expect("send probe");
    let mut echoed = [0u8; 128];
    let length = client.recv(&mut echoed).expect("echo");
    assert_eq!(&echoed[..length], payload);
    let deadline = Instant::now() + SOCKET_WITNESS_WAIT;
    let observations = loop {
        let observations = witness.observations();
        if !observations.is_empty() {
            break observations;
        }
        assert!(Instant::now() < deadline, "witness did not record probe");
        std::thread::sleep(TEST_POLL_INTERVAL);
    };
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].probe_id, 42);
    assert_eq!(observations[0].payload_digest, payload_digest(&payload));
    let address = witness.local_addr();
    witness
        .shutdown(Instant::now() + SOCKET_WITNESS_WAIT)
        .expect("shutdown witness");
    std::net::UdpSocket::bind(address).expect("witness released UDP port");
}
