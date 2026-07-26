use super::forwarder::{classify_probe_reply, resolver_path, write_resolver_revision};
use crate::socket_reality::evidence::CallResult;
use crate::socket_reality::witness::probe_payload;
use serde_json::Value;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn resolver_writer_atomically_replaces_complete_revisions() {
    let path = resolver_path();
    write_resolver_revision(
        &path,
        1,
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12002)),
        None,
    )
    .expect("write first revision");
    write_resolver_revision(
        &path,
        2,
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12003)),
        None,
    )
    .expect("replace with second revision");

    let value: Value = serde_json::from_str(&fs::read_to_string(&path).expect("read revision"))
        .expect("complete JSON");
    assert_eq!(value["revision"], 2);
    assert_eq!(value["listen_addr"], "127.0.0.1:12003");
    fs::remove_file(path).expect("remove resolver fixture");
}

#[test]
fn stale_probe_reply_keeps_its_wire_identity_and_does_not_complete_retry() {
    let expected = probe_payload(2);
    let stale = CallResult::Ok(probe_payload(1));

    assert_eq!(classify_probe_reply(&expected, &stale), Some((1, false)));
    assert_eq!(
        classify_probe_reply(&expected, &CallResult::Ok(expected.clone())),
        Some((2, true))
    );
    assert_eq!(
        classify_probe_reply(&expected, &CallResult::Ok(b"malformed".to_vec())),
        None
    );
}
