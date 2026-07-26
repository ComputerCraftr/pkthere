use super::{parse_listen_addr, parse_locked_client, parse_stats_json};

#[test]
fn parses_forwarder_output_shapes() {
    assert_eq!(
        parse_listen_addr("[INFO] Listening on UDP:127.0.0.1:1234, forwarding"),
        Some("127.0.0.1:1234".parse().expect("socket address"))
    );
    assert_eq!(
        parse_locked_client("[INFO] Locked to single client 127.0.0.1:4321 (connected)"),
        Some("127.0.0.1:4321".parse().expect("socket address"))
    );
    assert_eq!(
        parse_stats_json("[INFO] {\"locked\":true}").expect("stats")["locked"],
        true
    );
}
