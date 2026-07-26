use serde_json::json;

#[test]
fn flow_tuple_splits_exact_source_and_destination() {
    let worker = json!({"listener_flow_outbound":"127.0.0.1:1202 -> 127.0.0.1:54666"});
    assert_eq!(
        super::flow_tuple(&worker, "listener_flow_outbound"),
        ("127.0.0.1:1202", "127.0.0.1:54666")
    );
}

#[test]
#[should_panic(expected = "flow field must contain 'src -> dst'")]
fn flow_tuple_rejects_malformed_flow_string() {
    let worker = json!({"listener_flow_outbound":"127.0.0.1:1202"});
    super::flow_tuple(&worker, "listener_flow_outbound");
}
