use super::{
    DiagnosticKind, DiagnosticLogIndex, DiagnosticStream, TraceKey, parse_diagnostic_line,
};

#[test]
fn runtime_readiness_uses_the_shared_schema_parser() {
    let line = concat!(
        "[DEBUG] runtime-trace ",
        "{\"diagnostic_schema\":3,\"diagnostic_sequence\":9,",
        "\"event\":\"worker-ready\",\"worker\":1,",
        "\"worker_pair\":0,\"direction\":\"u2c\"}\n"
    );

    let (kind, value) = parse_diagnostic_line(line)
        .expect("valid runtime diagnostic")
        .expect("known runtime diagnostic");

    assert_eq!(kind, DiagnosticKind::Runtime);
    assert_eq!(value["worker_pair"], 0);
    assert_eq!(value["direction"], "u2c");
}

#[test]
fn socket_evidence_parser_keeps_generation_key_and_getsockname() {
    let records = DiagnosticLogIndex::parse(
        "",
        r#"[DEBUG] socket-evidence {"diagnostic_schema":3,"diagnostic_sequence":1,"event":"socket_evidence","key":{"process_id":7,"role":"upstream","domain":"ipv4","socket_slot":3,"generation":2},"getsockname":"127.0.0.1:0"}"#,
    )
    .expect("valid evidence");
    let records = records.socket_evidence().collect::<Vec<_>>();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value["key"]["generation"], 2);
    assert_eq!(records[0].value["key"]["socket_slot"], 3);
    assert_eq!(records[0].value["getsockname"], "127.0.0.1:0");
}

#[test]
fn diagnostic_index_orders_cross_stream_records_by_production_sequence() {
    let stdout = r#"[INFO] {"diagnostic_schema":3,"diagnostic_sequence":3,"worker_flows":[]}"#;
    let stderr = concat!(
        "[DEBUG] packet-dump {\"diagnostic_schema\":3,\"diagnostic_sequence\":1,\"event\":\"packet_dump\",\"stage\":\"received\",\"worker\":2,\"direction\":\"c2u\",\"packet_id\":9}\n",
        "[DEBUG] packet-dump {\"diagnostic_schema\":3,\"diagnostic_sequence\":2,\"event\":\"packet_dump\",\"stage\":\"admission\",\"worker\":2,\"direction\":\"c2u\",\"packet_id\":9}\n",
    );
    let index = DiagnosticLogIndex::parse(stdout, stderr).expect("valid schema-3 diagnostics");
    let records = index
        .packet_records(&TraceKey {
            worker: 2,
            direction: "c2u".to_owned(),
            packet_id: 9,
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].sequence, 1);
    assert_eq!(records[0].stream, DiagnosticStream::Stderr);
    assert_eq!(index.stats().next().map(|record| record.sequence), Some(3));
}

#[test]
fn complete_trace_wait_does_not_accept_opposite_direction_disposition() {
    let stderr = concat!(
        "[DEBUG] packet-dump {\"diagnostic_schema\":3,\"diagnostic_sequence\":1,\"event\":\"packet_dump\",\"stage\":\"received\",\"worker\":0,\"direction\":\"c2u\",\"packet_id\":1}\n",
        "[DEBUG] packet-dump {\"diagnostic_schema\":3,\"diagnostic_sequence\":2,\"event\":\"packet_dump\",\"stage\":\"admission\",\"worker\":0,\"direction\":\"c2u\",\"packet_id\":1,\"admission\":{\"result\":\"accepted\"}}\n",
        "[DEBUG] packet-dump {\"diagnostic_schema\":3,\"diagnostic_sequence\":3,\"event\":\"packet_dump\",\"stage\":\"received\",\"worker\":1,\"direction\":\"u2c\",\"packet_id\":1}\n",
        "[DEBUG] packet-dump {\"diagnostic_schema\":3,\"diagnostic_sequence\":4,\"event\":\"packet_dump\",\"stage\":\"admission\",\"worker\":1,\"direction\":\"u2c\",\"packet_id\":1,\"admission\":{\"result\":\"accepted\"}}\n",
        "[DEBUG] packet-dump {\"diagnostic_schema\":3,\"diagnostic_sequence\":5,\"event\":\"packet_dump\",\"stage\":\"disposition\",\"worker\":1,\"direction\":\"u2c\",\"packet_id\":1,\"disposition\":\"forwarded\"}\n",
    );
    let incomplete =
        DiagnosticLogIndex::parse("", stderr).expect("valid opposite-direction traces");
    assert!(
        incomplete.has_complete_accepted_forwarded_trace("u2c"),
        "the U2C lifecycle is independently complete"
    );
    assert!(
        !incomplete.has_complete_accepted_forwarded_trace("c2u"),
        "an equal U2C packet ID must not complete the C2U trace"
    );
    let c2u_key = TraceKey {
        worker: 0,
        direction: "c2u".to_owned(),
        packet_id: 1,
    };
    assert_eq!(
        incomplete
            .trace_stages()
            .get(&c2u_key)
            .expect("C2U trace")
            .disposition
            .len(),
        0,
        "an equal U2C packet ID must not complete the C2U trace"
    );
}

#[test]
fn diagnostic_index_rejects_malformed_known_records() {
    let error = DiagnosticLogIndex::parse("", "[DEBUG] packet-dump {bad\n")
        .expect_err("known structured records must not be silently ignored");
    assert!(error.contains("malformed known diagnostic"));
}

#[test]
fn diagnostic_index_ignores_only_an_unterminated_trailing_record() {
    let stderr = concat!(
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":1,\"transition\":\"begin\"}\n",
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":2"
    );
    let index = DiagnosticLogIndex::parse("", stderr)
        .expect("live log snapshot may end in a partial write");
    assert_eq!(index.handshakes().count(), 1);
}

#[test]
fn completed_handshake_requires_one_ordered_matching_pair() {
    let stderr = concat!(
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":1,\"transition\":\"begin\",\"expected_ack_destination_id\":40001,\"buffered_len\":5}\n",
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":2,\"transition\":\"ack-matched\",\"expected_ack_destination_id\":40001,\"buffered_len\":5}\n",
    );
    let index = DiagnosticLogIndex::parse("", stderr).expect("valid handshake diagnostics");
    index
        .require_single_completed_handshake(5)
        .expect("one ordered handshake pair");
}

#[test]
fn completed_handshake_rejects_duplicate_begin_or_terminal_reset() {
    let stderr = concat!(
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":1,\"transition\":\"begin\",\"expected_ack_destination_id\":40001,\"buffered_len\":5}\n",
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":2,\"transition\":\"begin\",\"expected_ack_destination_id\":40001,\"buffered_len\":6}\n",
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":3,\"transition\":\"ack-matched\",\"expected_ack_destination_id\":40001,\"buffered_len\":5}\n",
        "[DEBUG] handshake-trace {\"diagnostic_schema\":3,\"diagnostic_sequence\":4,\"transition\":\"reset\"}\n",
    );
    let index = DiagnosticLogIndex::parse("", stderr).expect("valid handshake diagnostics");
    let error = index
        .require_single_completed_handshake(5)
        .expect_err("duplicate negotiation must fail the invariant");
    assert!(error.contains("observed begin=2"), "{error}");
}
