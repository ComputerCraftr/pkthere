use crate::orchestrator::MatrixCase;

fn worker_str<'a>(worker: &'a serde_json::Value, field: &str) -> &'a str {
    worker[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing {field}"))
}

pub fn assert_socket_matrix_state(
    worker: &serde_json::Value,
    case: MatrixCase<'_>,
    timeout_action: &str,
    case_desc: &str,
) {
    assert_identity_fields(worker, case_desc);
    let listener_expected = !case.debug_client_unconnected
        && worker_str(worker, "client_proto") != "ICMP"
        && worker_str(worker, "client_sock_type") != "RAW"
        && (timeout_action.eq_ignore_ascii_case("exit") || cfg!(not(target_os = "freebsd")));
    let upstream_expected = if cfg!(windows)
        && worker_str(worker, "upstream_proto") == "ICMP"
        && worker_str(worker, "upstream_sock_type") == "RAW"
    {
        true
    } else {
        !case.debug_upstream_unconnected
    };
    assert_eq!(
        worker["listener_connected"]
            .as_bool()
            .expect("missing listener_connected"),
        listener_expected,
        "{case_desc}: listener_connected mismatch"
    );
    assert_eq!(
        worker["upstream_connected"]
            .as_bool()
            .expect("missing upstream_connected"),
        upstream_expected,
        "{case_desc}: upstream_connected mismatch"
    );
}

fn assert_identity_fields(worker: &serde_json::Value, case_desc: &str) {
    for field in [
        "listener_flow_outbound",
        "listen_local_filter_canonical",
        "listen_local_kernel_canonical",
        "upstream_remote_filter_canonical",
        "upstream_local_filter_canonical",
        "upstream_local_kernel_canonical",
    ] {
        assert!(
            worker[field].as_str().is_some(),
            "{case_desc}: missing stats identity field {field}"
        );
    }
}
