use super::{PolicyFinding, PolicyKind, analyze_rust_source, repo_root};

fn findings_at(path: &str, source: &str) -> Vec<PolicyFinding> {
    analyze_rust_source(path, source)
        .findings
        .into_iter()
        .filter(|finding| finding.kind == PolicyKind::SocketLifecycleAuthority)
        .collect()
}

#[test]
fn socket_authority_detects_ufcs_aliases_and_unsafe_prefix_conversion() {
    let source = r#"
        use socket2::Socket as RawSocket;
        fn receive(socket: &RawSocket, buffer: &mut [std::mem::MaybeUninit<u8>]) {
            drop(RawSocket::recv(socket, buffer));
            drop(unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 1) });
        }
    "#;
    assert!(findings_at("src/fixture.rs", source).len() >= 2);
}

#[test]
fn socket_authority_rejects_descriptor_duplication_and_owned_raw_escape() {
    let source = r#"
        fn leak(socket: socket2::Socket) {
            drop(socket.try_clone());
            drop(socket.into_raw_fd());
            drop(libc::dup(7));
            drop(libc::dup2(7, 8));
            drop(libc::dup3(7, 8, 0));
        }
    "#;
    assert_eq!(findings_at("src/fixture.rs", source).len(), 5);
}

#[test]
fn disconnect_syscall_authorities_are_confined_to_production_and_reality_backends() {
    let root = repo_root();
    let production =
        crate::common::rust_semantics::parse_file(&root.join("src/net/managed_socket/platform.rs"));
    let reality = crate::common::rust_semantics::parse_file(
        &root.join("tests/support/src/socket_reality/collect/disconnect_platform.rs"),
    );
    let collector = crate::common::rust_semantics::parse_file(
        &root.join("tests/support/src/socket_reality/collect/direct.rs"),
    );
    assert!(crate::common::rust_semantics::references_ident(
        &production,
        "AF_UNSPEC"
    ));
    assert!(crate::common::rust_semantics::references_ident(
        &reality,
        "AF_UNSPEC"
    ));
    assert!(
        !crate::common::rust_semantics::references_ident(&collector, "AF_UNSPEC")
            && !crate::common::rust_semantics::references_ident(&collector, "WSAGetLastError")
            && !crate::common::rust_semantics::calls(&collector, &["independent_disconnect_call"]),
        "individual collectors must call the independent platform backend"
    );
}

#[test]
fn reality_collectors_cannot_import_policy_decisions_indirectly() {
    let source = r#"
        use pkthere_socket_policy::resolve_socket_policy_for_creation_path as decide;
        fn collect() { decide(); }
    "#;
    assert_eq!(
        findings_at("tests/support/src/socket_reality/collect/helper.rs", source).len(),
        1
    );
}

#[test]
fn reality_evidence_schema_contains_observations_not_policy_conclusions() {
    let root = repo_root();
    let evidence = crate::common::rust_semantics::parse_file(
        &root.join("tests/support/src/socket_reality/evidence.rs"),
    );
    let identifiers = crate::common::rust_semantics::identifiers(&evidence);
    for forbidden in [
        "SocketRealityReport",
        "executed_case",
        "measured",
        "MismatchObserved",
        "probe_payload",
        "requested_echo_id",
        "sent_packet",
    ] {
        assert!(
            !identifiers.contains(forbidden),
            "collector evidence contains policy/conclusion identifier {forbidden}"
        );
    }
    assert!(
        identifiers
            .iter()
            .all(|identifier| !identifier.starts_with("saw_")),
        "collector evidence contains a derived saw_* conclusion field"
    );
}
