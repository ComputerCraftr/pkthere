use crate::cli::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
    RuntimeOptions, SupportedProtocol, TimeoutAction, WorkerFlowMode,
};
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple};
use crate::net::framing_shim::{
    ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelFrameKind, ReplyIdNegotiation, SessionId,
    encode_icmp_tunnel_prefix_with_source,
};
use crate::net::icmp_sequence::{
    SharedIcmpSequenceState, activate_receive_session, publish_outbound_request_through,
};
use crate::net::packet_headers::{SHIM_IS_CADENCE, SHIM_SOURCE_ID_EQUALS_HEADER};
use crate::net::payload::{
    BufferedPayload, C2uSessionControlDecision, PayloadEvent, U2cDecision,
    classify_c2u_session_control_event, classify_u2c_event, reply_id_negotiation_for_c2u,
    reply_id_negotiation_for_u2c_listener_reply,
};
use crate::worker_support::admission_test_support::{icmp_wire_spec, synthetic_receive_context};
use crate::worker_support::{RejectionReason, SocketLeg, admit_wire_packet};
use pkthere_socket_policy::{PeerSourceRequirement, ProtocolIdRequirement, ReceiveEvidencePolicy};
use socket2::Type;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

#[inline]
fn test_icmp_echo_header(logical_dst_id: u16, seq: u16, is_req: bool) -> [u8; 8] {
    let mut hdr = [0; 8];
    hdr[0] = if is_req { 8 } else { 0 };
    hdr[4..6].copy_from_slice(&logical_dst_id.to_be_bytes());
    hdr[6..8].copy_from_slice(&seq.to_be_bytes());
    hdr
}

#[test]
fn buffering_copies_user_payload_once_and_clones_reuse_the_owned_bytes() {
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"retained payload");
    let (buffered, copies) = crate::allocation_test_support::count_payload_copies(|| {
        BufferedPayload::from_event(&event, None)
    });
    assert_eq!(copies, 1);

    let (cloned, clone_copies) =
        crate::allocation_test_support::count_payload_copies(|| buffered.clone());
    assert_eq!(clone_copies, 0);
    assert!(buffered.shares_payload_storage(&cloned));
}

#[test]
fn cadence_buffering_performs_no_full_payload_copy() {
    let event = PayloadEvent::cadence_packet(1001, 7, SessionId::for_tests());
    let (_, copies) = crate::allocation_test_support::count_payload_copies(|| {
        BufferedPayload::from_event(&event, None)
    });
    assert_eq!(copies, 0);
}

fn test_config(
    listen_proto: SupportedProtocol,
    upstream_proto: SupportedProtocol,
) -> RuntimeConfig {
    RuntimeConfig {
        listen: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001)),
            1001,
        ),
        listener_source_id_request: IcmpReplyIdRequest::Default,
        listener_reply_id_request: IcmpReplyIdRequest::Default,
        listen_proto,
        listen_mode: ListenMode::Fixed,
        listen_str: String::from("test-listen"),
        upstream: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4321)),
            4321,
        ),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto,
        upstream_str: String::from("test-upstream"),
        options: RuntimeOptions {
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            timeout_secs: 10,
            icmp_handshake_timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 0,
            max_payload: 1500,
            icmp_sync_pps: 10,
            icmp_session_pool_size: crate::cli::DEFAULT_ICMP_SESSION_POOL_SIZE,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            debug_reresolve_address_file: None,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        },
    }
}

fn test_sequence_state() -> SharedIcmpSequenceState {
    let state = SharedIcmpSequenceState::new();
    let mut cache = state.cache();
    activate_receive_session(&state, &mut cache, SessionId::for_tests());
    state
}

fn publish_through(state: &SharedIcmpSequenceState, sequence: u16) {
    publish_outbound_request_through(state, SessionId::for_tests(), sequence);
}

fn validate_payload<'a>(
    c2u: bool,
    cfg: &RuntimeConfig,
    buf: &'a [u8],
    locked_icmp_remote_source_id: Option<u16>,
    is_locked: bool,
) -> Result<PayloadEvent<'a>, RejectionReason> {
    const DEFAULT_REMOTE_SOURCE_ID: u16 = 0x2002;
    let mut expected_local_id = 1001;
    let mut logical_src_id = match locked_icmp_remote_source_id {
        Some(id) => id,
        None => DEFAULT_REMOTE_SOURCE_ID,
    };

    let proto = if c2u {
        cfg.listen_proto
    } else {
        cfg.upstream_proto
    };
    let role = if c2u {
        SocketLeg::ClientFacing
    } else {
        SocketLeg::UpstreamFacing
    };
    let mut spec = if proto == SupportedProtocol::ICMP {
        let mut spec = icmp_wire_spec(None, None);
        spec.socket.role = role;
        spec
    } else {
        synthetic_receive_context(
            role,
            proto,
            Type::DGRAM,
            ReceiveEvidencePolicy {
                peer_source: PeerSourceRequirement::SourceMetadata,
                protocol_id: ProtocolIdRequirement::None,
            },
            None,
            None,
            None,
        )
    };

    if proto == SupportedProtocol::ICMP && !buf.is_empty() && buf.len() >= 8 {
        let network = spec.socket.parser.parse_network(buf);
        let parsed = spec.socket.parser.parse_transport(buf, network);
        if let Some(icmp) = parsed.icmp {
            expected_local_id = icmp.identity.destination_id;
            if let Some(source_id) = icmp.identity.source_id {
                logical_src_id = source_id;
            }
        }
    }

    if let Some(icmp) = spec.socket.policy.icmp.as_mut() {
        icmp.id_capability = pkthere_socket_policy::IcmpSocketIdCapability::DisjointIds;
    }

    spec.admission.expected_local = Some(LogicalEndpoint::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        expected_local_id,
    ));
    spec.socket.local_filter = LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, expected_local_id);

    if is_locked {
        let remote_id = match locked_icmp_remote_source_id {
            Some(id) => id,
            None => DEFAULT_REMOTE_SOURCE_ID,
        };
        let remote = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), remote_id);
        let local = LogicalEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), expected_local_id);
        spec.admission.locked_flow = Some(ClientFlowKey::Icmp(LogicalEndpoint::from_v4(
            Ipv4Addr::new(127, 0, 0, 2),
            remote_id,
        )));
        spec.admission.expected_inbound = Some(FlowTuple::new(remote, local));
        spec.admission.expected_session_id = Some(SessionId::for_tests());
    }

    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), logical_src_id).into();

    if buf.is_empty() && proto == SupportedProtocol::ICMP {
        return Ok(PayloadEvent::cadence_packet(
            expected_local_id,
            0,
            SessionId::for_tests(),
        ));
    }

    match admit_wire_packet(c2u, cfg, spec, buf, Some(&source)) {
        Ok(admitted) => Ok(admitted.event),
        Err(crate::worker_support::WirePacketRejection::Filtered(rej)) => Err(rej.reason),
        Err(crate::worker_support::WirePacketRejection::ReceiveNoise(_)) => {
            Err(RejectionReason::MalformedIcmpHeader(None))
        }
    }
}

#[test]
fn explicit_icmp_header_id_is_serialized_verbatim() {
    let packet = encode_icmp_user_payload(4242, b"x", true);
    let parser = icmp_wire_spec(None, None).socket.parser;
    let network = parser.parse_network(&packet);
    let parsed = parser.parse_transport(&packet, network);
    let icmp = parsed.icmp.expect("icmp");
    assert_eq!(icmp.identity.destination_id, 4242);
    assert_eq!(
        icmp.identity.source_id.expect("shimmed ICMP source ID"),
        0x2002
    );
    assert_eq!(icmp.seq, 9);
    let (start, end) = parsed.payload_bounds;
    assert_eq!(&packet[start..end], b"x");
}

#[test]
fn zero_length_icmp_user_payload_wire_packet_is_one_byte_longer_than_cadence() {
    let hdr = test_icmp_echo_header(4242, 9, true);
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let zero_prefix = encode_icmp_tunnel_prefix_with_source(
        IcmpTunnelFrameKind::UserPayload,
        0x1001,
        0x2002,
        SessionId::for_tests(),
        None,
        0,
        &mut scratch,
    )
    .expect("zero-length user prefix");
    let zero_len_user = super::send::build_test_icmp_echo_packet(&hdr, zero_prefix, &[]);
    let cadence = super::send::build_test_icmp_echo_packet(&hdr, &[], &[]);

    assert_eq!(zero_len_user.len(), cadence.len() + 11);
    assert_eq!(cadence.len(), 8);
}

#[test]
fn validate_payload_accepts_zero_len_udp_wire_and_synthetic_cadence_packet() {
    let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
    let buf = [];

    let wire = validate_payload(true, &cfg, &buf, None, false)
        .expect("wire zero-length UDP must be treated as user data");
    assert!(matches!(wire, PayloadEvent::UserPayload { .. }));
    assert_eq!(wire.payload_len(), 0);

    let cfg_icmp = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let synthetic = validate_payload(true, &cfg_icmp, &[], None, false)
        .expect("synthetic cadence packet should be accepted");
    assert!(matches!(synthetic, PayloadEvent::CadencePacket { .. }));
    assert_eq!(synthetic.payload_len(), 0);
}

#[test]
fn validate_payload_classifies_shimmed_zero_len_icmp_as_session_control() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let buf = encode_icmp_frame(
        0x1234,
        IcmpTunnelFrameKind::SessionControl,
        Some(0x2002),
        &[],
        true,
    );

    let event = validate_payload(true, &cfg, &buf, None, false)
        .expect("wire ICMP session-control packet should decode");
    assert!(matches!(event, PayloadEvent::SessionControl { .. }));
    match event {
        PayloadEvent::SessionControl { icmp, .. } => assert_eq!(icmp.seq(), 9),
        other => panic!("unexpected event: {other:?}"),
    }
}

fn encode_icmp_frame(
    logical_dst_id: u16,
    kind: IcmpTunnelFrameKind,
    reply_id: Option<u16>,
    payload: &[u8],
    is_req: bool,
) -> Vec<u8> {
    let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
    let source_id = reply_id.unwrap_or(0x2002);
    let advertised_reply_id = match reply_id {
        Some(id) => id,
        None => source_id,
    };
    let prefix = encode_icmp_tunnel_prefix_with_source(
        kind,
        logical_dst_id,
        source_id,
        SessionId::for_tests(),
        (kind == IcmpTunnelFrameKind::SessionControl)
            .then(|| ReplyIdNegotiation::negotiate(advertised_reply_id))
            .flatten(),
        payload.len(),
        &mut scratch,
    )
    .expect("test ICMP tunnel frame should serialize");
    let mut buf = Vec::with_capacity(8 + prefix.len() + payload.len());
    buf.extend_from_slice(&test_icmp_echo_header(logical_dst_id, 9, is_req));
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(payload);
    buf
}

fn encode_icmp_user_payload(logical_dst_id: u16, payload: &[u8], is_req: bool) -> Vec<u8> {
    encode_icmp_frame(
        logical_dst_id,
        IcmpTunnelFrameKind::UserPayload,
        Some(0x2002),
        payload,
        is_req,
    )
}

fn encode_icmp_user_payload_with_reply_id(
    logical_dst_id: u16,
    reply_id: u16,
    payload: &[u8],
    is_req: bool,
) -> Vec<u8> {
    encode_icmp_frame(
        logical_dst_id,
        IcmpTunnelFrameKind::UserPayload,
        Some(reply_id),
        payload,
        is_req,
    )
}

#[test]
fn validate_payload_decodes_zero_len_icmp_user_datagram() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let buf = encode_icmp_user_payload_with_reply_id(0x1234, 0x2002, &[], true);

    let event = validate_payload(true, &cfg, &buf, Some(0x2002), true)
        .expect("ICMP shim should decode zero-length user data");
    assert!(matches!(event, PayloadEvent::UserPayload { .. }));
    assert_eq!(event.payload_len(), 0);
}

#[test]
fn validate_payload_decodes_non_empty_icmp_user_datagram() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let buf = encode_icmp_user_payload_with_reply_id(0x1234, 0x2002, b"abc", true);

    let event = validate_payload(true, &cfg, &buf, Some(0x2002), true)
        .expect("ICMP shim should decode non-empty user data");
    assert!(matches!(event, PayloadEvent::UserPayload { .. }));
    match event {
        PayloadEvent::UserPayload { bytes, .. } => assert_eq!(bytes, b"abc"),
        other => panic!("unexpected event: {other:?}"),
    }
}

fn check_validate_payload_with_mismatched_raw_id(
    logical_dst_id: u16,
    reply_id: u16,
    locked_id: Option<u16>,
) -> crate::net::payload::IcmpPayloadMeta {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let buf = encode_icmp_user_payload_with_reply_id(logical_dst_id, reply_id, &[], true);
    let event = validate_payload(true, &cfg, &buf, locked_id, true)
        .expect("payload decoding should succeed");
    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => icmp,
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn validate_payload_uses_source_endpoint_id_as_logical_identifier() {
    let icmp = check_validate_payload_with_mismatched_raw_id(0xAA55, 0x2002, Some(0x2002));
    assert_eq!(icmp.flow_identity().remote_source_id(), 0x2002);
}

#[test]
fn validate_payload_does_not_enforce_external_icmp_id_policy() {
    let icmp = check_validate_payload_with_mismatched_raw_id(0xAA55, 0x2002, Some(0x2002));
    assert_ne!(icmp.flow_identity().remote_source_id(), 0xAA55);
    assert_eq!(icmp.inbound_header_ident(), 0xAA55);
}

#[test]
fn validate_payload_rejects_unframed_empty_icmp() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let empty_icmp = [8u8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09];
    assert_eq!(
        validate_payload(true, &cfg, &empty_icmp, None, false).unwrap_err(),
        RejectionReason::MalformedIcmpHeader(Some(
            crate::net::packet_headers::IcmpMalformedReason::InvalidShimFlags
        ))
    );
}

#[test]
fn validate_payload_max_payload_zero_allows_empty_data() {
    let mut cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
    cfg.max_payload = 0;

    let ok_udp = [];
    let over_udp = [0];

    assert!(validate_payload(true, &cfg, &ok_udp, Some(1001), true,).is_ok());
    assert!(validate_payload(true, &cfg, &over_udp, Some(1001), true,).is_err());

    // ICMP: 1 byte shim (no payload) OK, 2 bytes (shim + 1 byte payload) Fail
    let mut cfg_icmp = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    cfg_icmp.max_payload = 0;

    let ok_icmp = encode_icmp_user_payload_with_reply_id(0x1234, 1001, &[], true);
    let over_icmp = encode_icmp_user_payload_with_reply_id(0x1234, 1001, &[0], true);

    assert!(validate_payload(true, &cfg_icmp, &ok_icmp, Some(1001), true,).is_ok());
    assert!(validate_payload(true, &cfg_icmp, &over_icmp, Some(1001), true,).is_err());
}

#[test]
fn validate_payload_max_payload_excludes_icmp_shim_byte() {
    let mut cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    cfg.max_payload = 3;
    let ok = encode_icmp_user_payload_with_reply_id(0x1234, 0x2002, b"abc", true);
    let over = encode_icmp_user_payload_with_reply_id(0x1234, 0x2002, b"abcd", true);

    assert!(validate_payload(true, &cfg, &ok, Some(0x2002), true,).is_ok());
    assert!(validate_payload(true, &cfg, &over, Some(0x2002), true,).is_err());
}

#[test]
fn validate_payload_strict_handshake_rejections() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);

    // 1. Valid handshake (Unlocked, Echo Request, SessionControl)
    let mut buf = encode_icmp_frame(
        0x1234,
        IcmpTunnelFrameKind::SessionControl,
        Some(0x2002),
        &[],
        true,
    );
    let res = validate_payload(true, &cfg, &buf, None, false);

    assert!(res.is_ok());
    match res.unwrap() {
        PayloadEvent::SessionControl { icmp, .. } => {
            assert_eq!(icmp.flow_identity().remote_source_id(), 0x2002)
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // 2. Locked sessions require the already-negotiated reply ID.
    let locked_buf = encode_icmp_frame(
        0x1234,
        IcmpTunnelFrameKind::SessionControl,
        Some(0x3003),
        &[],
        true,
    );
    let res = validate_payload(true, &cfg, &locked_buf, None, true);
    assert!(
        res.is_err(),
        "locked session should require matching negotiated reply ID"
    );
    assert_eq!(
        res.unwrap_err(),
        RejectionReason::IcmpSourceEndpointMismatch
    );

    // 3. Reject Echo Reply
    buf[0] = 0; // Type 0 = Echo Reply
    let res = validate_payload(
        true, // Expected Request (type 8), but got Reply (type 0)
        &cfg, &buf, None, false,
    );
    assert!(res.is_err(), "should reject Echo Reply in C2U");
    assert!(matches!(
        res.unwrap_err(),
        RejectionReason::MalformedIcmpHeader(_)
    ));
}

#[test]
fn validate_payload_accepts_reflected_reply_id_negotiation_on_u2c_without_adopting_it() {
    let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
    let buf = encode_icmp_user_payload_with_reply_id(0x1234, 0x2002, b"x", false);

    let event = validate_payload(false, &cfg, &buf, None, true)
        .expect("reflected source endpoint ID should be tolerated on u2c");
    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => {
            assert_eq!(icmp.flow_identity().remote_source_id(), 0x2002);
            assert_eq!(icmp.advertised_reply_id(), None);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn validate_payload_parses_authenticated_unknown_session_for_reset_recovery() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let buf = encode_icmp_user_payload(0x1234, &[], true);

    let event = validate_payload(true, &cfg, &buf, None, false)
        .expect("authenticated unknown-session data must reach bounded reset recovery");
    assert!(matches!(event, PayloadEvent::UserPayload { .. }));
}

#[test]
fn validate_payload_adopts_session_control_identifier_on_initial_handshake() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let buf = encode_icmp_frame(
        0x1234,
        IcmpTunnelFrameKind::SessionControl,
        Some(0x2002),
        &[],
        true,
    );

    let event = validate_payload(true, &cfg, &buf, None, false)
        .expect("initial ICMP handshake payload should decode");
    match event {
        PayloadEvent::SessionControl { icmp, .. } => {
            assert_eq!(icmp.flow_identity().remote_source_id(), 0x2002);
            assert_eq!(icmp.advertised_reply_id(), Some(0x2002));
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn icmp_source_endpoint_id_is_immutable_for_locked_flow_identity() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::ICMP);
    let first = encode_icmp_frame(
        0x1234,
        IcmpTunnelFrameKind::SessionControl,
        Some(0x2002),
        &[],
        true,
    );
    let first_event = validate_payload(true, &cfg, &first, None, false)
        .expect("first C2U reply-ID negotiation should establish pending ICMP identity");
    let PayloadEvent::SessionControl { icmp, .. } = first_event else {
        panic!("expected session control");
    };
    assert_eq!(
        icmp.flow_identity(),
        crate::net::payload::AdmittedIcmpIdentity::new(0x2002, 0x1234)
            .expect("nonzero admitted identity")
    );

    let second = encode_icmp_user_payload_with_reply_id(0x1234, 0x3003, b"b", true);
    let second_err = validate_payload(true, &cfg, &second, Some(0x2002), true)
        .expect_err("locked C2U packet must reject source endpoint mismatch");
    assert_eq!(second_err, RejectionReason::IcmpSourceEndpointMismatch);

    let reflected = encode_icmp_user_payload_with_reply_id(0x1234, 0x2002, b"a", false);
    let reflected_event = validate_payload(false, &cfg, &reflected, None, true)
        .expect("reflected U2C source endpoint should remain payload metadata only");
    let PayloadEvent::UserPayload {
        icmp: Some(icmp), ..
    } = reflected_event
    else {
        panic!("expected reflected ICMP user payload");
    };
    assert_eq!(icmp.reply_id_negotiation(), None);
}

#[test]
fn locked_icmp_c2u_cadence_requires_an_explicit_source_shim() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let mut buf = test_icmp_echo_header(1001, 9, true).to_vec();
    buf.push(SHIM_IS_CADENCE | SHIM_SOURCE_ID_EQUALS_HEADER);
    buf.extend_from_slice(&SessionId::for_tests().get().to_be_bytes());

    let event = validate_payload(true, &cfg, &buf, Some(1001), true)
        .expect("locked C2U cadence packet with matching header ID should be accepted");

    assert!(event.is_cadence_packet());
    match event {
        PayloadEvent::CadencePacket { icmp, .. } => {
            assert_eq!(icmp.flow_identity().remote_source_id(), 1001);
            assert_eq!(icmp.inbound_header_ident(), 1001);
            assert_eq!(icmp.advertised_reply_id(), None);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn locked_icmp_c2u_with_truncated_explicit_shim_is_rejected() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let mut buf = test_icmp_echo_header(1001, 9, true).to_vec();
    buf.push(0x40);

    let err = validate_payload(true, &cfg, &buf, Some(0x2002), true)
        .expect_err("locked C2U packet with truncated explicit source shim should be rejected");

    assert!(matches!(err, RejectionReason::MalformedIcmpHeader(_)));
}

#[test]
fn locked_icmp_c2u_with_matching_source_endpoint_is_accepted() {
    let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    let buf = encode_icmp_user_payload_with_reply_id(1001, 0x2002, b"b", true);

    let event = validate_payload(true, &cfg, &buf, Some(0x2002), true)
        .expect("locked C2U packet with matching source endpoint ID should be accepted");

    match event {
        PayloadEvent::UserPayload {
            icmp: Some(icmp), ..
        } => {
            assert_eq!(icmp.flow_identity().remote_source_id(), 0x2002);
            assert_eq!(icmp.advertised_reply_id(), None);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn reply_id_negotiation_for_c2u_uses_advertised_local_reply_id_for_udp_sources() {
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"abc");

    assert_eq!(
        reply_id_negotiation_for_c2u(&event, false, 4321)
            .expect("secure session ID")
            .map(ReplyIdNegotiation::reply_id),
        Some(4321)
    );
    assert_eq!(
        reply_id_negotiation_for_c2u(&event, true, 4321).expect("acked path"),
        None
    );
}

#[test]
fn session_control_negotiation_carries_independent_source_and_reply_ids() {
    let event = PayloadEvent::session_control_negotiation(
        40000,
        9999,
        7,
        SessionId::for_tests(),
        SupportedProtocol::UDP,
        ReplyIdNegotiation::negotiate(40001).expect("nonzero test reply ID"),
    );

    match event {
        PayloadEvent::SessionControl { icmp, .. } => {
            assert_eq!(icmp.flow_identity().remote_source_id(), 40000);
            assert_eq!(icmp.advertised_reply_id(), Some(40001));
            assert!(icmp.negotiates_reply_id());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn reply_id_negotiation_for_c2u_supports_independent_source_and_reply_ids() {
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"abc");

    assert_eq!(
        reply_id_negotiation_for_c2u(&event, false, 40000)
            .expect("secure session ID")
            .map(ReplyIdNegotiation::reply_id),
        Some(40000)
    );
    assert_eq!(
        reply_id_negotiation_for_c2u(&event, true, 40000).expect("acked path"),
        None
    );
}

#[test]
fn reply_id_negotiation_for_c2u_advertises_sender_upstream_reply_id() {
    let event = PayloadEvent::user_payload(2002, 2002, 9, SupportedProtocol::ICMP, b"abc");

    assert_eq!(
        reply_id_negotiation_for_c2u(&event, false, 9999)
            .expect("secure session ID")
            .map(ReplyIdNegotiation::reply_id),
        Some(9999)
    );
}

#[test]
fn reply_id_negotiation_for_u2c_advertises_explicit_listener_reply_id() {
    let event =
        PayloadEvent::session_control(1001, 1001, 9, SupportedProtocol::ICMP, &[], Some(1001));

    assert_eq!(
        reply_id_negotiation_for_u2c_listener_reply(&event, Some(2002)),
        ReplyIdNegotiation::acknowledge(2002)
    );
    assert_eq!(
        reply_id_negotiation_for_u2c_listener_reply(&event, Some(2002)),
        ReplyIdNegotiation::acknowledge(2002)
    );
    assert_eq!(
        reply_id_negotiation_for_u2c_listener_reply(&event, None),
        ReplyIdNegotiation::acknowledge(1001)
    );
    let control = PayloadEvent::session_control(1, 1, 1, SupportedProtocol::ICMP, &[], None);
    assert_eq!(
        reply_id_negotiation_for_u2c_listener_reply(&control, Some(2002)),
        None
    );

    let ack_only = PayloadEvent::session_control_negotiation(
        1,
        1,
        1,
        SessionId::for_tests(),
        SupportedProtocol::ICMP,
        ReplyIdNegotiation::acknowledge(2002).expect("nonzero test reply ID"),
    );
    assert_eq!(
        reply_id_negotiation_for_u2c_listener_reply(&ack_only, Some(2002)),
        None
    );

    let udp_reply = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"reply");
    assert_eq!(
        reply_id_negotiation_for_u2c_listener_reply(&udp_reply, Some(2002)),
        None
    );
}

#[test]
fn reply_id_negotiation_for_c2u_never_emits_for_session_control() {
    let event =
        PayloadEvent::session_control(2002, 2002, 9, SupportedProtocol::ICMP, &[], Some(2002));

    assert_eq!(
        reply_id_negotiation_for_c2u(&event, false, 9999).expect("control path"),
        None
    );
}

#[test]
fn ipv4_header_included_packet_sets_protocol_addresses_and_checksum() {
    let mut hdr = test_icmp_echo_header(0x1234, 7, true);
    let icmp_checksum = pkthere_wire::checksum::checksum16_header(&hdr, b"abc");
    hdr[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());
    let icmp = super::send::build_test_icmp_echo_packet(&hdr, &[], b"abc");
    let src = Ipv4Addr::new(127, 0, 0, 1);
    let dst = Ipv4Addr::new(127, 0, 0, 2);
    let packet = super::send::build_test_ipv4_icmp_packet(src, dst, &icmp);

    assert_eq!(packet[0], 0x45);
    assert_eq!(
        u16::from_be_bytes([packet[2], packet[3]]),
        packet.len() as u16
    );
    assert_eq!(packet[8], 64);
    assert_eq!(packet[9], 1);
    assert_eq!(&packet[12..16], &src.octets());
    assert_eq!(&packet[16..20], &dst.octets());
    let mut sum = packet[..20]
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]) as u32)
        .sum::<u32>();
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    assert_eq!(sum, 0xffff);
    assert_eq!(&packet[20..], icmp.as_slice());
}

#[test]
fn classify_u2c_event_rejects_duplicate_user_payload_sequences() {
    let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
    let sequence_state = test_sequence_state();
    let event = PayloadEvent::user_payload(1001, 2002, 55, SupportedProtocol::UDP, b"data");
    publish_through(&sequence_state, 55);

    // First time: OK
    assert!(classify_u2c_event(&cfg, &event, &sequence_state).is_ok());

    // Second time: Duplicate
    let err = classify_u2c_event(&cfg, &event, &sequence_state).unwrap_err();
    assert!(
        err.to_string().contains("duplicate"),
        "Expected duplicate error, got: {}",
        err
    );
}

#[test]
fn classify_u2c_event_leaves_duplicate_session_control_to_protocol_state() {
    let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
    let sequence_state = test_sequence_state();
    let event =
        PayloadEvent::session_control(1001, 2002, 55, SupportedProtocol::UDP, &[], Some(2002));
    publish_through(&sequence_state, 55);

    // First time: OK
    assert!(classify_u2c_event(&cfg, &event, &sequence_state).is_ok());

    assert_eq!(
        classify_u2c_event(&cfg, &event, &sequence_state).unwrap(),
        U2cDecision::ConsumeSessionControl
    );
}

#[test]
fn test_session_control_is_consumed_for_udp_listener() {
    let mut cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
    cfg.icmp_sync_pps = 100; // sync enabled
    let sequence_state = test_sequence_state();
    let event = PayloadEvent::session_control(1001, 2002, 55, SupportedProtocol::UDP, &[], None);
    publish_through(&sequence_state, 55);

    // When listener is UDP, Session Control must be consumed locally, not forwarded.
    assert_eq!(
        classify_u2c_event(&cfg, &event, &sequence_state).unwrap(),
        U2cDecision::ConsumeSessionControl
    );
}

#[test]
fn test_session_control_replies_locally_for_udp_upstream() {
    let mut cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
    cfg.icmp_sync_pps = 100; // sync enabled
    let event = PayloadEvent::session_control(1001, 2002, 55, SupportedProtocol::UDP, &[], None);

    // Non-negotiating session-control frames are consumed; reply-ID negotiation is mandatory
    // for local ACK emission.
    assert_eq!(
        classify_c2u_session_control_event(&cfg, &event).unwrap(),
        C2uSessionControlDecision::Consume
    );
}

#[test]
fn test_session_control_forwards_only_in_icmp_bridge_with_sync() {
    let mut cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::ICMP);
    cfg.icmp_sync_pps = 100; // sync enabled
    let sequence_state = test_sequence_state();

    let event1 =
        PayloadEvent::session_control(1001, 2002, 55, SupportedProtocol::ICMP, &[], Some(2002));
    let event2 =
        PayloadEvent::session_control(1001, 2002, 56, SupportedProtocol::ICMP, &[], Some(2002));
    publish_through(&sequence_state, 56);

    // Reply-ID negotiation is answered locally; it is not forwarded as sync cadence.
    assert_eq!(
        classify_c2u_session_control_event(&cfg, &event1).unwrap(),
        C2uSessionControlDecision::ReplyLocally
    );
    assert_eq!(
        classify_u2c_event(&cfg, &event2, &sequence_state).unwrap(),
        U2cDecision::ForwardSessionControl
    );

    // Disable Sync -> Consumed Locally
    cfg.icmp_sync_pps = 0;
    let event3 =
        PayloadEvent::session_control(1001, 2002, 57, SupportedProtocol::ICMP, &[], Some(2002));
    let event4 =
        PayloadEvent::session_control(1001, 2002, 58, SupportedProtocol::ICMP, &[], Some(2002));

    assert_eq!(
        classify_c2u_session_control_event(&cfg, &event3).unwrap(),
        C2uSessionControlDecision::ReplyLocally
    );
    assert_eq!(
        classify_u2c_event(&cfg, &event4, &sequence_state).unwrap(),
        U2cDecision::ConsumeSessionControl
    );
}
