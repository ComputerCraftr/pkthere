#![allow(clippy::module_inception)]

use super::*;

#[cfg(test)]
#[inline]
fn test_icmp_echo_header(ident: u16, seq: u16) -> [u8; 8] {
    let mut hdr = [0u8; 8];
    let idb = ident.to_be_bytes();
    let sqb = seq.to_be_bytes();
    hdr[4] = idb[0];
    hdr[5] = idb[1];
    hdr[6] = sqb[0];
    hdr[7] = sqb[1];
    hdr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        DebugBehavior, DebugLogs, ListenMode, ReresolveMode, RuntimeConfig, SupportedProtocol,
        TimeoutAction, WorkerFlowMode,
    };
    use crate::flow_key::ClientFlowKey;
    use crate::net::framing_shim::{
        ICMP_TUNNEL_SHIM_MAX_LEN, IcmpTunnelFrameKind, encode_icmp_tunnel_prefix,
    };
    use crate::net::packet_headers::parse_packet_headers;
    use crate::net::params::CanonicalAddr;
    use crate::stats::Stats;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_config(
        listen_proto: SupportedProtocol,
        upstream_proto: SupportedProtocol,
    ) -> RuntimeConfig {
        RuntimeConfig {
            listen: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234)),
                1234,
            ),
            listen_proto,
            listen_mode: ListenMode::Fixed,
            listen_str: String::from("test-listen"),
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            upstream: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4321)),
                4321,
            ),
            upstream_local_id: 0,
            upstream_proto,
            upstream_str: String::from("test-upstream"),
            timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 0,
            max_payload: 1500,
            icmp_sync_pps: 10,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        }
    }

    fn udp_bounds(buf: &[u8]) -> (usize, usize) {
        (0, buf.len())
    }

    fn admitted_icmp(buf: &[u8]) -> (Option<IcmpAdmissionInfo>, (usize, usize)) {
        let parsed = parse_packet_headers(buf);
        let icmp = parsed
            .icmp
            .expect("test fixture should contain a valid ICMP echo packet");
        (
            Some(IcmpAdmissionInfo {
                ident: icmp.ident,
                seq: icmp.seq,
                is_req: icmp.is_req,
            }),
            parsed.payload_bounds,
        )
    }

    #[test]
    fn explicit_icmp_header_id_is_serialized_verbatim() {
        let hdr = test_icmp_echo_header(4242, 9);
        let packet = super::payload_send::build_test_icmp_echo_packet(&hdr, &[], b"x");
        let parsed = parse_packet_headers(&packet);
        let icmp = parsed.icmp.expect("icmp");
        assert_eq!(icmp.ident, 4242);
        assert_eq!(icmp.seq, 9);
        let (start, end) = parsed.payload_bounds;
        assert_eq!(&packet[start..end], b"x");
    }

    #[test]
    fn zero_length_icmp_user_payload_wire_packet_is_one_byte_longer_than_cadence() {
        let hdr = test_icmp_echo_header(4242, 9);
        let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
        let zero_prefix =
            encode_icmp_tunnel_prefix(IcmpTunnelFrameKind::UserPayload, None, 0, &mut scratch)
                .expect("zero-length user prefix");
        let zero_len_user =
            super::payload_send::build_test_icmp_echo_packet(&hdr, zero_prefix, &[]);
        let cadence = super::payload_send::build_test_icmp_echo_packet(&hdr, &[], &[]);

        assert_eq!(zero_len_user.len(), cadence.len() + 1);
        assert_eq!(cadence.len(), 8);
    }

    #[test]
    fn validate_payload_accepts_zero_len_udp_wire_and_synthetic_cadence_packet() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let stats = Stats::new();

        let wire = validate_payload(
            true,
            &cfg,
            &stats,
            &[],
            None,
            (0, 0),
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("wire zero-length UDP must be treated as user data");
        assert!(matches!(wire, PayloadEvent::UserPayload { .. }));
        assert_eq!(wire.payload_len(), 0);

        let synthetic = validate_payload(
            true,
            &cfg,
            &stats,
            &[],
            None,
            (0, 0),
            Some(cfg.listen.id),
            PayloadOrigin::SyntheticCadencePacket,
            false,
        )
        .expect("synthetic cadence packet should be accepted");
        assert!(matches!(synthetic, PayloadEvent::CadencePacket { .. }));
        assert_eq!(synthetic.payload_len(), 0);
    }

    #[test]
    fn validate_payload_classifies_shimmed_zero_len_icmp_as_session_control() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_frame(IcmpTunnelFrameKind::SessionControl, None, &[]);
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("wire ICMP session-control packet should decode");
        assert!(matches!(event, PayloadEvent::SessionControl { .. }));
        match event {
            PayloadEvent::SessionControl { icmp, .. } => assert_eq!(icmp.seq, 9),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    fn encode_icmp_frame(
        kind: IcmpTunnelFrameKind,
        source_id: Option<u16>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut scratch = [0; ICMP_TUNNEL_SHIM_MAX_LEN];
        let prefix = encode_icmp_tunnel_prefix(kind, source_id, payload.len(), &mut scratch)
            .expect("test ICMP tunnel frame should serialize");
        let mut buf = Vec::with_capacity(8 + prefix.len() + payload.len());
        buf.extend_from_slice(&[8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09]);
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(payload);
        buf
    }

    fn encode_icmp_user_payload(payload: &[u8]) -> Vec<u8> {
        encode_icmp_frame(IcmpTunnelFrameKind::UserPayload, None, payload)
    }

    fn encode_icmp_user_payload_with_source_id(source_id: u16, payload: &[u8]) -> Vec<u8> {
        encode_icmp_frame(IcmpTunnelFrameKind::UserPayload, Some(source_id), payload)
    }

    #[test]
    fn validate_payload_decodes_zero_len_icmp_user_datagram() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_user_payload_with_source_id(0x2002, &[]);
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("ICMP shim should decode zero-length user data");
        assert!(matches!(event, PayloadEvent::UserPayload { .. }));
        assert_eq!(event.payload_len(), 0);
    }

    #[test]
    fn validate_payload_decodes_non_empty_icmp_user_datagram() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_user_payload_with_source_id(0x2002, b"abc");
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("ICMP shim should decode non-empty user data");
        assert!(matches!(event, PayloadEvent::UserPayload { .. }));
        match event {
            PayloadEvent::UserPayload { data, .. } => assert_eq!(data.bytes, b"abc"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn validate_payload_uses_source_id_shim_as_logical_identifier() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let mut buf = encode_icmp_user_payload_with_source_id(0x2002, &[]);
        buf[4] = 0xAA;
        buf[5] = 0x55;
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("source ID shim should define logical ICMP peer identity");
        match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => {
                assert_eq!(icmp.logical_src_ident, 0x2002)
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn validate_payload_does_not_enforce_external_icmp_id_policy() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let mut buf = encode_icmp_user_payload_with_source_id(0x2002, &[]);
        buf[4] = 0xAA;
        buf[5] = 0x55;
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("payload decoding should not enforce receive-side ICMP ID admission");
        match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => {
                assert_eq!(icmp.logical_src_ident, 0x2002)
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn validate_payload_accepts_empty_icmp_as_cadence_packet() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let empty_icmp = [8u8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09];
        let (icmp_info, payload_bounds) = admitted_icmp(&empty_icmp);
        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &empty_icmp,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("empty ICMP should be accepted as cadence packet");
        assert!(event.is_cadence_packet());
    }

    #[test]
    fn validate_payload_max_payload_zero_allows_empty_data() {
        let mut cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::UDP);
        cfg.max_payload = 0;
        let stats = Stats::new();

        // UDP: 0 bytes OK, 1 byte Fail
        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &[],
                None,
                udp_bounds(&[]),
                None,
                PayloadOrigin::Wire,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &[0],
                None,
                udp_bounds(&[0]),
                None,
                PayloadOrigin::Wire,
                false,
            )
            .is_err()
        );

        // ICMP: 1 byte shim (no payload) OK, 2 bytes (shim + 1 byte payload) Fail
        let mut cfg_icmp = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        cfg_icmp.max_payload = 0;

        let ok_icmp = encode_icmp_user_payload_with_source_id(0x2002, &[]);
        let over_icmp = encode_icmp_user_payload_with_source_id(0x2002, &[0]);
        let (ok_icmp_info, ok_icmp_bounds) = admitted_icmp(&ok_icmp);
        let (over_icmp_info, over_icmp_bounds) = admitted_icmp(&over_icmp);

        assert!(
            validate_payload(
                true,
                &cfg_icmp,
                &stats,
                &ok_icmp,
                ok_icmp_info,
                ok_icmp_bounds,
                None,
                PayloadOrigin::Wire,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_payload(
                true,
                &cfg_icmp,
                &stats,
                &over_icmp,
                over_icmp_info,
                over_icmp_bounds,
                None,
                PayloadOrigin::Wire,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn validate_payload_max_payload_excludes_icmp_shim_byte() {
        let mut cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        cfg.max_payload = 3;
        let stats = Stats::new();
        let ok = encode_icmp_user_payload_with_source_id(0x2002, b"abc");
        let over = encode_icmp_user_payload_with_source_id(0x2002, b"abcd");
        let (ok_info, ok_bounds) = admitted_icmp(&ok);
        let (over_info, over_bounds) = admitted_icmp(&over);

        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &ok,
                ok_info,
                ok_bounds,
                None,
                PayloadOrigin::Wire,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_payload(
                true,
                &cfg,
                &stats,
                &over,
                over_info,
                over_bounds,
                None,
                PayloadOrigin::Wire,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn validate_payload_strict_handshake_rejections() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();

        // 1. Valid handshake (Unlocked, Echo Request, UserData)
        let mut buf = encode_icmp_user_payload_with_source_id(0x2002, &[]);
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);
        let res = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        );
        assert!(res.is_ok());
        match res.unwrap() {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => {
                assert_eq!(icmp.logical_src_ident, 0x2002)
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // 2. Locked sessions reject additional source-ID shims.
        let res = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            true,
        )
        .expect_err("locked session should reject additional source-ID shim");
        assert!(res.to_string().contains("initial C2U lock"));

        // 3. Reject Echo Reply
        buf[0] = 0; // Type 0 = Echo Reply
        let (reply_info, reply_bounds) = admitted_icmp(&buf);
        // Need c2u=true but buffer type=0 (Reply) to trigger !src_is_req
        let res = validate_payload(
            true, // Expected Request (type 8), but got Reply (type 0)
            &cfg,
            &stats,
            &buf,
            reply_info,
            reply_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        );
        assert!(res.is_err(), "should reject Source ID on Echo Reply");
        let err_msg = res.unwrap_err().to_string();
        // validate_payload currently prioritize Echo type mismatch error over shim handshake checks if c2u=true
        assert!(err_msg.contains("direction mismatch") || err_msg.contains("on Echo Reply"));
    }

    #[test]
    fn validate_payload_accepts_reflected_source_id_shim_on_u2c_without_adopting_it() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let stats = Stats::new();
        let mut buf = encode_icmp_user_payload_with_source_id(0x2002, b"x");
        buf[0] = 0; // Echo Reply for u2c path
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let event = validate_payload(
            false,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            true,
        )
        .expect("reflected source-ID shim should be tolerated on u2c");
        match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => {
                assert_eq!(icmp.logical_src_ident, 0x04D2);
                assert_eq!(icmp.shim_src_ident, Some(0x2002));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn validate_payload_rejects_initial_icmp_user_payload_without_source_id() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_user_payload(&[]);
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let err = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect_err("initial ICMP lock should require source-ID shim");
        assert!(err.to_string().contains("requires source ID shim"));
    }

    #[test]
    fn validate_payload_adopts_shim_identifier_on_initial_handshake() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_user_payload_with_source_id(0x2002, &[]);
        let (icmp_info, payload_bounds) = admitted_icmp(&buf);

        let event = validate_payload(
            true,
            &cfg,
            &stats,
            &buf,
            icmp_info,
            payload_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("initial ICMP handshake payload should decode");
        match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => {
                assert_eq!(icmp.logical_src_ident, 0x2002);
                assert_eq!(icmp.shim_src_ident, Some(0x2002));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn icmp_source_id_shim_is_single_use_for_locked_flow_identity() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let src = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0)),
            0x04D2,
        );

        let first = encode_icmp_user_payload_with_source_id(0x2002, b"a");
        let (first_info, first_bounds) = admitted_icmp(&first);
        let first_event = validate_payload(
            true,
            &cfg,
            &stats,
            &first,
            first_info,
            first_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        )
        .expect("first C2U source-ID shim should establish ICMP identity");
        let locked_flow =
            ClientFlowKey::from_validated_client_payload(true, src, cfg.listen_proto, &first_event)
                .expect("first C2U user payload should produce a flow key");
        assert_eq!(
            locked_flow,
            ClientFlowKey::IcmpV4 {
                ip: Ipv4Addr::new(127, 0, 0, 2),
                ident: 0x2002,
            }
        );

        let second = encode_icmp_user_payload_with_source_id(0x3003, b"b");
        let (second_info, second_bounds) = admitted_icmp(&second);
        let second_err = validate_payload(
            true,
            &cfg,
            &stats,
            &second,
            second_info,
            second_bounds,
            None,
            PayloadOrigin::Wire,
            true,
        )
        .expect_err("locked C2U packet must reject a second source-ID shim");
        assert!(second_err.to_string().contains("initial C2U lock"));
        assert_eq!(
            locked_flow,
            ClientFlowKey::IcmpV4 {
                ip: Ipv4Addr::new(127, 0, 0, 2),
                ident: 0x2002,
            }
        );

        let mut reflected = encode_icmp_user_payload_with_source_id(0x2002, b"a");
        reflected[0] = 0;
        let (reflected_info, reflected_bounds) = admitted_icmp(&reflected);
        let reflected_event = validate_payload(
            false,
            &cfg,
            &stats,
            &reflected,
            reflected_info,
            reflected_bounds,
            None,
            PayloadOrigin::Wire,
            true,
        )
        .expect("reflected U2C source-ID shim should remain payload metadata only");
        assert_eq!(
            ClientFlowKey::from_validated_client_payload(
                false,
                src,
                cfg.listen_proto,
                &reflected_event
            ),
            None
        );
        assert_eq!(
            locked_flow,
            ClientFlowKey::IcmpV4 {
                ip: Ipv4Addr::new(127, 0, 0, 2),
                ident: 0x2002,
            }
        );
    }

    #[test]
    fn source_id_shim_for_c2u_uses_upstream_local_id_for_udp_sources() {
        let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, b"abc");

        assert_eq!(source_id_shim_for_c2u(&event, false, 4321), Some(4321));
        assert_eq!(source_id_shim_for_c2u(&event, true, 4321), None);
    }

    #[test]
    fn source_id_shim_for_c2u_propagates_logical_icmp_source_id() {
        let event =
            PayloadEvent::user_payload(2002, 9, SupportedProtocol::ICMP, b"abc", Some(2002));

        assert_eq!(source_id_shim_for_c2u(&event, false, 9999), Some(2002));
    }

    #[test]
    fn source_id_shim_for_c2u_never_emits_for_session_control() {
        let event =
            PayloadEvent::session_control(2002, 9, SupportedProtocol::ICMP, &[], Some(2002));

        assert_eq!(source_id_shim_for_c2u(&event, false, 9999), None);
    }
}
