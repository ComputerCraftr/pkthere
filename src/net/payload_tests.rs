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
    use crate::net::icmp_echo_parse::parse_icmp_echo_header;
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
        let (ok, ident, seq, is_req, _ip_ver, payload_bounds, _src_ip, _dst_ip) =
            parse_icmp_echo_header(buf);
        assert!(ok, "test fixture should contain a valid ICMP echo packet");
        (
            Some(IcmpAdmissionInfo { ident, seq, is_req }),
            payload_bounds,
        )
    }

    #[test]
    fn explicit_icmp_header_id_is_serialized_verbatim() {
        let hdr = test_icmp_echo_header(4242, 9);
        let packet = super::payload_send::build_test_icmp_echo_packet(&hdr, &[], b"x");
        let (_, ident, seq, _is_req, _ip_ver, (start, end), _src_ip, _dst_ip) =
            parse_icmp_echo_header(&packet);
        assert_eq!(ident, 4242);
        assert_eq!(seq, 9);
        assert_eq!(&packet[start..end], b"x");
    }

    #[test]
    fn zero_length_icmp_user_payload_wire_packet_is_one_byte_longer_than_cadence() {
        let hdr = test_icmp_echo_header(4242, 9);
        let zero_len_user =
            super::payload_send::build_test_icmp_echo_packet(&hdr, &[ICMP_SHIM_IS_DATA], &[]);
        let cadence = super::payload_send::build_test_icmp_echo_packet(&hdr, &[], &[]);

        assert_eq!(zero_len_user.len(), cadence.len() + 1);
        assert_eq!(zero_len_user[8], ICMP_SHIM_IS_DATA);
        assert_eq!(cadence.len(), 8);
    }

    #[test]
    fn parse_icmp_echo_header_accepts_ipv4_with_ip_header() {
        let icmp_payload = [0xDEu8, 0xAD, 0xBE];
        let mut buf = vec![0u8; 20 + 8 + icmp_payload.len()];
        buf[0] = 0x45;
        buf[8] = 64;
        buf[9] = 1;
        buf[20] = 8;
        buf[22] = 0;
        buf[23] = 0;
        buf[24] = 0x12;
        buf[25] = 0x34;
        buf[26] = 0x00;
        buf[27] = 0x02;
        buf[28..].copy_from_slice(&icmp_payload);

        let (ok, ident, seq, is_req, _ip_ver, (start, end), _src_ip, _dst_ip) =
            parse_icmp_echo_header(&buf);
        assert!(ok);
        assert_eq!(start, 28);
        assert_eq!(end, 28 + icmp_payload.len());
        assert_eq!(ident, 0x1234);
        assert_eq!(seq, 0x0002);
        assert!(is_req);
        assert_eq!(&buf[start..end], &icmp_payload);
    }

    #[test]
    fn parse_icmp_echo_header_accepts_ipv6_with_ip_header() {
        let icmp_payload = [0xCAu8, 0xFE, 0xBA, 0xBE];
        let mut buf = vec![0u8; 40 + 8 + icmp_payload.len()];
        buf[0] = 0x60;
        buf[6] = 58;
        buf[40] = 129;
        buf[44] = 0xBE;
        buf[45] = 0xEF;
        buf[46] = 0x00;
        buf[47] = 0x2A;
        buf[48..].copy_from_slice(&icmp_payload);

        let (ok, ident, seq, is_req, _ip_ver, (start, end), _src_ip, _dst_ip) =
            parse_icmp_echo_header(&buf);
        assert!(ok);
        assert_eq!(start, 48);
        assert_eq!(end, 48 + icmp_payload.len());
        assert_eq!(ident, 0xBEEF);
        assert_eq!(seq, 0x002A);
        assert!(!is_req);
        assert_eq!(&buf[start..end], &icmp_payload);
    }

    #[test]
    fn parse_icmp_echo_header_accepts_headerless_icmp() {
        let payload = [0xABu8, 0xCD];
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.extend_from_slice(&[8, 0, 0, 0, 0x01, 0x02, 0x03, 0x04]);
        buf.extend_from_slice(&payload);

        let (ok, ident, seq, is_req, _ip_ver, (start, end), _src_ip, _dst_ip) =
            parse_icmp_echo_header(&buf);
        assert!(ok);
        assert_eq!(start, 8);
        assert_eq!(end, 8 + payload.len());
        assert_eq!(ident, 0x0102);
        assert_eq!(seq, 0x0304);
        assert!(is_req);
        assert_eq!(&buf[start..end], &payload);
    }

    #[test]
    fn parse_icmp_echo_header_rejects_truncated_input() {
        let buf = [0u8; 4];
        let (ok, _ident, _seq, _is_req, _ip_ver, (start, end), _src_ip, _dst_ip) =
            parse_icmp_echo_header(&buf);

        assert!(!ok);
        assert_eq!(start, 0);
        assert_eq!(end, 0);
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
        // A single zero shim byte is session-control, not cadence.
        let buf = [8u8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09, 0x00];
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

    fn encode_icmp_payload(shim: Option<u8>, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + shim.map_or(0, |_| 1) + payload.len());
        buf.extend_from_slice(&[8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09]);
        if let Some(shim) = shim {
            buf.push(shim);
        }
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn validate_payload_decodes_zero_len_icmp_user_datagram() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);
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
        let buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), b"abc");
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
    fn validate_payload_preserves_wire_identifier_without_external_policy() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let mut buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);
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
        .expect("wire ICMP identifier should decode without external admission policy");
        match event {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => {
                assert_eq!(icmp.logical_src_ident, 0xAA55)
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn validate_payload_does_not_enforce_external_icmp_id_policy() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let mut buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);
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
                assert_eq!(icmp.logical_src_ident, 0xAA55)
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
    fn validate_payload_rejects_invalid_icmp_shim() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let bad_reserved = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | 0x01), &[]);
        // SessionControl (0x00) but has_payload (0x40) set
        let bad_session_control_with_flag = encode_icmp_payload(Some(ICMP_SHIM_HAS_PAYLOAD), &[]);
        // SessionControl (0x00) but has actual data bytes
        let bad_session_control_with_payload = encode_icmp_payload(Some(0x00), b"x");
        // Data (0x80) with has_payload bit (0x40) but no bytes
        let bad_data_missing_payload =
            encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), &[]);
        // Data (0x80) without has_payload bit but has bytes
        let bad_data_with_unexpected_payload = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), b"x");

        for bad in [
            bad_reserved,
            bad_session_control_with_flag,
            bad_session_control_with_payload,
            bad_data_missing_payload,
            bad_data_with_unexpected_payload,
        ] {
            let (icmp_info, payload_bounds) = admitted_icmp(&bad);
            assert!(
                validate_payload(
                    true,
                    &cfg,
                    &stats,
                    &bad,
                    icmp_info,
                    payload_bounds,
                    None,
                    PayloadOrigin::Wire,
                    false,
                )
                .is_err(),
                "shim {:02X} should be rejected",
                bad.get(8).cloned().unwrap_or(0xFF)
            );
        }
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

        let ok_icmp = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA), &[]);
        let over_icmp = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), &[0]);
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
        let ok = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), b"abc");
        let over = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD), b"abcd");
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
        let mut buf = encode_icmp_payload(Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_SOURCE_ID), &[]);
        let id_bytes = 0x2002u16.to_be_bytes();
        buf.insert(9, id_bytes[0]);
        buf.insert(10, id_bytes[1]);
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

        // 2. Locked session accepts the packet but ignores shim identity takeover.
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
        .expect("locked session should ignore reflected/advisory shim identity");
        match res {
            PayloadEvent::UserPayload {
                icmp: Some(icmp), ..
            } => {
                assert_eq!(icmp.logical_src_ident, 0x04D2);
                assert_eq!(icmp.shim_src_ident, Some(0x2002));
            }
            other => panic!("unexpected event: {other:?}"),
        }

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

        // 4. Reject SessionControl
        // Handshake bit 0x20 is set, but IS_DATA (0x80) is NOT set.
        let _buf_ka = encode_icmp_payload(Some(ICMP_SHIM_HAS_SOURCE_ID), &[]);
        let mut buf_ka_full = [0u8; 11];
        buf_ka_full[..8].copy_from_slice(&[8u8, 0, 0, 0, 0x04, 0xD2, 0x00, 0x09]);
        buf_ka_full[8] = ICMP_SHIM_HAS_SOURCE_ID;
        let id_bytes = 0x2002u16.to_be_bytes();
        buf_ka_full[9] = id_bytes[0];
        buf_ka_full[10] = id_bytes[1];
        let (ka_info, ka_bounds) = admitted_icmp(&buf_ka_full);

        let res = validate_payload(
            true,
            &cfg,
            &stats,
            &buf_ka_full,
            ka_info,
            ka_bounds,
            None,
            PayloadOrigin::Wire,
            false,
        );
        assert!(res.is_err(), "should reject Source ID on SessionControl");
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("session-control packet")
        );
    }

    #[test]
    fn validate_payload_accepts_reflected_user_payload_shim_on_u2c_without_rehandshake() {
        let cfg = test_config(SupportedProtocol::UDP, SupportedProtocol::ICMP);
        let stats = Stats::new();
        let mut buf = encode_icmp_payload(
            Some(ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD | ICMP_SHIM_HAS_SOURCE_ID),
            &[],
        );
        let id_bytes = 0x2002u16.to_be_bytes();
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(b"x");
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
        .expect("reflected user payload shim should be accepted on u2c");
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
    fn validate_payload_adopts_shim_identifier_on_initial_handshake() {
        let cfg = test_config(SupportedProtocol::ICMP, SupportedProtocol::UDP);
        let stats = Stats::new();
        let buf = [
            8u8,
            0,
            0,
            0,
            0x04,
            0xD2,
            0x00,
            0x09,
            ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_SOURCE_ID,
            0x20,
            0x02,
        ];
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
