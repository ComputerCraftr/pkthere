use crate::SupportedProtocol;
use crate::packet_headers::{
    ICMP_CONTROL_NEGOTIATE, ICMP_TUNNEL_CONTROL_VERSION, IcmpMalformedReason,
    Ipv4PacketLengthEncoding, ParsedPacketHeaders, ParsedTransport, SHIM_IS_CADENCE, SHIM_IS_DATA,
    SHIM_SOURCE_ID_EQUALS_HEADER, select_receive_parser,
};
use crate::packet_headers::{IpVersion, ReceiveHeaderMode};

struct MalformedCase {
    name: &'static str,
    body: Vec<u8>,
    reason: IcmpMalformedReason,
}

fn echo(version: IpVersion, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![
        match version {
            IpVersion::V4 => 8,
            IpVersion::V6 => 128,
        },
        0,
        0,
        0,
        0x12,
        0x34,
        0,
        7,
    ];
    packet.extend_from_slice(body);
    packet
}

fn wrap_ip(
    version: IpVersion,
    receive_header: ReceiveHeaderMode,
    ipv6_extension: bool,
    transport: &[u8],
) -> Vec<u8> {
    match (version, receive_header) {
        (_, ReceiveHeaderMode::TransportHeaderOnly) => transport.to_vec(),
        (IpVersion::V4, ReceiveHeaderMode::IpHeaderIncluded) => {
            let total_len = 20 + transport.len();
            let mut packet = vec![0u8; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = 1;
            packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
            packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
            packet.extend_from_slice(transport);
            packet
        }
        (IpVersion::V6, ReceiveHeaderMode::IpHeaderIncluded) => {
            let extension_len = usize::from(ipv6_extension) * 8;
            let payload_len = extension_len + transport.len();
            let mut packet = vec![0u8; 40];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
            packet[6] = if extension_len == 0 { 58 } else { 60 };
            packet[7] = 64;
            packet[23] = 1;
            packet[39] = 1;
            if extension_len != 0 {
                packet.extend_from_slice(&[58, 0, 0, 0, 0, 0, 0, 0]);
            }
            packet.extend_from_slice(transport);
            packet
        }
        (_, ReceiveHeaderMode::PayloadOnly) => {
            unreachable!("ICMP malformed kernels do not use payload-only receive mode")
        }
    }
}

fn specialized(
    version: IpVersion,
    receive_header: ReceiveHeaderMode,
    packet: &[u8],
) -> ParsedPacketHeaders {
    select_receive_parser(
        SupportedProtocol::ICMP,
        version,
        receive_header,
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("production ICMP receive parser")
    .parse(packet)
}

fn layouts(version: IpVersion) -> &'static [(ReceiveHeaderMode, bool)] {
    match version {
        IpVersion::V4 => &[
            (ReceiveHeaderMode::TransportHeaderOnly, false),
            (ReceiveHeaderMode::IpHeaderIncluded, false),
        ],
        IpVersion::V6 => &[
            (ReceiveHeaderMode::TransportHeaderOnly, false),
            (ReceiveHeaderMode::IpHeaderIncluded, false),
            (ReceiveHeaderMode::IpHeaderIncluded, true),
        ],
    }
}

fn malformed_corpus() -> Vec<MalformedCase> {
    let mut explicit_zero_source = vec![
        0,
        0,
        0,
        ICMP_TUNNEL_CONTROL_VERSION,
        ICMP_CONTROL_NEGOTIATE,
        0x12,
        0x34,
    ];
    explicit_zero_source.extend_from_slice(&1_u64.to_be_bytes());
    explicit_zero_source.extend_from_slice(&0_u32.to_be_bytes());
    explicit_zero_source.extend_from_slice(&1_u64.to_be_bytes());
    vec![
        MalformedCase {
            name: "invalid shim",
            body: vec![0x01],
            reason: IcmpMalformedReason::InvalidShimFlags,
        },
        MalformedCase {
            name: "truncated source ID",
            body: vec![SHIM_IS_DATA],
            reason: IcmpMalformedReason::TruncatedSourceId,
        },
        MalformedCase {
            name: "data and cadence both selected",
            body: vec![SHIM_IS_DATA | SHIM_IS_CADENCE | SHIM_SOURCE_ID_EQUALS_HEADER],
            reason: IcmpMalformedReason::IllegalFrameFlags,
        },
        MalformedCase {
            name: "truncated reply ID",
            body: vec![
                SHIM_SOURCE_ID_EQUALS_HEADER,
                ICMP_TUNNEL_CONTROL_VERSION,
                ICMP_CONTROL_NEGOTIATE,
                0x12,
            ],
            reason: IcmpMalformedReason::SessionControlReplyIdLength,
        },
        MalformedCase {
            name: "control without compact flag or explicit source",
            body: vec![0, 2, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 1],
            reason: IcmpMalformedReason::InvalidSessionControlFlags,
        },
        MalformedCase {
            name: "control with compact flag and extra explicit source",
            body: vec![
                SHIM_SOURCE_ID_EQUALS_HEADER,
                0x56,
                0x78,
                2,
                0x12,
                0x34,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
            ],
            reason: IcmpMalformedReason::InvalidSessionControlFlags,
        },
        MalformedCase {
            name: "control with explicit zero source",
            body: explicit_zero_source,
            reason: IcmpMalformedReason::ZeroSourceId,
        },
    ]
}

fn assert_reason(name: &str, parsed: ParsedPacketHeaders, expected: IcmpMalformedReason) {
    assert_eq!(parsed.transport, ParsedTransport::MalformedIcmp, "{name}");
    assert_eq!(parsed.icmp_malformed_reason, Some(expected), "{name}");
}

#[test]
fn canonical_malformed_corpus_matches_every_applicable_kernel() {
    for version in [IpVersion::V4, IpVersion::V6] {
        for case in malformed_corpus() {
            for &(receive_header, ipv6_extension) in layouts(version) {
                let packet = wrap_ip(
                    version,
                    receive_header,
                    ipv6_extension,
                    &echo(version, &case.body),
                );
                assert_reason(
                    case.name,
                    specialized(version, receive_header, &packet),
                    case.reason,
                );
            }
        }
    }
}

#[test]
fn every_headerless_echo_truncation_has_canonical_first_reason() {
    for version in [IpVersion::V4, IpVersion::V6] {
        let complete = echo(version, &[]);
        for end in 1..complete.len() {
            let packet = &complete[..end];
            assert_reason(
                "truncated Echo header specialized",
                specialized(version, ReceiveHeaderMode::TransportHeaderOnly, packet),
                IcmpMalformedReason::TruncatedEchoHeader,
            );
        }
    }
}

#[test]
fn invalid_echo_code_precedes_shim_errors_but_unrelated_types_are_noise() {
    for version in [IpVersion::V4, IpVersion::V6] {
        let mut invalid_code = echo(version, &[0]);
        invalid_code[1] = 1;
        assert_reason(
            "invalid Echo code",
            specialized(
                version,
                ReceiveHeaderMode::TransportHeaderOnly,
                &invalid_code,
            ),
            IcmpMalformedReason::InvalidEchoTypeOrCode,
        );

        let mut unrelated = echo(version, &[0]);
        unrelated[0] = match version {
            IpVersion::V4 => 3,
            IpVersion::V6 => 1,
        };
        let parsed = specialized(version, ReceiveHeaderMode::TransportHeaderOnly, &unrelated);
        assert_eq!(parsed.transport, ParsedTransport::UnrelatedIcmp);
        assert_eq!(parsed.icmp_malformed_reason, None);
    }
}

#[test]
fn empty_echo_body_remains_unframed_kernel_echo_in_every_applicable_kernel() {
    for version in [IpVersion::V4, IpVersion::V6] {
        for &(receive_header, ipv6_extension) in layouts(version) {
            let packet = wrap_ip(version, receive_header, ipv6_extension, &echo(version, &[]));
            let parsed = specialized(version, receive_header, &packet);
            let icmp = parsed.icmp.expect("unframed kernel Echo");
            assert_eq!(icmp.shim_flags, None);
            assert_eq!(icmp.session_id, 0);
            assert_eq!(parsed.payload_bounds.0, parsed.payload_bounds.1);
            assert_eq!(parsed.icmp_malformed_reason, None);
        }
    }
}
