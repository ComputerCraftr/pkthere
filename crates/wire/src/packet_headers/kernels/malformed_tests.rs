use crate::packet_headers::{
    IcmpMalformedReason, ParsedPacketHeaders, ParsedTransport, SHIM_HAS_REPLY_ID, SHIM_IS_DATA,
    SHIM_NEGOTIATE_REPLY_ID, SHIM_SOURCE_ID_EQUALS_HEADER, parse_icmp_v4_transport,
    parse_icmp_v6_transport, parse_ipv4_icmp_packet, parse_ipv6_icmp_packet, parse_packet_headers,
};

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

#[derive(Clone, Copy)]
enum Layout {
    Headerless,
    IpHeader,
    Ipv6Extension,
}

struct MalformedCase {
    name: &'static str,
    body: Vec<u8>,
    reason: IcmpMalformedReason,
}

fn echo(family: Family, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![
        match family {
            Family::V4 => 8,
            Family::V6 => 128,
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

fn wrap_ip(family: Family, layout: Layout, transport: &[u8]) -> Vec<u8> {
    match (family, layout) {
        (_, Layout::Headerless) => transport.to_vec(),
        (Family::V4, Layout::IpHeader) => {
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
        (Family::V6, Layout::IpHeader | Layout::Ipv6Extension) => {
            let extension_len = usize::from(matches!(layout, Layout::Ipv6Extension)) * 8;
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
        (Family::V4, Layout::Ipv6Extension) => unreachable!("IPv4 has no IPv6 extension layout"),
    }
}

fn specialized(family: Family, layout: Layout, packet: &[u8]) -> ParsedPacketHeaders {
    match (family, layout) {
        (Family::V4, Layout::Headerless) => parse_icmp_v4_transport(packet),
        (Family::V6, Layout::Headerless) => parse_icmp_v6_transport(packet),
        (Family::V4, Layout::IpHeader) => parse_ipv4_icmp_packet(packet),
        (Family::V6, Layout::IpHeader | Layout::Ipv6Extension) => parse_ipv6_icmp_packet(packet),
        (Family::V4, Layout::Ipv6Extension) => unreachable!("inapplicable layout"),
    }
}

fn malformed_corpus() -> Vec<MalformedCase> {
    vec![
        MalformedCase {
            name: "invalid shim",
            body: vec![0],
            reason: IcmpMalformedReason::InvalidShimFlags,
        },
        MalformedCase {
            name: "truncated source ID",
            body: vec![SHIM_IS_DATA],
            reason: IcmpMalformedReason::TruncatedSourceId,
        },
        MalformedCase {
            name: "illegal data negotiation flags",
            body: vec![SHIM_IS_DATA | SHIM_SOURCE_ID_EQUALS_HEADER | SHIM_HAS_REPLY_ID],
            reason: IcmpMalformedReason::IllegalFrameFlags,
        },
        MalformedCase {
            name: "missing reply ID flag",
            body: vec![SHIM_NEGOTIATE_REPLY_ID | SHIM_SOURCE_ID_EQUALS_HEADER],
            reason: IcmpMalformedReason::SessionControlMissingReplyId,
        },
        MalformedCase {
            name: "truncated reply ID",
            body: vec![
                SHIM_NEGOTIATE_REPLY_ID | SHIM_SOURCE_ID_EQUALS_HEADER | SHIM_HAS_REPLY_ID,
                0x12,
            ],
            reason: IcmpMalformedReason::SessionControlReplyIdLength,
        },
    ]
}

fn assert_reason(name: &str, parsed: ParsedPacketHeaders, expected: IcmpMalformedReason) {
    assert_eq!(parsed.transport, ParsedTransport::Malformed, "{name}");
    assert_eq!(parsed.icmp_malformed_reason, Some(expected), "{name}");
}

#[test]
fn canonical_malformed_corpus_matches_every_applicable_kernel() {
    for family in [Family::V4, Family::V6] {
        let layouts: &[Layout] = match family {
            Family::V4 => &[Layout::Headerless, Layout::IpHeader],
            Family::V6 => &[Layout::Headerless, Layout::IpHeader, Layout::Ipv6Extension],
        };
        for case in malformed_corpus() {
            for &layout in layouts {
                let packet = wrap_ip(family, layout, &echo(family, &case.body));
                assert_reason(case.name, specialized(family, layout, &packet), case.reason);
                assert_reason(case.name, parse_packet_headers(&packet), case.reason);
            }
        }
    }
}

#[test]
fn every_headerless_echo_truncation_has_canonical_first_reason() {
    for family in [Family::V4, Family::V6] {
        let complete = echo(family, &[]);
        for end in 1..complete.len() {
            let packet = &complete[..end];
            assert_reason(
                "truncated Echo header specialized",
                specialized(family, Layout::Headerless, packet),
                IcmpMalformedReason::TruncatedEchoHeader,
            );
            assert_reason(
                "truncated Echo header generic",
                parse_packet_headers(packet),
                IcmpMalformedReason::TruncatedEchoHeader,
            );
        }
    }
}

#[test]
fn invalid_echo_code_precedes_shim_errors_but_unrelated_types_are_noise() {
    for family in [Family::V4, Family::V6] {
        let mut invalid_code = echo(family, &[0]);
        invalid_code[1] = 1;
        for parsed in [
            specialized(family, Layout::Headerless, &invalid_code),
            parse_packet_headers(&invalid_code),
        ] {
            assert_reason(
                "invalid Echo code",
                parsed,
                IcmpMalformedReason::InvalidEchoTypeOrCode,
            );
        }

        let mut unrelated = echo(family, &[0]);
        unrelated[0] = match family {
            Family::V4 => 3,
            Family::V6 => 1,
        };
        for parsed in [
            specialized(family, Layout::Headerless, &unrelated),
            parse_packet_headers(&unrelated),
        ] {
            assert_eq!(parsed.transport, ParsedTransport::Unsupported);
            assert_eq!(parsed.icmp_malformed_reason, None);
        }
    }
}

#[test]
fn empty_echo_body_is_cadence_in_every_applicable_kernel() {
    for family in [Family::V4, Family::V6] {
        let layouts: &[Layout] = match family {
            Family::V4 => &[Layout::Headerless, Layout::IpHeader],
            Family::V6 => &[Layout::Headerless, Layout::IpHeader, Layout::Ipv6Extension],
        };
        for &layout in layouts {
            let packet = wrap_ip(family, layout, &echo(family, &[]));
            for parsed in [
                specialized(family, layout, &packet),
                parse_packet_headers(&packet),
            ] {
                assert!(parsed.icmp.is_some());
                assert_eq!(parsed.payload_bounds.0, parsed.payload_bounds.1);
                assert_eq!(parsed.icmp_malformed_reason, None);
            }
        }
    }
}
