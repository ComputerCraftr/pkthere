use crate::SupportedProtocol;
use crate::packet_headers::{
    IpMalformedReason, IpUnsupportedReason, IpVersion, Ipv4PacketLengthEncoding,
    NetworkParseOutcome, ParsedNetworkHeader, ParsedNetworkLayer, ReceiveHeaderMode,
    select_receive_parser,
};
use std::net::{IpAddr, Ipv6Addr};

fn header(bytes: &[u8], packet_end: usize, protocol: u8, offset: usize) -> ParsedNetworkHeader {
    let mut source = [0_u8; 16];
    let mut destination = [0_u8; 16];
    source.copy_from_slice(&bytes[8..24]);
    destination.copy_from_slice(&bytes[24..40]);
    ParsedNetworkHeader {
        version: IpVersion::V6,
        source: IpAddr::V6(Ipv6Addr::from(source)),
        destination: IpAddr::V6(Ipv6Addr::from(destination)),
        ipv6_flow_label: Some(
            ((u32::from(bytes[0]) & 0x0f) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]),
        ),
        protocol,
        packet_end,
        transport_offset: offset,
    }
}

fn scalar_ipv6_network_oracle(bytes: &[u8]) -> ParsedNetworkLayer {
    if bytes.is_empty() {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::MissingHeader);
    }
    match bytes[0] >> 4 {
        6 => {}
        4 => {
            return ParsedNetworkLayer::UnexpectedVersion {
                expected: IpVersion::V6,
                observed: Some(IpVersion::V4),
            };
        }
        observed_nibble => {
            return ParsedNetworkLayer::Malformed(IpMalformedReason::InvalidVersion {
                observed_nibble,
            });
        }
    }
    if bytes.len() < 40 {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedHeader);
    }
    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let next_header = bytes[6];
    if payload_len == 0 {
        return ParsedNetworkLayer::Unsupported {
            header: header(bytes, 40, next_header, 40),
            reason: IpUnsupportedReason::Jumbogram,
        };
    }
    let packet_end = 40 + payload_len;
    if packet_end > bytes.len() {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::CaptureTruncated);
    }
    let direct = header(bytes, packet_end, next_header, 40);
    match next_header {
        51 => {
            return ParsedNetworkLayer::Unsupported {
                header: direct,
                reason: IpUnsupportedReason::AuthenticationHeader,
            };
        }
        50 => {
            return ParsedNetworkLayer::Unsupported {
                header: direct,
                reason: IpUnsupportedReason::EncryptedPayload,
            };
        }
        44 => {
            return ParsedNetworkLayer::Unsupported {
                header: direct,
                reason: IpUnsupportedReason::Fragmented,
            };
        }
        _ => {}
    }
    if !matches!(next_header, 0 | 43 | 60) {
        return ParsedNetworkLayer::Valid(direct);
    }
    if packet_end < 48 {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedExtension);
    }
    let following = bytes[40];
    let extension_len = (usize::from(bytes[41]) + 1) * 8;
    let transport_offset = 40 + extension_len;
    if transport_offset > packet_end {
        return ParsedNetworkLayer::Malformed(IpMalformedReason::TruncatedExtension);
    }
    let extended = header(bytes, packet_end, following, transport_offset);
    if next_header == 43 && bytes[43] != 0 {
        return ParsedNetworkLayer::Unsupported {
            header: extended,
            reason: IpUnsupportedReason::RoutingHeaderWithSegments,
        };
    }
    let reason = match following {
        44 => Some(IpUnsupportedReason::Fragmented),
        0 | 43 | 60 => Some(IpUnsupportedReason::ExtensionChain),
        51 => Some(IpUnsupportedReason::AuthenticationHeader),
        50 => Some(IpUnsupportedReason::EncryptedPayload),
        _ => None,
    };
    match reason {
        Some(reason) => ParsedNetworkLayer::Unsupported {
            header: extended,
            reason,
        },
        None => ParsedNetworkLayer::Valid(extended),
    }
}

fn production_layer(outcome: NetworkParseOutcome) -> ParsedNetworkLayer {
    match outcome {
        NetworkParseOutcome::Valid(packet) => ParsedNetworkLayer::Valid(packet.header),
        NetworkParseOutcome::Rejected(layer) => layer,
        NetworkParseOutcome::NotPresent => panic!("IPv6 header parser must classify layer three"),
    }
}

#[test]
fn production_ipv6_kernel_matches_independent_scalar_oracle() {
    let parser = select_receive_parser(
        SupportedProtocol::ICMP,
        IpVersion::V6,
        ReceiveHeaderMode::IpHeaderIncluded,
        Ipv4PacketLengthEncoding::NetworkTotal,
    )
    .expect("production IPv6 parser");
    let mut state = 0x9e37_79b9_u32;
    for length in 0..=120 {
        for sample in 0..96 {
            let mut packet = vec![0_u8; length];
            for byte in &mut packet {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
            if length >= 40 && sample % 3 != 0 {
                packet[0] = 0x60 | (packet[0] & 0x0f);
                let declared = sample % (length - 39);
                packet[4..6].copy_from_slice(
                    &u16::try_from(declared)
                        .expect("bounded differential payload")
                        .to_be_bytes(),
                );
                if sample % 4 == 0 {
                    packet[6] = [0, 43, 60, 44, 50, 51, 58, 59][sample % 8];
                }
            }
            assert_eq!(
                production_layer(parser.parse_network(&packet)),
                scalar_ipv6_network_oracle(&packet),
                "scalar mismatch for capture length {length}, sample {sample}: {packet:02x?}"
            );
        }
    }
}
