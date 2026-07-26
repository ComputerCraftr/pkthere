use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpMalformedReason {
    MissingHeader,
    InvalidVersion { observed_nibble: u8 },
    TruncatedHeader,
    InvalidHeaderLength,
    InvalidPacketLength,
    CaptureTruncated,
    ReservedIpv4Flag,
    TruncatedExtension,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpUnsupportedReason {
    Fragmented,
    ExtensionChain,
    RoutingHeaderWithSegments,
    AuthenticationHeader,
    EncryptedPayload,
    Jumbogram,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedNetworkHeader {
    pub version: IpVersion,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub ipv6_flow_label: Option<u32>,
    pub protocol: u8,
    pub packet_end: usize,
    pub transport_offset: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParsedNetworkLayer {
    NotPresent,
    Valid(ParsedNetworkHeader),
    Malformed(IpMalformedReason),
    UnexpectedVersion {
        expected: IpVersion,
        observed: Option<IpVersion>,
    },
    Unsupported {
        header: ParsedNetworkHeader,
        reason: IpUnsupportedReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedNetworkPacket {
    pub header: ParsedNetworkHeader,
    pub(crate) expected_transport: bool,
    pub(crate) request_type: u8,
    pub(crate) reply_type: u8,
    pub(crate) captured_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkParseOutcome {
    NotPresent,
    Valid(ValidatedNetworkPacket),
    Rejected(ParsedNetworkLayer),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParsedTransport {
    NotParsed,
    UdpDatagram,
    Icmp,
    Udp,
    UnrelatedProtocol,
    UnrelatedIcmp,
    MalformedIcmp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IcmpMalformedReason {
    TruncatedEchoHeader,
    InvalidEchoTypeOrCode,
    InvalidShimFlags,
    TruncatedSourceId,
    IllegalFrameFlags,
    SessionControlReplyIdLength,
    InvalidSessionControlFlags,
    InvalidSessionControlDirection,
    MissingSessionId,
    ZeroSessionId,
    ZeroSourceId,
    ZeroReplyId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireIcmpIdentity {
    pub source_id: Option<u16>,
    pub destination_id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedIcmpEcho {
    pub identity: WireIcmpIdentity,
    pub session_id: u64,
    pub seq: u16,
    pub is_req: bool,
    pub shim_flags: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedUdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPacketHeaders {
    pub network: ParsedNetworkLayer,
    pub transport: ParsedTransport,
    pub udp: Option<ParsedUdpHeader>,
    pub icmp: Option<ParsedIcmpEcho>,
    pub packet_bounds: (usize, usize),
    pub transport_bounds: (usize, usize),
    pub payload_bounds: (usize, usize),
    pub icmp_malformed_reason: Option<IcmpMalformedReason>,
}

impl ParsedPacketHeaders {
    #[inline]
    pub const fn network_only(network: ParsedNetworkLayer) -> Self {
        Self {
            network,
            transport: ParsedTransport::NotParsed,
            udp: None,
            icmp: None,
            packet_bounds: (0, 0),
            transport_bounds: (0, 0),
            payload_bounds: (0, 0),
            icmp_malformed_reason: None,
        }
    }

    #[inline]
    pub const fn source_ip(self) -> Option<IpAddr> {
        match self.network {
            ParsedNetworkLayer::Valid(header) | ParsedNetworkLayer::Unsupported { header, .. } => {
                Some(header.source)
            }
            _ => None,
        }
    }

    #[inline]
    pub const fn destination_ip(self) -> Option<IpAddr> {
        match self.network {
            ParsedNetworkLayer::Valid(header) | ParsedNetworkLayer::Unsupported { header, .. } => {
                Some(header.destination)
            }
            _ => None,
        }
    }
}
