use super::ParsedPacketHeaders;
use std::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredPacketExtent {
    pub packet: Range<usize>,
    pub transport: Range<usize>,
    pub payload: Range<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4PacketLengthEncoding {
    NetworkTotal,
    DarwinHostPayload,
}

impl ParsedPacketHeaders {
    pub fn declared_extent(self, bytes: &[u8]) -> Option<DeclaredPacketExtent> {
        let packet = checked_range(self.packet_bounds, bytes.len())?;
        let transport = checked_range(self.transport_bounds, packet.end)?;
        let payload = checked_range(self.payload_bounds, transport.end)?;
        (transport.start >= packet.start
            && payload.start >= transport.start
            && payload.end == transport.end)
            .then_some(DeclaredPacketExtent {
                packet,
                transport,
                payload,
            })
    }

    pub fn declared_extent_with_ipv4_length(
        self,
        bytes: &[u8],
        _ipv4_length: Ipv4PacketLengthEncoding,
    ) -> Option<DeclaredPacketExtent> {
        self.declared_extent(bytes)
    }
}

fn checked_range(bounds: (usize, usize), limit: usize) -> Option<Range<usize>> {
    let (start, end) = bounds;
    (start <= end && end <= limit).then_some(start..end)
}
