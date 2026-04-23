pub mod checksum;
pub mod packet_headers;
mod protocol;

pub use protocol::SupportedProtocol;

pub const MAX_WIRE_PAYLOAD: usize = 65535;

#[inline(always)]
pub const fn be16_16(b0: u8, b1: u8) -> u16 {
    (b1 as u16) | ((b0 as u16) << 8)
}
