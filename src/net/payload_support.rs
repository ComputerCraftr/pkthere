#[cfg(unix)]
pub(crate) const DEST_ADDR_REQUIRED: i32 = libc::EDESTADDRREQ;
#[cfg(windows)]
pub(crate) const DEST_ADDR_REQUIRED: i32 = 10039; // WSAEDESTADDRREQ

pub(crate) const ICMP_SHIM_IS_DATA: u8 = 0x80;
pub(crate) const ICMP_SHIM_HAS_PAYLOAD: u8 = 0x40;
pub(crate) const ICMP_SHIM_HAS_SOURCE_ID: u8 = 0x20;
pub(crate) const ICMP_SHIM_ALLOWED_BITS: u8 =
    ICMP_SHIM_IS_DATA | ICMP_SHIM_HAS_PAYLOAD | ICMP_SHIM_HAS_SOURCE_ID;
