#[cfg(unix)]
pub(crate) const DEST_ADDR_REQUIRED: i32 = libc::EDESTADDRREQ;
#[cfg(windows)]
pub(crate) const DEST_ADDR_REQUIRED: i32 = 10039; // WSAEDESTADDRREQ
