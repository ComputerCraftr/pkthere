use crate::net::params::MAX_WIRE_PAYLOAD;
use socket2::Socket;

use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, SOCKET_ERROR, WSAEINTR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

#[inline]
pub(crate) fn as_uninit_mut(buf: &mut [u8]) -> &mut [std::mem::MaybeUninit<u8>] {
    unsafe {
        std::slice::from_raw_parts_mut(
            buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
            buf.len(),
        )
    }
}

#[cfg(unix)]
#[inline]
pub(crate) fn wait_socket_until_readable(sock: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pfd.revents & libc::POLLIN) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(windows)]
#[inline]
pub(crate) fn wait_socket_until_readable(sock: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = WSAPOLLFD {
            fd: sock.as_raw_socket() as usize,
            events: POLLRDNORM as i16,
            revents: 0,
        };
        let rc = unsafe { WSAPoll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pfd.revents & (POLLRDNORM as i16)) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = unsafe { WSAGetLastError() };
        if err == WSAEINTR {
            continue;
        }
        if rc == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(err));
        }
        return Err(io::Error::other("unexpected WSAPoll return value"));
    }
}

#[cfg(not(any(unix, windows)))]
#[inline]
pub(crate) fn wait_socket_until_readable(_sock: &Socket, _timeout: Duration) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket readiness waiting is not implemented on this platform",
    ))
}

#[repr(align(64))]
pub(crate) struct AlignedBuf {
    pub(crate) data: [u8; MAX_WIRE_PAYLOAD],
}

impl AlignedBuf {
    pub(crate) const fn new() -> Self {
        Self {
            data: [0u8; MAX_WIRE_PAYLOAD],
        }
    }
}
