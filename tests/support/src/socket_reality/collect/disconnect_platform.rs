//! Independent socket-reality implementation of the platform disconnect call.
//!
//! This module intentionally does not call the production managed-socket
//! backend. Reality evidence must be able to contradict committed production
//! policy. Keeping this as one test-support authority also prevents individual
//! probes from growing bespoke disconnect implementations.

use socket2::Domain;
use socket2::Socket;
use std::io;

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(windows)]
use socket2::SockAddr;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(unix)]
pub(super) fn disconnect(socket: &impl AsRawFd, _domain: Domain) -> io::Result<()> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    let address = libc::sockaddr {
        sa_len: std::mem::size_of::<libc::sockaddr>() as u8,
        sa_family: libc::AF_UNSPEC as libc::sa_family_t,
        sa_data: [0; 14],
    };
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    let address = libc::sockaddr {
        sa_family: libc::AF_UNSPEC as libc::sa_family_t,
        sa_data: [0; 14],
    };
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            &address as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
        )
    };
    match result {
        0 => Ok(()),
        _ => {
            // Capture errno before any evidence bookkeeping can issue another
            // system call and overwrite the independent observation.
            let observed_error = io::Error::last_os_error();
            Err(observed_error)
        }
    }
}

#[cfg(windows)]
pub(super) fn disconnect(socket: &impl AsRawSocket, domain: Domain) -> io::Result<()> {
    let unspecified = match domain {
        Domain::IPV6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    let address = SockAddr::from(unspecified);
    let result = unsafe {
        windows_sys::Win32::Networking::WinSock::connect(
            socket.as_raw_socket() as _,
            address.as_ptr().cast(),
            address.len(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let code = unsafe { windows_sys::Win32::Networking::WinSock::WSAGetLastError() };
        Err(io::Error::from_raw_os_error(code))
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn disconnect<T>(_socket: &T, _domain: Domain) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "independent datagram disconnect probe is unavailable",
    ))
}

#[cfg(windows)]
pub(super) fn configure_protocol_zero_capture(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        RCVALL_IPLEVEL, SIO_RCVALL, WSAGetLastError, WSAIoctl,
    };

    let mut bytes_returned = 0;
    let option = RCVALL_IPLEVEL as u32;
    // SAFETY: this synchronous call borrows a live socket. The input option
    // and output-length storage remain valid for the complete WSAIoctl call.
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as _,
            SIO_RCVALL,
            &option as *const _ as _,
            std::mem::size_of_val(&option) as _,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        // SAFETY: WSAGetLastError has no pointer preconditions and is read on
        // the same thread immediately after WSAIoctl reports failure.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    socket.set_header_included_v4(true)
}

#[cfg(not(windows))]
pub(super) fn configure_protocol_zero_capture(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SIO_RCVALL protocol-zero capture is available only on Windows",
    ))
}
