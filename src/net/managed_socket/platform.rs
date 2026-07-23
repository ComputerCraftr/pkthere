#[cfg(windows)]
use socket2::SockAddr;
use socket2::Socket;
use std::io;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, SOCKET_ERROR, WSAEINTR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

#[cfg(unix)]
pub(super) fn wait_until_readable(socket: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            return Ok((descriptor.revents & libc::POLLIN) != 0);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(windows)]
pub(super) fn wait_until_readable(socket: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = WSAPOLLFD {
            fd: socket.as_raw_socket() as usize,
            events: POLLRDNORM,
            revents: 0,
        };
        let result = unsafe { WSAPoll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            return Ok((descriptor.revents & POLLRDNORM) != 0);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = unsafe { WSAGetLastError() };
        if error == WSAEINTR {
            continue;
        }
        if result == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(error));
        }
        return Err(io::Error::other("unexpected WSAPoll return value"));
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn wait_until_readable(_socket: &Socket, _timeout: Duration) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket readiness waiting is not implemented on this platform",
    ))
}

/// Disconnect-before-reconnect is a pkthere portability invariant.
#[cfg(unix)]
pub(super) fn disconnect(socket: &Socket) -> io::Result<()> {
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
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    if error.raw_os_error() == Some(libc::EAFNOSUPPORT) {
        return Ok(());
    }
    Err(error)
}

#[cfg(windows)]
pub(super) fn disconnect(socket: &Socket) -> io::Result<()> {
    let unspecified = match socket.local_addr()?.as_socket() {
        Some(SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    socket.connect(&SockAddr::from(unspecified))
}

#[cfg(all(not(unix), not(windows)))]
pub(super) fn disconnect(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed socket disconnect is not supported on this platform",
    ))
}
