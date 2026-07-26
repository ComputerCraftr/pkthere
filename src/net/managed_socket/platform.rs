#[cfg(windows)]
use socket2::SockAddr;
use socket2::Socket;
use std::io;
use std::net::UdpSocket;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, SOCKET_ERROR, WSAEINTR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

const NANOS_PER_MILLISECOND: u32 = 1_000_000;

fn poll_timeout_millis(timeout: Duration) -> i32 {
    let rounded_up = timeout.as_millis().saturating_add(u128::from(
        !timeout.subsec_nanos().is_multiple_of(NANOS_PER_MILLISECOND),
    ));
    rounded_up.min(i32::MAX as u128) as i32
}

#[cfg(unix)]
pub(super) fn wait_until_readable_or_wake(
    socket: &Socket,
    wake: &UdpSocket,
    timeout: Duration,
) -> io::Result<(bool, bool)> {
    let _operation = crate::authority::audited_operation(crate::authority::OperationId::Poll);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "poll deadline overflow"))?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok((false, false));
        }
        let timeout_ms = poll_timeout_millis(remaining);
        let mut descriptors = [
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both pollfd entries contain live descriptors borrowed for
        // this bounded call, and the mutable array remains valid for `nfds`.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout_ms,
            )
        };
        if result >= 0 {
            return Ok((
                descriptors[0].revents & libc::POLLIN != 0,
                descriptors[1].revents & libc::POLLIN != 0,
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(windows)]
pub(super) fn wait_until_readable_or_wake(
    socket: &Socket,
    wake: &UdpSocket,
    timeout: Duration,
) -> io::Result<(bool, bool)> {
    let _operation = crate::authority::audited_operation(crate::authority::OperationId::Poll);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "poll deadline overflow"))?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok((false, false));
        }
        let timeout_ms = poll_timeout_millis(remaining);
        let mut descriptors = [
            WSAPOLLFD {
                fd: socket.as_raw_socket() as usize,
                events: POLLRDNORM,
                revents: 0,
            },
            WSAPOLLFD {
                fd: wake.as_raw_socket() as usize,
                events: POLLRDNORM,
                revents: 0,
            },
        ];
        // SAFETY: the two WSAPOLLFD entries contain live borrowed sockets and
        // the mutable array remains valid for the synchronous WSAPoll call.
        let result = unsafe { WSAPoll(descriptors.as_mut_ptr(), 2, timeout_ms) };
        if result >= 0 {
            return Ok((
                descriptors[0].revents & POLLRDNORM != 0,
                descriptors[1].revents & POLLRDNORM != 0,
            ));
        }
        // SAFETY: WSAGetLastError has no pointer preconditions and is queried
        // immediately on the thread where WSAPoll failed.
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
pub(super) fn wait_until_readable_or_wake(
    _socket: &Socket,
    _wake: &UdpSocket,
    _timeout: Duration,
) -> io::Result<(bool, bool)> {
    let _operation = crate::authority::audited_operation(crate::authority::OperationId::Poll);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket readiness waiting with a maintenance wake is not implemented on this platform",
    ))
}

/// Disconnect-before-reconnect is a pkthere portability invariant.
#[cfg(unix)]
pub(super) fn disconnect(socket: &Socket) -> io::Result<()> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketDisconnect);
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
    // SAFETY: `address` is a fully initialized AF_UNSPEC sockaddr and both
    // pointer and length remain valid for the duration of connect.
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            &address as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
pub(super) fn disconnect(socket: &Socket) -> io::Result<()> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketDisconnect);
    let unspecified = match {
        let _inspection = crate::authority::audited_operation(
            crate::authority::OperationId::SocketLocalInspection,
        );
        socket.local_addr()?
    }
    .as_socket()
    {
        Some(SocketAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    socket.connect(&SockAddr::from(unspecified))
}

#[cfg(all(not(unix), not(windows)))]
pub(super) fn disconnect(_socket: &Socket) -> io::Result<()> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketDisconnect);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "managed socket disconnect is not supported on this platform",
    ))
}
