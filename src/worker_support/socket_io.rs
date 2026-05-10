use socket2::{SockAddr, Socket};

use std::io;
use std::mem::MaybeUninit;
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
pub(crate) fn recv_packet(
    sock: &Socket,
    connected: bool,
    buf: &mut [MaybeUninit<u8>],
) -> io::Result<(usize, Option<SockAddr>)> {
    if connected {
        return sock.recv(buf).map(|len| (len, None));
    }

    sock.recv_from(buf).map(|(len, src_sa)| (len, Some(src_sa)))
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
            events: POLLRDNORM,
            revents: 0,
        };
        let rc = unsafe { WSAPoll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pfd.revents & POLLRDNORM) != 0);
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

#[cfg(test)]
mod tests {
    use super::recv_packet;
    use crate::recv_buf::RecvBuf;
    use socket2::Socket;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

    #[test]
    fn recv_buf_initialized_exposes_only_requested_length() {
        let mut buf = RecvBuf::<4>::new();
        let recv = buf.recv_buf_mut();
        recv[0].write(b'a');
        recv[1].write(b'b');
        recv[2].write(b'c');
        recv[3].write(b'd');
        assert_eq!(buf.initialized(2), b"ab");
        assert_eq!(buf.initialized(4), b"abcd");
    }

    #[test]
    fn unconnected_recv_returns_source_socket_addr() {
        let recv_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44444));
        let recv = UdpSocket::bind(recv_addr).expect("bind recv socket");
        let sender = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            55555,
        )))
        .expect("bind sender");
        sender.send_to(b"x", recv_addr).expect("send packet");

        let recv = Socket::from(recv);
        let mut buf = RecvBuf::<8>::new();
        let (len, source) = recv_packet(&recv, false, buf.recv_buf_mut()).expect("recv packet");
        assert_eq!(len, 1);
        let source = source.unwrap().as_socket().expect("source as socket");
        assert_eq!(source, sender.local_addr().expect("sender local"));
    }
}
