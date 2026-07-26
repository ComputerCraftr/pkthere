use pkthere_socket_policy::{SocketCaptureAction, SocketCreationFailureClass};
use socket2::Socket;
use std::io;

pub(super) fn classify_socket_creation_error(error: &io::Error) -> SocketCreationFailureClass {
    if unsupported_candidate(error) {
        return SocketCreationFailureClass::UnsupportedCandidate;
    }
    match error.kind() {
        io::ErrorKind::PermissionDenied => SocketCreationFailureClass::PermissionDenied,
        io::ErrorKind::Interrupted => SocketCreationFailureClass::TransientInterrupted,
        io::ErrorKind::OutOfMemory => SocketCreationFailureClass::ResourceExhausted,
        io::ErrorKind::InvalidInput => SocketCreationFailureClass::InvalidSpecification,
        io::ErrorKind::Unsupported => {
            SocketCreationFailureClass::UnavailableInCurrentExecutionDomain
        }
        _ if resource_exhausted(error) => SocketCreationFailureClass::ResourceExhausted,
        _ => SocketCreationFailureClass::Unexpected,
    }
}

#[cfg(unix)]
fn unsupported_candidate(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ESOCKTNOSUPPORT | libc::EPROTOTYPE)
    )
}

#[cfg(windows)]
fn unsupported_candidate(error: &io::Error) -> bool {
    use windows_sys::Win32::Networking::WinSock::{
        WSAEAFNOSUPPORT, WSAEPROTONOSUPPORT, WSAEPROTOTYPE, WSAESOCKTNOSUPPORT,
    };
    matches!(
        error.raw_os_error(),
        Some(WSAEAFNOSUPPORT | WSAEPROTONOSUPPORT | WSAEPROTOTYPE | WSAESOCKTNOSUPPORT)
    )
}

#[cfg(not(any(unix, windows)))]
fn unsupported_candidate(_error: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn resource_exhausted(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS)
    )
}

#[cfg(windows)]
fn resource_exhausted(error: &io::Error) -> bool {
    use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
    matches!(error.raw_os_error(), Some(WSAEMFILE | WSAENOBUFS))
}

#[cfg(not(any(unix, windows)))]
fn resource_exhausted(_error: &io::Error) -> bool {
    false
}

#[cfg(unix)]
pub(super) fn enable_reuse_port(socket: &Socket) -> io::Result<()> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketConfigure);
    socket.set_reuse_port(true)
}

#[cfg(not(unix))]
pub(super) fn enable_reuse_port(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::other(
        "resolved SO_REUSEPORT policy contradicted the compiled socket backend",
    ))
}

#[cfg(windows)]
pub(super) fn apply_capture_action(socket: &Socket, action: SocketCaptureAction) -> io::Result<()> {
    match action {
        SocketCaptureAction::Disabled => Ok(()),
        SocketCaptureAction::WindowsReceiveAllIp => enable_windows_receive_all_ip(socket),
    }
}

#[cfg(not(windows))]
pub(super) fn apply_capture_action(
    _socket: &Socket,
    action: SocketCaptureAction,
) -> io::Result<()> {
    match action {
        SocketCaptureAction::Disabled => Ok(()),
        SocketCaptureAction::WindowsReceiveAllIp => Err(io::Error::other(
            "resolved Windows packet-capture policy contradicted the compiled socket backend",
        )),
    }
}

#[cfg(windows)]
fn enable_windows_receive_all_ip(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        RCVALL_IPLEVEL, SIO_RCVALL, WSAGetLastError, WSAIoctl,
    };

    let mut bytes_returned = 0;
    let option = RCVALL_IPLEVEL as u32;
    let result = {
        let _operation =
            crate::authority::audited_operation(crate::authority::OperationId::SocketCaptureEnable);
        // SAFETY: the socket handle is live for this synchronous call; the
        // input option and output-length pointers remain valid throughout it.
        unsafe {
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
        }
    };
    if result == 0 {
        Ok(())
    } else {
        // SAFETY: WSAGetLastError has no pointer preconditions and is queried
        // immediately on the thread where WSAIoctl failed.
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}
