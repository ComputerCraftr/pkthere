use crate::{DRAIN_WAIT_MS, ForwarderSession, MatrixCase, snapshot_forwarder_output_tail};
use std::net::{SocketAddr, UdpSocket};

#[derive(Clone, Copy, Debug)]
pub(crate) enum UnconnectedWrongPeerRole {
    ClientSide,
    UpstreamSide,
}

pub(crate) fn panic_with_session_context(context: &str, session: &ForwarderSession) -> ! {
    let (stdout, stderr) = snapshot_forwarder_output_tail(session, 20)
        .unwrap_or_else(|_| (String::new(), String::new()));
    let mut details = String::new();
    if !stdout.trim().is_empty() {
        details.push_str("\nrecent stdout tail:\n");
        details.push_str(&stdout);
    }
    if !stderr.trim().is_empty() {
        details.push_str("\nrecent stderr tail:\n");
        details.push_str(&stderr);
    }
    panic!("{context}{details}");
}

pub(crate) fn routable_loopback_for_wildcard_bind(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        ),
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            addr.port(),
        ),
        _ => addr,
    }
}

pub(crate) fn describe_unconnected_wrong_peer_case(
    role: UnconnectedWrongPeerRole,
    case: MatrixCase,
) -> String {
    let role = match role {
        UnconnectedWrongPeerRole::ClientSide => "client",
        UnconnectedWrongPeerRole::UpstreamSide => "upstream",
    };
    format!(
        "role={role} family={:?} proto={} client_connection={:?} upstream_connection={:?}",
        case.family, case.proto, case.client_connection, case.upstream_connection
    )
}

pub(crate) fn uses_kernel_echo_debug(case: MatrixCase) -> bool {
    case.proto == pkthere_wire::SupportedProtocol::ICMP
}

pub(crate) fn assert_only_retry_duplicates_remain(
    client: &UdpSocket,
    allowed_duplicate: &[u8],
    buffer: &mut [u8],
    case_desc: &str,
    session: &ForwarderSession,
) {
    let deadline = std::time::Instant::now() + DRAIN_WAIT_MS;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        client
            .set_read_timeout(Some(remaining))
            .unwrap_or_else(|error| panic!("{case_desc}: set duplicate-drain timeout: {error}"));
        match client.recv(buffer) {
            Ok(length) if &buffer[..length] == allowed_duplicate => {}
            Ok(length) => panic_with_session_context(
                &format!(
                    "{case_desc}: stray packet produced unexpected client-visible payload {:?}",
                    &buffer[..length]
                ),
                session,
            ),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                return;
            }
            Err(error) => panic_with_session_context(
                &format!(
                    "{case_desc}: unexpected receive error while draining legitimate retry duplicates: {error}"
                ),
                session,
            ),
        }
    }
}
