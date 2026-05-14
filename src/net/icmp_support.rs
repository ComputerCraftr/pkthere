use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering as AtomOrdering};

use crate::cli::SupportedProtocol;

static FALLBACK_ICMP_ID: AtomicU16 = AtomicU16::new(49152);

#[inline]
pub(crate) fn listener_requires_raw(proto: SupportedProtocol) -> bool {
    proto == SupportedProtocol::ICMP
}

#[inline]
pub(crate) fn upstream_requires_raw(
    proto: SupportedProtocol,
    requested_remote_id: u16,
    requested_local_id: u16,
) -> bool {
    if proto != SupportedProtocol::ICMP {
        false
    } else if requested_remote_id != 0
        && requested_local_id != 0
        && requested_remote_id != requested_local_id
    {
        true
    } else if requested_remote_id == 0 {
        // Dynamic ID: only OSes that completely lack DGRAM ping sockets need RAW.
        cfg!(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos"
        )))
    } else {
        // Specific ID: macOS supports binding fixed IDs to DGRAM ping sockets.
        // Linux/Android ignore requested bind IDs on DGRAM; most others lack DGRAM entirely.
        !cfg!(target_os = "macos")
    }
}

fn next_nonzero_icmp_id() -> u16 {
    if let Ok(sock) = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        && let Ok(addr) = sock.local_addr()
    {
        let id = addr.port();
        if id != 0 {
            return id;
        }
    }

    loop {
        let id = FALLBACK_ICMP_ID.fetch_add(1, AtomOrdering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

pub(crate) fn choose_upstream_icmp_ids(
    req_local_id: u16,
    req_remote_id: u16,
    reported_local_port: u16,
    reuse_remote_id: bool,
    is_raw_socket: bool,
    debug_handles: bool,
) -> (u16, u16) {
    // Linux/Android raw sockets for IPPROTO_ICMP often return 1 (the protocol number)
    // from getsockname. We must ignore this as it's not a valid ICMP identity, but
    // only when we know we are using a raw socket on those platforms.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let untrustworthy = is_raw_socket;

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let untrustworthy = false;

    let trustworthy_local_port = if untrustworthy {
        0
    } else {
        reported_local_port
    };

    // For DGRAM sockets, the kernel-assigned port (ID) MUST match both local and remote.
    // If the kernel didn't assign one (or we couldn't trust it), we still force them
    // to match to satisfy DGRAM socket requirements.
    if !is_raw_socket {
        let id = if trustworthy_local_port != 0 {
            trustworthy_local_port
        } else if req_remote_id != 0 {
            req_remote_id
        } else if req_local_id != 0 {
            req_local_id
        } else {
            next_nonzero_icmp_id()
        };

        if (req_local_id != 0 && req_local_id != id) || (req_remote_id != 0 && req_remote_id != id)
        {
            log_debug!(
                debug_handles,
                "ICMP upstream id override (DGRAM): requested local {} and remote {} but using {}, using identical id for both",
                req_local_id,
                req_remote_id,
                id
            );
        }
        return (id, id);
    }

    // For RAW sockets, we can respect independent ID requests.
    let remote = if req_remote_id != 0 {
        req_remote_id
    } else {
        next_nonzero_icmp_id()
    };
    let local = if reuse_remote_id {
        remote
    } else if req_local_id != 0 {
        req_local_id
    } else {
        next_nonzero_icmp_id()
    };

    if req_local_id == 0 || req_remote_id == 0 {
        log_debug!(
            debug_handles,
            "ICMP upstream id fallback (RAW): requested local={}, requested remote={}, using generated id {} for local, {} for remote",
            req_local_id,
            req_remote_id,
            local,
            remote
        );
    }

    (local, remote)
}

#[cfg(test)]
mod tests {
    use super::{choose_upstream_icmp_ids, listener_requires_raw, upstream_requires_raw};
    use crate::cli::SupportedProtocol::ICMP;

    #[test]
    fn upstream_effective_icmp_id_never_returns_zero_for_dynamic_assignment() {
        assert_ne!(choose_upstream_icmp_ids(0, 0, 0, false, false, false).0, 0);
    }

    #[test]
    fn generated_icmp_ids_come_from_nonzero_ephemeral_allocation() {
        let (id, _) = choose_upstream_icmp_ids(0, 0, 0, false, false, false);
        assert_ne!(id, 0);
    }

    #[test]
    fn upstream_icmp_id_selection_follows_priority_order() {
        // 1. Kernel assigned (wins even over request) -> forces BOTH local and remote
        assert_eq!(
            choose_upstream_icmp_ids(11, 22, 5678, false, false, false),
            (5678, 5678)
        );
        assert_eq!(
            choose_upstream_icmp_ids(0, 0, 5678, false, false, false),
            (5678, 5678)
        );

        // 2. User requested (when kernel is 0) -> independent IDs respected only for RAW
        assert_eq!(
            choose_upstream_icmp_ids(1111, 2222, 0, false, true, false),
            (1111, 2222)
        );
        assert_eq!(
            choose_upstream_icmp_ids(1111, 2222, 0, false, false, false),
            (2222, 2222)
        );

        // 3. Generated (when both are 0) -> local and remote are generated
        // For RAW, if reuse_remote_id is true, they should match.
        let (l, r) = choose_upstream_icmp_ids(0, 0, 0, true, true, false);
        assert_ne!(l, 0);
        assert_eq!(l, r);

        // For DGRAM, they always match regardless of reuse_remote_id.
        let (l, r) = choose_upstream_icmp_ids(0, 0, 0, false, false, false);
        assert_ne!(l, 0);
        assert_eq!(l, r);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_untrusts_raw_socket_getsockname_id_1() {
        // requested 0, kernel reports 1, is_raw_socket true -> should UNTRUST 1 and allocate an ID
        let (l, r) = choose_upstream_icmp_ids(0, 0, 1, true, true, false);
        assert_ne!(l, 1);
        assert_ne!(l, 0);
        assert_eq!(l, r);

        // requested 1, kernel reports 1, is_raw_socket true -> should STILL UNTRUST 1 if it's raw
        let (l, r) = choose_upstream_icmp_ids(1, 1, 1, true, true, false);
        assert_eq!(l, 1);
        assert_eq!(l, r);

        // requested 0, kernel reports 1, is_raw_socket false (DGRAM) -> should TRUST 1
        let (l, r) = choose_upstream_icmp_ids(0, 0, 1, true, false, false);
        assert_eq!(l, 1);
        assert_eq!(l, r);
    }

    #[test]
    fn icmp_datagram_path_is_reserved_for_upstream_role() {
        assert!(listener_requires_raw(ICMP));

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        assert!(!upstream_requires_raw(ICMP, 0, 0));

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        assert!(upstream_requires_raw(ICMP, 0, 0));

        #[cfg(target_os = "macos")]
        assert!(!upstream_requires_raw(ICMP, 1234, 0));

        #[cfg(not(target_os = "macos"))]
        assert!(upstream_requires_raw(ICMP, 1234, 0));

        assert!(upstream_requires_raw(ICMP, 1001, 2002));

        #[cfg(target_os = "macos")]
        assert!(!upstream_requires_raw(ICMP, 1001, 1001));
    }
}
