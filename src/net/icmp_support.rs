use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

static EFFECTIVE_ICMP_ID_RNG_STATE: AtomicU64 = AtomicU64::new(0);

#[inline]
pub(crate) const fn listener_requires_raw_icmp() -> bool {
    true
}

#[inline]
pub(crate) const fn upstream_requires_raw_icmp(requested_id: u16) -> bool {
    if requested_id == 0 {
        // Dynamic ID: only OSes that completely lack DGRAM ping sockets need RAW.
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        return true;

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        return false;
    } else {
        // Specific ID: macOS supports binding fixed IDs to DGRAM ping sockets.
        #[cfg(target_os = "macos")]
        return false;

        // Linux/Android ignore requested bind IDs on DGRAM, while others lack DGRAM entirely.
        #[cfg(not(target_os = "macos"))]
        return true;
    }
}

fn next_nonzero_icmp_id() -> u16 {
    fn initial_seed() -> u64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let pid = u64::from(std::process::id());
        let seed = nanos ^ pid.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15u64;
        if seed == 0 {
            0xA5A5_5A5A_D3C1_B4E7
        } else {
            seed
        }
    }

    let mut state = EFFECTIVE_ICMP_ID_RNG_STATE.load(AtomOrdering::Relaxed);
    if state == 0 {
        let seed = initial_seed();
        match EFFECTIVE_ICMP_ID_RNG_STATE.compare_exchange(
            0,
            seed,
            AtomOrdering::Relaxed,
            AtomOrdering::Relaxed,
        ) {
            Ok(_) => state = seed,
            Err(existing) => state = existing,
        }
    }

    loop {
        let mut next = state;
        next ^= next >> 12;
        next ^= next << 25;
        next ^= next >> 27;
        next = next.wrapping_mul(0x2545_F491_4F6C_DD1D);
        if next == 0 {
            next = initial_seed();
        }
        match EFFECTIVE_ICMP_ID_RNG_STATE.compare_exchange(
            state,
            next,
            AtomOrdering::Relaxed,
            AtomOrdering::Relaxed,
        ) {
            Ok(_) => {
                let id = next as u16;
                if id != 0 {
                    return id;
                }
                state = next;
            }
            Err(observed) => state = observed,
        }
    }
}

pub(crate) fn choose_upstream_icmp_ids(
    req_local_id: u16,
    req_remote_id: u16,
    reported_local_port: u16,
    reuse_remote_id: bool,
    is_raw_socket: bool,
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
                cfg!(test),
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
            cfg!(test),
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
    use super::{choose_upstream_icmp_ids, listener_requires_raw_icmp, upstream_requires_raw_icmp};

    #[test]
    fn upstream_effective_icmp_id_never_returns_zero_for_dynamic_assignment() {
        assert_ne!(choose_upstream_icmp_ids(0, 0, 0, false, false).0, 0);
    }

    #[test]
    fn generated_icmp_ids_are_not_structurally_forced_odd() {
        let mut saw_even = false;
        for _ in 0..256 {
            let (id, _) = choose_upstream_icmp_ids(0, 0, 0, false, false);
            assert_ne!(id, 0);
            if id % 2 == 0 {
                saw_even = true;
                break;
            }
        }
        assert!(saw_even);
    }

    #[test]
    fn upstream_icmp_id_selection_follows_priority_order() {
        // 1. Kernel assigned (wins even over request) -> forces BOTH local and remote
        assert_eq!(
            choose_upstream_icmp_ids(11, 22, 5678, false, false),
            (5678, 5678)
        );
        assert_eq!(
            choose_upstream_icmp_ids(0, 0, 5678, false, false),
            (5678, 5678)
        );

        // 2. User requested (when kernel is 0) -> independent IDs respected only for RAW
        assert_eq!(
            choose_upstream_icmp_ids(1111, 2222, 0, false, true),
            (1111, 2222)
        );
        assert_eq!(
            choose_upstream_icmp_ids(1111, 2222, 0, false, false),
            (2222, 2222)
        );

        // 3. Generated (when both are 0) -> local and remote are generated
        // For RAW, if reuse_remote_id is true, they should match.
        let (l, r) = choose_upstream_icmp_ids(0, 0, 0, true, true);
        assert_ne!(l, 0);
        assert_eq!(l, r);

        // For DGRAM, they always match regardless of reuse_remote_id.
        let (l, r) = choose_upstream_icmp_ids(0, 0, 0, false, false);
        assert_ne!(l, 0);
        assert_eq!(l, r);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_untrusts_raw_socket_getsockname_id_1() {
        // requested 0, kernel reports 1, is_raw_socket true -> should UNTRUST 1 and generate random
        let (l, r) = choose_upstream_icmp_ids(0, 0, 1, true, true);
        assert_ne!(l, 1);
        assert_ne!(l, 0);
        assert_eq!(l, r);

        // requested 1, kernel reports 1, is_raw_socket true -> should STILL UNTRUST 1 if it's raw
        let (l, r) = choose_upstream_icmp_ids(1, 1, 1, true, true);
        assert_eq!(l, 1);
        assert_eq!(l, r);

        // requested 0, kernel reports 1, is_raw_socket false (DGRAM) -> should TRUST 1
        let (l, r) = choose_upstream_icmp_ids(0, 0, 1, true, false);
        assert_eq!(l, 1);
        assert_eq!(l, r);
    }

    #[test]
    fn icmp_datagram_path_is_reserved_for_upstream_role() {
        assert!(listener_requires_raw_icmp());

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        assert!(!upstream_requires_raw_icmp(0));

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        assert!(upstream_requires_raw_icmp(0));

        #[cfg(target_os = "macos")]
        assert!(!upstream_requires_raw_icmp(1234));

        #[cfg(not(target_os = "macos"))]
        assert!(upstream_requires_raw_icmp(1234));
    }
}
