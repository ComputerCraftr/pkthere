use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

static EFFECTIVE_ICMP_ID_RNG_STATE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpLocalIdSource {
    KernelAssigned,
    Requested,
    Generated,
}

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

pub(crate) fn choose_effective_local_icmp_id(
    requested_id: u16,
    actual_local_port: u16,
    _is_raw_socket: bool,
    for_upstream: bool,
) -> (u16, IcmpLocalIdSource) {
    // Linux/Android raw sockets for IPPROTO_ICMP often return 1 (the protocol number)
    // from getsockname. We must ignore this as it's not a valid ICMP identity, but
    // only when we know we are using a raw socket on those platforms.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let untrustworthy = _is_raw_socket;

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let untrustworthy = false;

    let trustworthy_local_port = if untrustworthy { 0 } else { actual_local_port };
    if trustworthy_local_port != 0 {
        if requested_id != 0 && requested_id != trustworthy_local_port {
            log_debug!(
                cfg!(test),
                "ICMP {} id override: requested {} but kernel assigned {}, using kernel id",
                if for_upstream { "upstream" } else { "listener" },
                requested_id,
                trustworthy_local_port
            );
        }
        return (trustworthy_local_port, IcmpLocalIdSource::KernelAssigned);
    }

    if requested_id != 0 {
        return (requested_id, IcmpLocalIdSource::Requested);
    }

    let generated = next_nonzero_icmp_id();
    log_debug!(
        cfg!(test),
        "ICMP {} id fallback: requested={}, kernel=0, using generated id {}",
        if for_upstream { "upstream" } else { "listener" },
        requested_id,
        generated
    );
    (generated, IcmpLocalIdSource::Generated)
}

#[cfg(test)]
mod tests {
    use super::{
        IcmpLocalIdSource, choose_effective_local_icmp_id, listener_requires_raw_icmp,
        upstream_requires_raw_icmp,
    };

    #[test]
    fn effective_local_icmp_id_never_returns_zero_for_dynamic_assignment() {
        assert_ne!(choose_effective_local_icmp_id(0, 0, false, false).0, 0);
    }

    #[test]
    fn generated_icmp_ids_are_not_structurally_forced_odd() {
        let mut saw_even = false;
        for _ in 0..256 {
            let (id, source) = choose_effective_local_icmp_id(0, 0, false, false);
            assert_ne!(id, 0);
            if source == IcmpLocalIdSource::Generated && id % 2 == 0 {
                saw_even = true;
                break;
            }
        }
        assert!(saw_even);
    }

    #[test]
    fn effective_local_icmp_id_follows_priority_order() {
        // 1. Kernel assigned (wins even over request)
        assert_eq!(
            choose_effective_local_icmp_id(1234, 5678, false, false),
            (5678, IcmpLocalIdSource::KernelAssigned)
        );
        assert_eq!(
            choose_effective_local_icmp_id(0, 5678, false, false),
            (5678, IcmpLocalIdSource::KernelAssigned)
        );

        // 2. User requested (when kernel is 0)
        assert_eq!(
            choose_effective_local_icmp_id(1234, 0, false, false),
            (1234, IcmpLocalIdSource::Requested)
        );

        // 3. Generated (when both are 0)
        let (id, source) = choose_effective_local_icmp_id(0, 0, false, false);
        assert_ne!(id, 0);
        assert_eq!(source, IcmpLocalIdSource::Generated);
    }

    #[test]
    fn listener_effective_local_icmp_id_follows_priority_order() {
        assert_eq!(
            choose_effective_local_icmp_id(3001, 4001, false, false),
            (4001, IcmpLocalIdSource::KernelAssigned)
        );
        assert_eq!(
            choose_effective_local_icmp_id(3001, 0, false, false),
            (3001, IcmpLocalIdSource::Requested)
        );
        let (generated, source) = choose_effective_local_icmp_id(0, 0, false, false);
        assert_ne!(generated, 0);
        assert_eq!(source, IcmpLocalIdSource::Generated);
    }

    #[test]
    fn upstream_effective_local_icmp_id_follows_priority_order() {
        assert_eq!(
            choose_effective_local_icmp_id(3002, 4002, false, true),
            (4002, IcmpLocalIdSource::KernelAssigned)
        );
        assert_eq!(
            choose_effective_local_icmp_id(3002, 0, false, true),
            (3002, IcmpLocalIdSource::Requested)
        );
        let (generated, source) = choose_effective_local_icmp_id(0, 0, false, true);
        assert_ne!(generated, 0);
        assert_eq!(source, IcmpLocalIdSource::Generated);
    }

    #[test]
    fn dynamic_upstream_and_wildcard_listener_share_same_fallback_ordering() {
        let listener = choose_effective_local_icmp_id(0, 0, false, false);
        let upstream = choose_effective_local_icmp_id(0, 0, false, true);
        assert_eq!(listener.1, IcmpLocalIdSource::Generated);
        assert_eq!(upstream.1, IcmpLocalIdSource::Generated);
        assert_ne!(listener.0, 0);
        assert_ne!(upstream.0, 0);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_untrusts_raw_socket_getsockname_id_1() {
        // requested 0, kernel reports 1, is_raw_socket true -> should UNTRUST 1 and generate random
        let (id, source) = choose_effective_local_icmp_id(0, 1, true, false);
        assert_ne!(id, 1);
        assert_ne!(id, 0);
        assert_eq!(source, IcmpLocalIdSource::Generated);

        // requested 1, kernel reports 1, is_raw_socket true -> should TRUST 1 (requested matches kernel)
        let (id, source) = choose_effective_local_icmp_id(1, 1, true, false);
        assert_eq!(id, 1);
        assert_eq!(source, IcmpLocalIdSource::Requested);

        // requested 0, kernel reports 1, is_raw_socket false (DGRAM) -> should TRUST 1
        let (id, source) = choose_effective_local_icmp_id(0, 1, false, false);
        assert_eq!(id, 1);
        assert_eq!(source, IcmpLocalIdSource::KernelAssigned);
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
