use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering as AtomOrdering};

use pkthere_socket_policy::{IcmpKernelIdPolicy, IcmpWildcardIdPolicy, ResolvedIcmpSocketPolicy};

static FALLBACK_ICMP_ID: AtomicU16 = AtomicU16::new(49152);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpIdSource {
    Requested,
    KernelReported,
    KernelDeferred,
    Generated,
    Collapsed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChosenIcmpIds {
    pub(crate) local_id: u16,
    pub(crate) remote_id: u16,
    pub(crate) local_source: IcmpIdSource,
    pub(crate) remote_source: IcmpIdSource,
    pub(crate) ignored_kernel_id: Option<u16>,
}

pub(crate) fn choose_upstream_icmp_ids(
    req_local_id: u16,
    req_remote_id: u16,
    reported_local_port: u16,
    policy: ResolvedIcmpSocketPolicy,
    debug_handles: bool,
) -> ChosenIcmpIds {
    let ignored_kernel_id = if matches!(
        policy.kernel_id_policy,
        IcmpKernelIdPolicy::IgnoreGetsocknameProtocol
    ) && reported_local_port != 0
    {
        Some(reported_local_port)
    } else {
        None
    };
    let trusted_kernel_id = match policy.kernel_id_policy {
        IcmpKernelIdPolicy::TrustedGetsockname | IcmpKernelIdPolicy::DeferredKernelAssigned => {
            reported_local_port
        }
        IcmpKernelIdPolicy::IgnoreGetsocknameProtocol => 0,
    };

    // Collapsed-ID sockets cannot represent independent local and remote ICMP
    // IDs. Only resolved policy is allowed to choose that path.
    if !policy.can_honor_disjoint_ids() {
        let (id, source) = if trusted_kernel_id != 0 {
            (trusted_kernel_id, IcmpIdSource::KernelReported)
        } else if req_remote_id == 0 && req_local_id == 0 {
            if matches!(
                policy.wildcard_id_policy,
                IcmpWildcardIdPolicy::UseKernelAssignedCollapsedId
            ) {
                log_debug!(
                    debug_handles,
                    "ICMP upstream wildcard DGRAM: deferring local/remote id selection to kernel-assigned ping socket id"
                );
                return ChosenIcmpIds {
                    local_id: 0,
                    remote_id: 0,
                    local_source: IcmpIdSource::KernelDeferred,
                    remote_source: IcmpIdSource::KernelDeferred,
                    ignored_kernel_id,
                };
            }
            let id = next_nonzero_icmp_id();
            log_debug!(
                debug_handles,
                "ICMP upstream wildcard no-disjoint mode: using collapsed id {} for local and remote",
                id
            );
            (id, IcmpIdSource::Generated)
        } else if req_local_id != 0 {
            (req_local_id, IcmpIdSource::Requested)
        } else if req_remote_id != 0 {
            (req_remote_id, IcmpIdSource::Collapsed)
        } else {
            (next_nonzero_icmp_id(), IcmpIdSource::Generated)
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
        return ChosenIcmpIds {
            local_id: id,
            remote_id: id,
            local_source: source,
            remote_source: if req_remote_id != 0 && req_remote_id == id {
                IcmpIdSource::Requested
            } else if source == IcmpIdSource::KernelReported {
                IcmpIdSource::KernelReported
            } else {
                IcmpIdSource::Collapsed
            },
            ignored_kernel_id,
        };
    }

    // Disjoint-capable sockets can respect independent ID requests.
    let (remote, remote_source) = if req_remote_id != 0 {
        (req_remote_id, IcmpIdSource::Requested)
    } else {
        (next_nonzero_icmp_id(), IcmpIdSource::Generated)
    };
    let (local, local_source) = if req_local_id != 0 {
        (req_local_id, IcmpIdSource::Requested)
    } else {
        (next_nonzero_icmp_id(), IcmpIdSource::Generated)
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
    } else {
        log_debug!(
            debug_handles,
            "ICMP upstream id fixed (RAW): requested local={}, requested remote={}, using provided IDs",
            req_local_id,
            req_remote_id
        );
    }

    ChosenIcmpIds {
        local_id: local,
        remote_id: remote,
        local_source,
        remote_source,
        ignored_kernel_id,
    }
}

#[cfg(test)]
mod tests {
    use super::choose_upstream_icmp_ids;
    use pkthere_socket_policy::{
        IcmpPolicyIntent, ResolvedIcmpSocketPolicy, SocketRole,
        resolve_icmp_socket_policy_with_intent,
    };
    use socket2::Type;

    fn raw_policy() -> ResolvedIcmpSocketPolicy {
        resolve_icmp_socket_policy_with_intent(
            SocketRole::Upstream,
            Type::RAW,
            IcmpPolicyIntent::default(),
        )
    }

    fn dgram_policy() -> ResolvedIcmpSocketPolicy {
        resolve_icmp_socket_policy_with_intent(
            SocketRole::Upstream,
            Type::DGRAM,
            IcmpPolicyIntent::default(),
        )
    }

    fn raw_collapsed_policy() -> ResolvedIcmpSocketPolicy {
        resolve_icmp_socket_policy_with_intent(
            SocketRole::Upstream,
            Type::RAW,
            IcmpPolicyIntent {
                disable_disjoint_ids: true,
                allow_debug_kernel_echo_self_handshake: false,
            },
        )
    }

    fn chosen_pair(decision: super::ChosenIcmpIds) -> (u16, u16) {
        (decision.local_id, decision.remote_id)
    }

    #[test]
    fn upstream_icmp_id_selection_follows_priority_order() {
        // 1. Kernel assigned (wins even over request) -> forces BOTH local and remote
        assert_eq!(
            chosen_pair(choose_upstream_icmp_ids(
                11,
                22,
                5678,
                dgram_policy(),
                false
            )),
            (5678, 5678)
        );
        assert_eq!(
            chosen_pair(choose_upstream_icmp_ids(0, 0, 5678, dgram_policy(), false)),
            (5678, 5678)
        );

        // 2. User requested (when kernel is 0) -> independent IDs respected only for RAW.
        // Collapsed policies use one effective fixed ID when they cannot wait
        // for a kernel-assigned wildcard ID.
        assert_eq!(
            chosen_pair(choose_upstream_icmp_ids(1111, 2222, 0, raw_policy(), false)),
            (1111, 2222)
        );
        assert_eq!(
            chosen_pair(choose_upstream_icmp_ids(
                1111,
                2222,
                0,
                raw_collapsed_policy(),
                false
            )),
            (1111, 1111)
        );

        // 3. Generated (when both are 0) -> local and remote are independent for RAW.
        let decision = choose_upstream_icmp_ids(0, 0, 0, raw_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_ne!(l, 0);
        assert_ne!(r, 0);
        assert_ne!(l, r);

        // Linux/Android DGRAM wildcard defers until getsockname reports the
        // kernel-assigned ping ID. Fixed collapsed policies generate now.
        let decision = choose_upstream_icmp_ids(0, 0, 0, dgram_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_eq!(l, r);
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert_eq!(l, 0);
        } else {
            assert_ne!(l, 0);
        }
    }

    #[test]
    fn dgram_wildcard_defers_until_kernel_reports_local_id() {
        let pre_kernel = chosen_pair(choose_upstream_icmp_ids(0, 0, 0, dgram_policy(), false));
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert_eq!(pre_kernel, (0, 0));
        } else {
            assert_ne!(pre_kernel.0, 0);
            assert_eq!(pre_kernel.0, pre_kernel.1);
        }
        assert_eq!(
            chosen_pair(choose_upstream_icmp_ids(0, 0, 5678, dgram_policy(), false)),
            (5678, 5678)
        );
    }

    #[test]
    fn raw_wildcard_generates_disjoint_capable_ids() {
        let decision = choose_upstream_icmp_ids(0, 0, 0, raw_policy(), false);
        let (local, remote) = chosen_pair(decision);
        assert_ne!(local, 0);
        assert_ne!(remote, 0);
        assert_ne!(local, remote);
    }

    #[test]
    fn raw_wildcard_ignores_reported_kernel_protocol_id_and_records_generation() {
        let decision = choose_upstream_icmp_ids(0, 0, 1, raw_policy(), false);
        assert_ne!(decision.local_id, 1);
        assert_ne!(decision.local_id, 0);
        assert_ne!(decision.remote_id, 0);
        assert_ne!(decision.local_id, decision.remote_id);
        assert_eq!(decision.local_source, super::IcmpIdSource::Generated);
        assert_eq!(decision.remote_source, super::IcmpIdSource::Generated);
        assert_eq!(decision.ignored_kernel_id, Some(1));

        let decision = choose_upstream_icmp_ids(0, 0, 58, raw_policy(), false);
        assert_ne!(decision.local_id, 58);
        assert_ne!(decision.remote_id, 58);
        assert_eq!(decision.ignored_kernel_id, Some(58));
    }

    #[test]
    fn raw_fixed_ids_ignore_reported_kernel_protocol_id_and_record_requests() {
        let decision = choose_upstream_icmp_ids(1111, 2222, 1, raw_policy(), false);
        assert_eq!(decision.local_id, 1111);
        assert_eq!(decision.remote_id, 2222);
        assert_eq!(decision.local_source, super::IcmpIdSource::Requested);
        assert_eq!(decision.remote_source, super::IcmpIdSource::Requested);
        assert_eq!(decision.ignored_kernel_id, Some(1));
    }

    #[test]
    fn forced_raw_wildcard_uses_collapsed_no_disjoint_ids() {
        let decision = choose_upstream_icmp_ids(0, 0, 0, raw_collapsed_policy(), false);
        let (local, remote) = chosen_pair(decision);
        assert_ne!(local, 0);
        assert_eq!(local, remote);
    }

    #[test]
    fn raw_fixed_remote_default_local_generates_distinct_local_id() {
        let decision = choose_upstream_icmp_ids(0, 1101, 0, raw_policy(), false);
        let (local, remote) = chosen_pair(decision);
        assert_ne!(local, 0);
        assert_eq!(remote, 1101);
        assert_ne!(local, remote);
    }

    #[test]
    fn raw_fixed_same_id_is_preserved_when_explicitly_requested() {
        assert_eq!(
            chosen_pair(choose_upstream_icmp_ids(1101, 1101, 0, raw_policy(), false)),
            (1101, 1101)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_untrusts_raw_socket_getsockname_id_1() {
        // requested 0, kernel reports 1, is_raw_socket true -> should UNTRUST 1 and allocate an ID
        let decision = choose_upstream_icmp_ids(0, 0, 1, raw_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_ne!(l, 1);
        assert_ne!(l, 0);
        assert_ne!(r, 0);
        assert_ne!(l, r);

        // requested 1, kernel reports 1, is_raw_socket true -> should STILL UNTRUST 1 if it's raw
        let decision = choose_upstream_icmp_ids(1, 1, 1, raw_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_eq!(l, 1);
        assert_eq!(l, r);

        // requested 0, kernel reports 1, is_raw_socket false (DGRAM) -> should TRUST 1
        let decision = choose_upstream_icmp_ids(0, 0, 1, dgram_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_eq!(l, 1);
        assert_eq!(l, r);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn linux_untrusts_raw_socket_getsockname_id_58() {
        // mirroring the protocol 1 (IPv4) test for protocol 58 (IPv6).
        // requested 0, kernel reports 58, is_raw_socket true -> should UNTRUST 58 and allocate an ID
        let decision = choose_upstream_icmp_ids(0, 0, 58, raw_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_ne!(l, 58);
        assert_ne!(l, 0);
        assert_ne!(r, 0);
        assert_ne!(l, r);

        // requested 58, kernel reports 58, is_raw_socket true -> should STILL UNTRUST 58 if it's raw
        let decision = choose_upstream_icmp_ids(58, 58, 58, raw_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_eq!(l, 58);
        assert_eq!(l, r);

        // requested 0, kernel reports 58, is_raw_socket false (DGRAM) -> should TRUST 58
        let decision = choose_upstream_icmp_ids(0, 0, 58, dgram_policy(), false);
        let (l, r) = chosen_pair(decision);
        assert_eq!(l, 58);
        assert_eq!(l, r);
    }
}
