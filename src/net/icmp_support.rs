#[cfg(not(miri))]
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering as AtomOrdering};

use pkthere_socket_policy::{IcmpWildcardIdPolicy, ResolvedIcmpSocketPolicy};

static FALLBACK_ICMP_ID: crate::authority::AuthorityAtomic<
    crate::authority::tags::IdentityAllocation,
    AtomicU16,
> = crate::authority::AuthorityAtomic::new_u16(
    49152,
    crate::authority::AtomicProtocolId::IdentityGeneration,
);

fn next_nonzero_icmp_id() -> u16 {
    #[cfg(not(miri))]
    {
        let socket = {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketBind);
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        };
        if let Ok(sock) = socket {
            let local = {
                let _operation = crate::authority::audited_operation(
                    crate::authority::OperationId::SocketLocalInspection,
                );
                sock.local_addr()
            };
            if let Ok(addr) = local {
                let id = addr.port();
                if id != 0 {
                    return id;
                }
            }
        }
    }

    // Independent fallback ID allocator: no peer or socket metadata is
    // published through this counter, and zero is explicitly skipped.
    match FALLBACK_ICMP_ID.try_update(AtomOrdering::AcqRel, AtomOrdering::Acquire, |id| {
        id.checked_add(1)
    }) {
        Ok(id) if id != 0 => id,
        Ok(_) | Err(_) => crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "fallback ICMP identifier allocator exhausted"
        )),
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
) -> ChosenIcmpIds {
    let trusted_kernel_id = policy
        .trusted_kernel_local_id(reported_local_port)
        .unwrap_or(0);
    let ignored_kernel_id =
        (reported_local_port != 0 && trusted_kernel_id == 0).then_some(reported_local_port);

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
                return ChosenIcmpIds {
                    local_id: 0,
                    remote_id: 0,
                    local_source: IcmpIdSource::KernelDeferred,
                    remote_source: IcmpIdSource::KernelDeferred,
                    ignored_kernel_id,
                };
            }
            let id = next_nonzero_icmp_id();
            (id, IcmpIdSource::Generated)
        } else if req_local_id != 0 {
            (req_local_id, IcmpIdSource::Requested)
        } else if req_remote_id != 0 {
            (req_remote_id, IcmpIdSource::Collapsed)
        } else {
            (next_nonzero_icmp_id(), IcmpIdSource::Generated)
        };

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

    ChosenIcmpIds {
        local_id: local,
        remote_id: remote,
        local_source,
        remote_source,
        ignored_kernel_id,
    }
}

#[cfg(test)]
mod tests;
