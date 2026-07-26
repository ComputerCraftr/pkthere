use super::{direct, direct_icmp, forwarder};
use crate::raw_icmp::acquire_raw_icmp_lock;
use crate::socket_reality::case::RealityOperation;
use crate::socket_reality::evidence::{RawReceiveEvidence, RealityEvidence};
use crate::socket_reality::requirement::{CollectionAuthority, RealityRequirement};
use crate::timing::RAW_ICMP_LOCK_WAIT;
use std::io;
use std::time::Instant;

pub fn route_probe_bind_before_connect_required(domain: socket2::Domain) -> io::Result<bool> {
    direct::route_probe_bind_before_connect_required(domain)
}

pub fn independent_disconnect(socket: &socket2::Socket, domain: socket2::Domain) -> io::Result<()> {
    super::disconnect_platform::disconnect(socket, domain)
}

pub fn configure_protocol_zero_capture(socket: &socket2::Socket) -> io::Result<()> {
    super::disconnect_platform::configure_protocol_zero_capture(socket)
}

pub fn collect(requirement: RealityRequirement) -> io::Result<RealityEvidence> {
    let case = requirement.case;
    validate_collection_authority(case.operation, requirement.collection_authority)?;
    let _raw_icmp_guard = (matches!(
        case.operation,
        RealityOperation::RawReceiveEvidence | RealityOperation::RawFourIdForwarding
    ) || (case.operation == RealityOperation::SocketDisconnect
        && case.socket_type == socket2::Type::RAW))
        .then(|| {
            acquire_raw_icmp_lock(
                Instant::now() + RAW_ICMP_LOCK_WAIT,
                "socket_reality_raw_collection",
            )
            .map_err(io::Error::other)
        })
        .transpose()?;

    match case.operation {
        RealityOperation::DatagramReceiveEvidence => {
            direct::collect_udp_datagram(&case).map(RealityEvidence::DatagramReceive)
        }
        RealityOperation::DatagramDisconnect => {
            direct::collect_udp_disconnect(&case).map(RealityEvidence::DatagramDisconnect)
        }
        RealityOperation::SocketDisconnect => {
            direct::collect_socket_disconnect(&case).map(RealityEvidence::SocketDisconnect)
        }
        RealityOperation::ConnectedPeerFiltering => {
            direct::collect_udp_connected_filter(&case).map(RealityEvidence::ConnectedFilter)
        }
        RealityOperation::IcmpDgramReceiveId | RealityOperation::IcmpDgramFixedId => {
            direct_icmp::collect_icmp_dgram(&case).map(RealityEvidence::IcmpDgram)
        }
        RealityOperation::IcmpDgramSharedId => {
            super::icmp_dgram_shared::collect(&case).map(RealityEvidence::IcmpDgramSharedId)
        }
        RealityOperation::ReusePortFanout => {
            direct_icmp::collect_reuse_port_fanout(&case).map(RealityEvidence::ReusePortFanout)
        }
        RealityOperation::ListenerOwnerReplacement => {
            direct_icmp::collect_listener_owner_replacement(&case)
                .map(RealityEvidence::ListenerOwnerReplacement)
        }
        RealityOperation::RawReceiveEvidence => {
            let direct = direct_icmp::collect_raw_receive(&case)?;
            let evidence = match &direct {
                RawReceiveEvidence::Direct { direct, socket, .. }
                    if direct
                        .socket(*socket)
                        .is_some_and(|socket| !socket.create.result.is_ok())
                        && requirement.collection_authority
                            == CollectionAuthority::DirectSocketOrPreparedPrivilegedForwarder =>
                {
                    RawReceiveEvidence::ProductionForwarder(forwarder::collect_raw_four_id(
                        &crate::socket_reality::case::RealityCase {
                            operation: RealityOperation::RawFourIdForwarding,
                            ..case
                        },
                    )?)
                }
                _ => direct,
            };
            Ok(RealityEvidence::RawReceive(evidence))
        }
        RealityOperation::RawFourIdForwarding => {
            forwarder::collect_raw_four_id(&case).map(RealityEvidence::RawFourId)
        }
        RealityOperation::UpstreamReconnect
        | RealityOperation::ListenerRelock
        | RealityOperation::ListenerRebind => {
            forwarder::collect_lifecycle(&case).map(RealityEvidence::Lifecycle)
        }
    }
}

pub(super) fn validate_collection_authority(
    operation: RealityOperation,
    authority: CollectionAuthority,
) -> io::Result<()> {
    let valid = match operation {
        RealityOperation::RawReceiveEvidence => matches!(
            authority,
            CollectionAuthority::DirectSocket
                | CollectionAuthority::DirectSocketOrPreparedPrivilegedForwarder
        ),
        RealityOperation::SocketDisconnect => authority == CollectionAuthority::DirectSocket,
        RealityOperation::RawFourIdForwarding
        | RealityOperation::UpstreamReconnect
        | RealityOperation::ListenerRelock
        | RealityOperation::ListenerRebind => authority == CollectionAuthority::PreparedForwarder,
        _ => authority == CollectionAuthority::DirectSocket,
    };
    if valid {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation:?} cannot use collection authority {authority:?}"
        )))
    }
}
