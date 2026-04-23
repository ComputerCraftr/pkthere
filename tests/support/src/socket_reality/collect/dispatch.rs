use super::{direct, forwarder};
use crate::raw_icmp::acquire_raw_icmp_lock;
use crate::socket_reality::case::{RealityCase, RealityOperation};
use crate::socket_reality::evidence::{RawReceiveEvidence, RealityEvidence};
use crate::timing::RAW_ICMP_LOCK_WAIT;
use std::io;
use std::time::Instant;

pub fn collect(case: &RealityCase) -> io::Result<RealityEvidence> {
    let _raw_icmp_guard = matches!(
        case.operation,
        RealityOperation::RawReceiveEvidence | RealityOperation::RawFourIdForwarding
    )
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
            direct::collect_udp_datagram(case).map(RealityEvidence::DatagramReceive)
        }
        RealityOperation::ConnectedPeerFiltering => {
            direct::collect_udp_connected_filter(case).map(RealityEvidence::ConnectedFilter)
        }
        RealityOperation::IcmpDgramReceiveId | RealityOperation::IcmpDgramFixedId => {
            direct::collect_icmp_dgram(case).map(RealityEvidence::IcmpDgram)
        }
        RealityOperation::ReusePortFanout => {
            direct::collect_reuse_port_fanout(case).map(RealityEvidence::ReusePortFanout)
        }
        RealityOperation::RawReceiveEvidence => {
            let direct = direct::collect_raw_receive(case)?;
            let evidence = match &direct {
                RawReceiveEvidence::Direct { direct, socket, .. }
                    if direct
                        .socket(*socket)
                        .is_some_and(|socket| !socket.create.result.is_ok())
                        && case.domain == socket2::Domain::IPV4
                        && !(cfg!(windows)
                            && case.socket_path
                                == crate::socket_reality::case::RealitySocketPath::RawIcmp) =>
                {
                    RawReceiveEvidence::ProductionForwarder(forwarder::collect_raw_four_id(
                        &RealityCase {
                            operation: RealityOperation::RawFourIdForwarding,
                            ..*case
                        },
                    )?)
                }
                _ => direct,
            };
            Ok(RealityEvidence::RawReceive(evidence))
        }
        RealityOperation::RawFourIdForwarding => {
            forwarder::collect_raw_four_id(case).map(RealityEvidence::RawFourId)
        }
        RealityOperation::UpstreamReconnect
        | RealityOperation::ListenerRelock
        | RealityOperation::ListenerRebind => {
            forwarder::collect_lifecycle(case).map(RealityEvidence::Lifecycle)
        }
    }
}
