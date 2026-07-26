use super::model::{VerificationError, VerificationErrorKind};
use crate::socket_reality::case::{RealityCase, RealityOperation};
use pkthere_socket_policy::SocketRole;
use pkthere_wire::SupportedProtocol;
use socket2::{Domain, Type};

pub(super) fn require_case_contract(case: RealityCase) -> Result<(), VerificationError> {
    let valid = match case.operation {
        RealityOperation::DatagramReceiveEvidence => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && case.connection_scenario.direct_connected() == Some(false)
        }
        RealityOperation::DatagramDisconnect => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Upstream
                && case.connection_scenario.direct_connected() == Some(true)
        }
        RealityOperation::SocketDisconnect => {
            case.connection_scenario.direct_connected() == Some(true)
                && ((case.protocol == SupportedProtocol::ICMP && case.socket_type == Type::RAW)
                    || (case.policy_role == SocketRole::Upstream
                        && ((case.protocol == SupportedProtocol::ICMP
                            && case.socket_type == Type::DGRAM)
                            || (case.protocol == SupportedProtocol::UDP
                                && case.socket_type == Type::DGRAM))))
        }
        RealityOperation::ConnectedPeerFiltering => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.connection_scenario.direct_connected() == Some(true)
        }
        RealityOperation::IcmpDgramReceiveId
        | RealityOperation::IcmpDgramFixedId
        | RealityOperation::IcmpDgramSharedId => {
            case.protocol == SupportedProtocol::ICMP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Upstream
                && case.connection_scenario.direct_connected() == Some(true)
        }
        RealityOperation::ReusePortFanout | RealityOperation::ListenerOwnerReplacement => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && case.connection_scenario.direct_connected() == Some(false)
        }
        RealityOperation::RawReceiveEvidence => {
            case.protocol == SupportedProtocol::ICMP
                && case.socket_type == Type::RAW
                && case.connection_scenario.direct_connected() == Some(false)
        }
        RealityOperation::RawFourIdForwarding => {
            case.domain == Domain::IPV4
                && case.protocol == SupportedProtocol::ICMP
                && case.socket_type == Type::RAW
                && case.policy_role == SocketRole::Upstream
                && case.connection_scenario.direct_connected() == Some(false)
        }
        RealityOperation::UpstreamReconnect => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Upstream
                && case.target_domain.is_some()
        }
        RealityOperation::ListenerRelock => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && case.target_domain == Some(case.domain)
        }
        RealityOperation::ListenerRebind => {
            case.protocol == SupportedProtocol::UDP
                && case.socket_type == Type::DGRAM
                && case.policy_role == SocketRole::Listener
                && case.connection_scenario.direct_connected() == Some(false)
                && case.target_domain.is_some()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(VerificationError {
            kind: VerificationErrorKind::EvidenceMismatch,
            message: format!("requested case has an invalid dimension combination: {case:?}"),
        })
    }
}
