use super::implementation::verify;
use super::model::{VerificationError, VerificationErrorKind, VerifiedReality};
use crate::socket_reality::case::{ICMP_DGRAM_FIXED_ID, RealityOperation};
use crate::socket_reality::evidence::{CallResult, RawReceiveEvidence, RealityEvidence};
use crate::socket_reality::requirement::RealityRequirement;
use pkthere_socket_policy::upstream_socket_creation_policy;
use pkthere_wire::SupportedProtocol;
use socket2::Type;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CollectionAvailability {
    Executed,
    AuthoritativeUnsupported,
}

pub fn verify_requirement(
    requirement: RealityRequirement,
    evidence: &RealityEvidence,
) -> Result<VerifiedReality, VerificationError> {
    let case = requirement.case;
    let (remote_id, local_id) = match case.operation {
        RealityOperation::IcmpDgramFixedId => (ICMP_DGRAM_FIXED_ID, ICMP_DGRAM_FIXED_ID),
        _ => (0, 0),
    };
    let policy_declares_available = case.protocol != SupportedProtocol::ICMP
        || case.socket_type != Type::DGRAM
        || upstream_socket_creation_policy(case.protocol, case.domain, remote_id, local_id, false)
            .primary
            .socket_type
            == Type::DGRAM;
    let collection = if primary_creation_error(evidence).is_some() {
        CollectionAvailability::AuthoritativeUnsupported
    } else {
        CollectionAvailability::Executed
    };
    classify_availability(requirement.required, policy_declares_available, collection).map_err(
        |kind| VerificationError {
            kind,
            message: primary_creation_error(evidence).map_or_else(
                || format!("availability contradiction for {case:?}"),
                |os_error| {
                    format!(
                        "socket creation for {:?} failed with OS evidence: {}",
                        case, os_error.message
                    )
                },
            ),
        },
    )?;
    verify(case, evidence)
}

pub(super) fn classify_availability(
    required: bool,
    policy_available: bool,
    collection: CollectionAvailability,
) -> Result<(), VerificationErrorKind> {
    if required && !policy_available {
        return Err(VerificationErrorKind::PolicyCapabilityContradiction);
    }
    match (required, collection) {
        (_, CollectionAvailability::Executed) => Ok(()),
        (true, CollectionAvailability::AuthoritativeUnsupported) => {
            Err(VerificationErrorKind::RequiredButUnavailable)
        }
        (false, CollectionAvailability::AuthoritativeUnsupported) => {
            Err(VerificationErrorKind::UnsupportedByRuntime)
        }
    }
}

fn primary_creation_error(
    evidence: &RealityEvidence,
) -> Option<&crate::socket_reality::evidence::OsErrorEvidence> {
    let direct = match evidence {
        RealityEvidence::DatagramReceive(evidence) => Some(&evidence.direct),
        RealityEvidence::ConnectedFilter(evidence) => Some(&evidence.direct),
        RealityEvidence::IcmpDgram(evidence) => Some(&evidence.direct),
        RealityEvidence::ReusePortFanout(_) => None,
        RealityEvidence::RawReceive(RawReceiveEvidence::Direct { direct, .. }) => Some(direct),
        RealityEvidence::RawReceive(RawReceiveEvidence::ProductionForwarder(_))
        | RealityEvidence::RawFourId(_)
        | RealityEvidence::Lifecycle(_) => None,
    }?;
    direct
        .sockets
        .first()
        .and_then(|socket| match &socket.create.result {
            CallResult::Ok(()) => None,
            CallResult::OsError(error) => Some(error),
        })
}
