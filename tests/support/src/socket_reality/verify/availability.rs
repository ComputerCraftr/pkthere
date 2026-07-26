use super::implementation::verify_observation;
use super::model::{VerificationError, VerificationErrorKind, VerifiedReality};
use crate::socket_reality::evidence::{CallResult, RawReceiveEvidence, RealityEvidence};
use crate::socket_reality::requirement::RealityRequirement;
use pkthere_socket_policy::SocketCreationFailureClass;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CollectionAvailability {
    Executed,
    AuthoritativeUnsupported(SocketCreationFailureClass),
    Failed(SocketCreationFailureClass),
}

pub fn verify_requirement(
    requirement: RealityRequirement,
    evidence: &RealityEvidence,
) -> Result<VerifiedReality, VerificationError> {
    let case = requirement.case;
    let creation_policy = super::creation::production_creation_policy(case);
    let creation_error = primary_creation_error(evidence);
    let collection = match creation_error {
        Some(error) => match classify_creation_failure(error) {
            failure_class @ (SocketCreationFailureClass::UnsupportedCandidate
            | SocketCreationFailureClass::UnavailableInCurrentExecutionDomain) => {
                CollectionAvailability::AuthoritativeUnsupported(failure_class)
            }
            failure_class => CollectionAvailability::Failed(failure_class),
        },
        None => CollectionAvailability::Executed,
    };
    let fallback_accepts = match collection {
        CollectionAvailability::AuthoritativeUnsupported(failure_class) => {
            case.socket_create_spec() == creation_policy.primary
                && creation_policy.fallback.is_some_and(|fallback| {
                    fallback.from == creation_policy.primary && fallback.permits(failure_class)
                })
        }
        CollectionAvailability::Executed | CollectionAvailability::Failed(_) => false,
    };
    classify_availability(fallback_accepts, collection).map_err(|kind| VerificationError {
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
    })?;
    verify_observation(
        case,
        evidence,
        matches!(
            collection,
            CollectionAvailability::AuthoritativeUnsupported(_)
        )
        .then_some(creation_error)
        .flatten(),
    )
}

pub(super) fn classify_availability(
    production_fallback_accepts: bool,
    collection: CollectionAvailability,
) -> Result<(), VerificationErrorKind> {
    match (production_fallback_accepts, collection) {
        (_, CollectionAvailability::Executed)
        | (true, CollectionAvailability::AuthoritativeUnsupported(_)) => Ok(()),
        (false, CollectionAvailability::AuthoritativeUnsupported(_)) => {
            Err(VerificationErrorKind::RequiredButUnavailable)
        }
        (_, CollectionAvailability::Failed(_)) => Err(VerificationErrorKind::EvidenceMismatch),
    }
}

pub(super) fn classify_creation_failure(
    error: &crate::socket_reality::evidence::OsErrorEvidence,
) -> SocketCreationFailureClass {
    if unsupported_candidate(error) {
        return SocketCreationFailureClass::UnsupportedCandidate;
    }
    match error.kind {
        std::io::ErrorKind::PermissionDenied => SocketCreationFailureClass::PermissionDenied,
        std::io::ErrorKind::Interrupted => SocketCreationFailureClass::TransientInterrupted,
        std::io::ErrorKind::OutOfMemory => SocketCreationFailureClass::ResourceExhausted,
        std::io::ErrorKind::InvalidInput => SocketCreationFailureClass::InvalidSpecification,
        std::io::ErrorKind::Unsupported => {
            SocketCreationFailureClass::UnavailableInCurrentExecutionDomain
        }
        _ if resource_exhausted(error) => SocketCreationFailureClass::ResourceExhausted,
        _ => SocketCreationFailureClass::Unexpected,
    }
}

#[cfg(unix)]
fn unsupported_candidate(error: &crate::socket_reality::evidence::OsErrorEvidence) -> bool {
    matches!(
        error.raw_os_error,
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ESOCKTNOSUPPORT | libc::EPROTOTYPE)
    )
}

#[cfg(windows)]
fn unsupported_candidate(error: &crate::socket_reality::evidence::OsErrorEvidence) -> bool {
    use windows_sys::Win32::Networking::WinSock::{
        WSAEAFNOSUPPORT, WSAEPROTONOSUPPORT, WSAEPROTOTYPE, WSAESOCKTNOSUPPORT,
    };
    matches!(
        error.raw_os_error,
        Some(WSAEAFNOSUPPORT | WSAEPROTONOSUPPORT | WSAEPROTOTYPE | WSAESOCKTNOSUPPORT)
    )
}

#[cfg(not(any(unix, windows)))]
fn unsupported_candidate(_error: &crate::socket_reality::evidence::OsErrorEvidence) -> bool {
    false
}

#[cfg(unix)]
fn resource_exhausted(error: &crate::socket_reality::evidence::OsErrorEvidence) -> bool {
    matches!(
        error.raw_os_error,
        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS)
    )
}

#[cfg(windows)]
fn resource_exhausted(error: &crate::socket_reality::evidence::OsErrorEvidence) -> bool {
    use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
    matches!(error.raw_os_error, Some(WSAEMFILE | WSAENOBUFS))
}

#[cfg(not(any(unix, windows)))]
fn resource_exhausted(_error: &crate::socket_reality::evidence::OsErrorEvidence) -> bool {
    false
}

fn primary_creation_error(
    evidence: &RealityEvidence,
) -> Option<&crate::socket_reality::evidence::OsErrorEvidence> {
    if let RealityEvidence::SocketDisconnect(evidence) = evidence {
        return match &evidence.attempt {
            CallResult::Ok(_) => None,
            CallResult::OsError(error) => Some(error),
        };
    }
    let direct = match evidence {
        RealityEvidence::DatagramReceive(evidence) => Some(&evidence.direct),
        RealityEvidence::DatagramDisconnect(_) => None,
        RealityEvidence::SocketDisconnect(_) => None,
        RealityEvidence::ConnectedFilter(evidence) => Some(&evidence.direct),
        RealityEvidence::IcmpDgram(evidence) => Some(&evidence.direct),
        RealityEvidence::IcmpDgramSharedId(evidence) => Some(&evidence.direct),
        RealityEvidence::ReusePortFanout(_) | RealityEvidence::ListenerOwnerReplacement(_) => None,
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
