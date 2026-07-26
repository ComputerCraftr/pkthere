use super::PacketDisposition;

pub(super) fn reservation_io_error(
    operation: &'static str,
    error: crate::net::sock_mgr::transaction_lock::ReservationError,
) -> std::io::Error {
    match error.class() {
        crate::runtime_support::FailureClass::RetryableContention
        | crate::runtime_support::FailureClass::Shutdown
        | crate::runtime_support::FailureClass::OperationFailed
        | crate::runtime_support::FailureClass::PacketRejected => {}
        crate::runtime_support::FailureClass::FatalInvariant => {
            crate::runtime_support::publish_process_fatal(format_args!("{operation}: {error}"));
        }
    }
    std::io::Error::other(format!("{operation}: {error}"))
}

pub(super) fn flow_authority_io_error(
    operation: &'static str,
    error: crate::flow_state::FlowAuthorityError,
) -> std::io::Error {
    if error.class().is_fatal() {
        crate::runtime_support::publish_process_fatal(format_args!("{operation}: {error}"));
    }
    std::io::Error::other(format!("{operation}: {error}"))
}

pub(super) fn flow_mutation_io_error<E: std::fmt::Debug>(
    operation: &'static str,
    error: crate::flow_state::FlowMutationError<E>,
) -> std::io::Error {
    match error {
        crate::flow_state::FlowMutationError::Operation(error) => {
            std::io::Error::other(format!("{operation}: {error:?}"))
        }
        crate::flow_state::FlowMutationError::Authority(error) => {
            if error.class().is_fatal() {
                crate::runtime_support::publish_process_fatal(format_args!("{operation}: {error}"));
            }
            std::io::Error::other(format!("{operation}: {error}"))
        }
    }
}

#[inline]
pub(super) fn record_sequence_rejection(
    stats: &mut dyn crate::stats::StatsSink,
    c2u: bool,
    error: &std::io::Error,
) -> PacketDisposition {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        stats.icmp_abuse_budget_drop(c2u);
        return PacketDisposition::DropRateLimited;
    }
    match crate::net::icmp_sequence::sequence_admission_error(error) {
        Some(
            crate::net::icmp_sequence::SequenceAdmissionError::InactiveSession
            | crate::net::icmp_sequence::SequenceAdmissionError::WrongSession,
        ) => {
            stats.stale_session_drop(c2u);
            PacketDisposition::DropSyncInvalid
        }
        Some(crate::net::icmp_sequence::SequenceAdmissionError::Duplicate) => {
            stats.replay_drop(c2u);
            PacketDisposition::DropDuplicate
        }
        Some(
            crate::net::icmp_sequence::SequenceAdmissionError::FutureSync
            | crate::net::icmp_sequence::SequenceAdmissionError::StaleSync
            | crate::net::icmp_sequence::SequenceAdmissionError::StaleReplay,
        )
        | None => {
            stats.replay_drop(c2u);
            PacketDisposition::DropSyncInvalid
        }
    }
}
