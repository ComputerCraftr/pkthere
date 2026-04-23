use super::implementation::error;
use super::model::{DerivedFacts, VerificationError};
use crate::socket_reality::evidence::ReusePortFanoutEvidence;
use pkthere_socket_policy::{
    ListenerWorkerDistribution, SocketCreationPath, listener_socket_setup_policy,
    listener_worker_socket_policy,
};

pub(super) fn verify_reuse_port_fanout(
    evidence: &ReusePortFanoutEvidence,
) -> Result<DerivedFacts, VerificationError> {
    if let Some(error_message) = &evidence.error {
        return Err(error(format!(
            "reuse-port probe failed after {} successful binds: {error_message}",
            evidence.successful_bind_count
        )));
    }
    if evidence.successful_bind_count != evidence.receiver_count {
        return Err(error(format!(
            "reuse-port probe bound {} of {} receiver sockets",
            evidence.successful_bind_count, evidence.receiver_count
        )));
    }
    let received = evidence.received_flow_counts.iter().sum::<usize>();
    if received != evidence.sent_flow_count {
        return Err(error(format!(
            "reuse-port probe received {received} of {} flows",
            evidence.sent_flow_count
        )));
    }
    let policy = listener_worker_socket_policy(evidence.receiver_count, true);
    let setup = listener_socket_setup_policy(policy, SocketCreationPath::Datagram);
    if setup.worker != policy || !setup.bind_requested_address {
        return Err(error(
            "listener setup policy does not preserve worker reuse and bind decisions",
        ));
    }
    if evidence.receiver_count > 1 && !setup.worker.reuse_address {
        return Err(error(
            "multi-worker listener policy omitted the address-reuse prerequisite",
        ));
    }
    let kernel_flow_affinity_required =
        policy.distribution == ListenerWorkerDistribution::KernelFlowAffinity;
    if kernel_flow_affinity_required && evidence.received_flow_counts.contains(&0) {
        return Err(error(format!(
            "kernel reuse-port flow affinity left a receiver idle: {:?}",
            evidence.received_flow_counts
        )));
    }
    if kernel_flow_affinity_required != policy.supports_requested_distribution() {
        return Err(error(
            "listener worker policy support does not match kernel-flow-affinity mode",
        ));
    }
    Ok(DerivedFacts::ReusePortFanout {
        receiver_count: evidence.receiver_count,
        received_flow_counts: evidence.received_flow_counts.clone(),
        kernel_flow_affinity_required,
    })
}
