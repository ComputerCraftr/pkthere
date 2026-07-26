use super::rollback_after_topology_update_failure;
use crate::cli::SupportedProtocol;
use crate::flow_state::{FlowRuntimeState, ReplyIdHandshakeAck};
use crate::net::payload::{BufferedPayload, PayloadEvent};
use crate::runtime_support::ShutdownController;
use crate::stats::Stats;

fn committing_handshake(
    flow_state: &FlowRuntimeState,
    instance: u64,
) -> crate::flow_state::ReplyIdHandshakeCommitToken {
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"owned-once");
    flow_state.begin_upstream_reply_id_handshake(
        2002,
        instance,
        1,
        BufferedPayload::from_event(&event, None),
    );
    let lease = flow_state
        .lease_due_upstream_reply_id_negotiation(std::time::Instant::now())
        .expect("negotiation lease");
    flow_state
        .record_upstream_negotiation_sequence(&lease, 0)
        .expect("record negotiation");
    flow_state.complete_upstream_reply_id_negotiation_send(
        lease,
        0,
        true,
        std::time::Instant::now(),
    );
    let ReplyIdHandshakeAck::Matched { token, .. } =
        flow_state.ack_upstream_reply_id_handshake(2002, instance, 0, None)
    else {
        panic!("ACK must enter committing state");
    };
    token
}

#[test]
fn successful_topology_failure_rollback_remains_retryable_without_fatal_exit() {
    let flow_state = FlowRuntimeState::new();
    let token = committing_handshake(&flow_state, 72);
    let stats = Stats::with_worker_shards(1);
    let mut recorder = stats.recorder(0);
    let exit = ShutdownController::new(1).expect("shutdown controller");

    assert!(matches!(
        rollback_after_topology_update_failure(
            &flow_state,
            &mut recorder,
            exit.as_ref(),
            token,
            &"injected manager failure",
        ),
        Some(crate::flow_state::HandshakeRollbackOutcome::Retryable)
    ));
    assert_eq!(exit.exit_status(), None);
    let retry = flow_state
        .lease_due_upstream_reply_id_negotiation(std::time::Instant::now())
        .expect("rolled-back handshake retries negotiation");
    flow_state
        .record_upstream_negotiation_sequence(&retry, 1)
        .expect("record retry sequence");
    flow_state.complete_upstream_reply_id_negotiation_send(
        retry,
        1,
        true,
        std::time::Instant::now(),
    );
    assert!(matches!(
        flow_state.ack_upstream_reply_id_handshake(2002, 72, 1, None),
        ReplyIdHandshakeAck::Matched { .. }
    ));
}
