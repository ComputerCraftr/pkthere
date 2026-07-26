use super::{FlowRuntimeState, activate_upstream_session, pending_client_lock};
use crate::diagnostics::PacketTraceId;
use crate::net::framing_shim::SessionId;

#[test]
fn receive_candidate_capacity_is_protocol_wide_not_local_pool_sized() {
    let state = FlowRuntimeState::with_session_pool_size(1);
    let first = pending_client_lock();
    state
        .set_pending_icmp_client_lock(
            first,
            1,
            PacketTraceId {
                worker_id: 0,
                c2u: true,
                packet_id: 1,
            },
            0,
        )
        .expect("install initial receive session");
    state
        .reserve_client_flow()
        .publish_locked(first.flow_key)
        .expect("publish first flow");

    for offset in 0..crate::flow_state::MAX_RECEIVE_SESSION_CANDIDATES {
        let session_id = SessionId::new(100 + offset as u64).expect("candidate ID");
        let candidate = super::pending_with_session(
            first,
            crate::net::framing_shim::SessionKey::for_tests_with(
                session_id,
                u32::try_from(offset + 1).expect("candidate ordinal fits u32"),
            ),
        );
        assert_eq!(
            state
                .set_pending_icmp_client_lock(
                    candidate,
                    2,
                    PacketTraceId {
                        worker_id: 0,
                        c2u: true,
                        packet_id: 2 + offset as u64,
                    },
                    offset as u16,
                )
                .expect("protocol-wide receive candidate capacity"),
            crate::flow_state::PendingIcmpClientLockSet::Started
        );
    }

    let overflow = super::pending_with_session(
        first,
        crate::net::framing_shim::SessionKey::for_tests_with(
            SessionId::new(10_000).expect("overflow candidate ID"),
            u32::try_from(crate::flow_state::MAX_RECEIVE_SESSION_CANDIDATES + 1)
                .expect("overflow candidate ordinal fits u32"),
        ),
    );
    assert!(
        state
            .set_pending_icmp_client_lock(
                overflow,
                2,
                PacketTraceId {
                    worker_id: 0,
                    c2u: true,
                    packet_id: 100,
                },
                0,
            )
            .is_err(),
        "the bounded 32-ready plus two-negotiating capacity rejects another session"
    );
}

#[test]
fn reset_clears_active_ready_negotiating_and_draining_sessions() {
    let state = FlowRuntimeState::with_session_pool_size(2);
    let active = SessionId::new(17).expect("active session");
    activate_upstream_session(&state, active.get());
    state
        .maintain_upstream_session_pool(2002)
        .expect("create reserve candidates");
    assert_eq!(state.session_pool_snapshot().pool.negotiating, 2);

    state.reset();
    assert_eq!(
        state.session_pool_snapshot(),
        crate::flow_state::SessionPoolSnapshot {
            pool: crate::flow_state::SessionPoolStateSnapshot {
                target: 2,
                ..crate::flow_state::SessionPoolStateSnapshot::default()
            },
            ..crate::flow_state::SessionPoolSnapshot::default()
        }
    );
}
