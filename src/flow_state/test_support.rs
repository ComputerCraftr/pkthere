use super::{FlowRuntimeState, ReplyIdHandshakeAck};
use crate::diagnostics::PacketTraceId;
use crate::net::framing_shim::{SessionId, SessionKey};
use std::time::Instant;

impl FlowRuntimeState {
    pub fn ack_upstream_reply_id_handshake(
        &self,
        observed_ack_destination_id: u16,
        observed_instance: u64,
        observed_sequence: u16,
        trigger_trace: Option<PacketTraceId>,
    ) -> ReplyIdHandshakeAck {
        let observed_key = {
            let sessions =
                crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
            sessions
                .upstream_pool
                .upstream_reserve_handshakes
                .iter()
                .map(|candidate| candidate.session_key)
                .chain(
                    sessions
                        .upstream_pool
                        .upstream_ready_sessions
                        .iter()
                        .map(|ready| ready.session_key),
                )
                .chain(sessions.control.upstream_pending_key)
                .find(|key| key.session_id().get() == observed_instance)
                .unwrap_or_else(|| {
                    SessionKey::new(
                        observed_instance,
                        0,
                        SessionId::new(observed_instance)
                            .expect("test handshake instance must be nonzero"),
                    )
                    .expect("test handshake generation must be nonzero")
                })
        };
        self.ack_upstream_reply_id_handshake_key(
            observed_ack_destination_id,
            observed_key,
            observed_sequence,
            0,
            Instant::now(),
            trigger_trace,
        )
    }
}
