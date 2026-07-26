use std::time::Instant;

pub(crate) trait StatsSink {
    fn send_add(
        &mut self,
        c2u: bool,
        bytes: u64,
        received_at: Instant,
        attempted_at: Instant,
        completed_at: Instant,
    );
    fn drop_err(&mut self, c2u: bool);
    fn receive_error(&mut self, c2u: bool) {
        self.drop_err(c2u);
    }
    fn spurious_readiness(&mut self, _c2u: bool) {}
    fn user_send_error(&mut self, c2u: bool) {
        self.drop_err(c2u);
    }
    fn control_send_error(&mut self, c2u: bool) {
        self.drop_err(c2u);
    }
    fn admission_drop(&mut self, c2u: bool) {
        self.drop_err(c2u);
    }
    fn malformed_packet(&mut self, c2u: bool) {
        self.admission_drop(c2u);
    }
    fn wrong_peer_drop(&mut self, _c2u: bool) {}
    fn wrong_source_drop(&mut self, _c2u: bool) {}
    fn handshake_invalid_drop(&mut self, c2u: bool) {
        self.admission_drop(c2u);
    }
    fn replay_drop(&mut self, c2u: bool) {
        self.admission_drop(c2u);
    }
    fn icmp_abuse_budget_drop(&mut self, c2u: bool) {
        self.admission_drop(c2u);
    }
    fn stale_session_drop(&mut self, c2u: bool) {
        self.admission_drop(c2u);
    }
    fn stale_authority_drop(&mut self, c2u: bool) {
        self.admission_drop(c2u);
    }
    fn packet_rejection(&mut self, _c2u: bool, _category: super::PacketRejectionCategory) {}
    fn invariant_failure(&mut self, c2u: bool) {
        self.drop_err(c2u);
    }
    fn topology_error(&mut self, c2u: bool) {
        self.drop_err(c2u);
    }
    fn drop_oversize(&mut self, c2u: bool);
    fn handshake_invalid_control(&mut self, c2u: bool);
    fn handshake_stale_ack(&mut self);
}
