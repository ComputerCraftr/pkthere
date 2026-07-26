use crate::cli::SupportedProtocol;
use crate::net::payload::PayloadEvent;
use crate::stats::StatsSink;
#[derive(Default)]
struct CountingStats {
    sends: usize,
}

impl StatsSink for CountingStats {
    fn send_add(
        &mut self,
        _c2u: bool,
        _bytes: u64,
        _received_at: std::time::Instant,
        _attempted_at: std::time::Instant,
        _completed_at: std::time::Instant,
    ) {
        self.sends += 1;
    }

    fn drop_err(&mut self, _c2u: bool) {}
    fn drop_oversize(&mut self, _c2u: bool) {}
    fn handshake_invalid_control(&mut self, _c2u: bool) {}
    fn handshake_stale_ack(&mut self) {}
}

#[test]
fn test_handle_send_result_failed() {
    use crate::flow_state::FlowRuntimeState;
    use crate::net::session::{
        HandledSendOutcome, PacketContext, SendOutcome, SendTraceKind, handle_send_result,
    };
    use crate::stats::Stats;
    use crate::worker_support::PacketTraceId;
    use socket2::SockAddr;
    use std::io;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Instant;

    let cfg = crate::worker_support::admission_test_support::test_config(
        crate::cli::IcmpReplyIdRequest::Default,
    );
    let stats = Stats::with_worker_shards(1);
    let mut recorder = stats.recorder(0);
    let flow_state = FlowRuntimeState::new();
    let now = Instant::now();
    let context = &mut PacketContext::new(1, now, now, &cfg, &mut recorder, &flow_state);
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, &[]);
    let err_res: io::Result<crate::net::managed_socket::ManagedSendResult> = Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "test error",
    ));
    let outcome = SendOutcome {
        result: &err_res,
        attempted_at: context.t_event,
        completed_at: context.t_event,
        account_success: true,
        destination: &SockAddr::from(SocketAddr::from_str("127.0.0.1:0").unwrap()),
        trace: Some(PacketTraceId {
            worker_id: 1,
            c2u: true,
            packet_id: 100,
        }),
        trace_kind: SendTraceKind::Forward,
    };

    let res = handle_send_result(context, true, &event, outcome);
    assert_eq!(res, HandledSendOutcome::Failed);
}

#[test]
fn successful_buffered_send_is_not_accounted_before_session_commit() {
    use crate::flow_state::FlowRuntimeState;
    use crate::net::managed_socket::{ManagedSendPath, ManagedSendResult};
    use crate::net::session::{PacketContext, SendOutcome, SendTraceKind, handle_send_result};
    use socket2::SockAddr;
    use std::net::SocketAddr;
    use std::time::Instant;

    let cfg = crate::worker_support::admission_test_support::test_config(
        crate::cli::IcmpReplyIdRequest::Default,
    );
    let mut stats = CountingStats::default();
    let flow_state = FlowRuntimeState::new();
    let now = Instant::now();
    let context = &mut PacketContext::new(0, now, now, &cfg, &mut stats, &flow_state);
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, b"pending");
    let sent = Ok(ManagedSendResult {
        length: event.payload_len(),
        path: ManagedSendPath::Connected,
    });
    let destination = SockAddr::from(SocketAddr::from(([127, 0, 0, 1], 9)));

    handle_send_result(
        context,
        true,
        &event,
        SendOutcome {
            result: &sent,
            attempted_at: now,
            completed_at: now,
            account_success: false,
            destination: &destination,
            trace: None,
            trace_kind: SendTraceKind::Forward,
        },
    );

    assert_eq!(stats.sends, 0);
}
