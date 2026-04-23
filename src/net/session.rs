use crate::net::payload::PayloadEvent;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use crate::net::socket_errors::DEST_ADDR_REQUIRED;
use crate::packet_trace::PacketTraceId;
use crate::worker_support::PacketContext;
use crate::worker_support::{PacketDisposition, log_packet_send_disposition};
use socket2::SockAddr;

use std::io;
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct SendOutcome<'a, 'b> {
    pub(crate) result: &'a io::Result<bool>,
    pub(crate) socket_connected: bool,
    pub(crate) destination: &'a SockAddr,
    pub(crate) disconnect: Option<(&'b mut SocketHandles, &'b SocketManager)>,
    pub(crate) trace: Option<PacketTraceId>,
    pub(crate) trace_kind: SendTraceKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendTraceKind {
    Forward,
    ReplySessionControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandledSendOutcome {
    Sent { retried_unconnected: bool },
    Failed,
}

pub(crate) fn handle_send_result(
    context: PacketContext<'_>,
    c2u: bool,
    event: &PayloadEvent<'_>,
    outcome: SendOutcome<'_, '_>,
) -> HandledSendOutcome {
    let PacketContext {
        worker_id,
        t_event: t_recv,
        cfg,
        stats,
        ..
    } = context;
    let SendOutcome {
        result: send_res,
        socket_connected: sock_connected,
        destination: dest_sa,
        disconnect: disconnect_ctx,
        trace,
        trace_kind,
    } = outcome;
    log_debug!(
        cfg.debug_logs.packets,
        "[handle_send_result] worker {} c2u={} is_user_payload={} payload_len={}",
        worker_id,
        c2u,
        event.is_user_payload(),
        event.payload_len()
    );

    match send_res {
        Ok(res) => {
            if cfg.stats_interval_mins != 0 && event.is_user_payload() {
                let t_send = Instant::now();
                stats.send_add(c2u, event.payload_len() as u64, t_recv, t_send);
            }

            if !*res
                && let Some((handles, sock_mgr)) = disconnect_ctx
                && handles.listener.listener_connected
            {
                let prev_ver = handles.version;
                log_warn_dir!(
                    worker_id,
                    c2u,
                    "send_payload error (EDESTADDRREQ); disconnecting client socket"
                );
                Arc::make_mut(&mut handles.listener).listener_connected = false;
                handles.version = match sock_mgr.set_client_sock_disconnected(
                    handles.listener.flow,
                    handles.listener.listener_flow,
                    false,
                    prev_ver,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        log_warn_dir!(worker_id, c2u, "disconnect_socket failed: {}", e);
                        prev_ver
                    }
                };
                log_debug_dir!(
                    cfg.debug_logs.handles,
                    worker_id,
                    c2u,
                    "publish disconnect: addr={:?} ver {}->{}",
                    handles.listener.flow,
                    prev_ver,
                    handles.version
                );
            }
            if let Some(trace) = trace {
                log_packet_send_disposition(
                    cfg,
                    trace,
                    match trace_kind {
                        SendTraceKind::Forward => PacketDisposition::Forwarded,
                        SendTraceKind::ReplySessionControl => {
                            PacketDisposition::ReplySessionControl
                        }
                    },
                    !*res,
                );
            }
            HandledSendOutcome::Sent {
                retried_unconnected: !*res,
            }
        }
        Err(e) => {
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                c2u,
                "send_payload error ({} on dest_sa '{:?}'): {}",
                if sock_connected && e.raw_os_error() != Some(DEST_ADDR_REQUIRED) {
                    "send"
                } else {
                    "send_to"
                },
                dest_sa.as_socket(),
                e
            );
            stats.drop_err(c2u);
            if let Some(trace) = trace {
                log_packet_send_disposition(
                    cfg,
                    trace,
                    match trace_kind {
                        SendTraceKind::Forward => PacketDisposition::SendFailed,
                        SendTraceKind::ReplySessionControl => PacketDisposition::ReplyFailed,
                    },
                    false,
                );
            }
            HandledSendOutcome::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cli::SupportedProtocol;
    use crate::net::payload::PayloadEvent;

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
        let flow_state = FlowRuntimeState::new();
        let context = PacketContext {
            worker_id: 1,
            t_start: Instant::now(),
            t_event: Instant::now(),
            cfg: &cfg,
            stats: &stats,
            flow_state: &flow_state,
        };
        let event = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, &[]);
        let err_res: io::Result<bool> = Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test error",
        ));
        let outcome = SendOutcome {
            result: &err_res,
            socket_connected: false,
            destination: &SockAddr::from(SocketAddr::from_str("127.0.0.1:0").unwrap()),
            disconnect: None,
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
}
