use crate::cli::RuntimeConfig;
use crate::flow_state::FlowRuntimeState;
use crate::net::payload::PayloadEvent;
use crate::net::payload_support::DEST_ADDR_REQUIRED;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use crate::stats::StatsSink;
use socket2::SockAddr;

use std::io;
use std::time::Instant;

#[inline]
pub(crate) fn counts_as_session_activity(
    event: &PayloadEvent<'_>,
    accepted_peer_activity: bool,
) -> bool {
    accepted_peer_activity && !event.is_cadence_packet()
}

pub(crate) fn handle_send_result(
    c2u: bool,
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &RuntimeConfig,
    stats: &dyn StatsSink,
    flow_state: &FlowRuntimeState,
    event: &PayloadEvent<'_>,
    counts_as_session_activity: bool,
    send_res: &io::Result<bool>,
    sock_connected: bool,
    dest_sa: &SockAddr,
    disconnect_ctx: Option<(&mut SocketHandles, &SocketManager)>,
) {
    log_debug!(
        cfg.debug_logs.packets,
        "[handle_send_result] worker {} c2u={} is_user_payload={} payload_len={}",
        worker_id,
        c2u,
        event.is_user_payload(),
        event.payload_len()
    );

    if counts_as_session_activity {
        flow_state.record_activity(t_start, t_recv);
    }

    match send_res {
        Ok(res) => {
            if cfg.stats_interval_mins != 0 && event.is_user_payload() {
                let t_send = Instant::now();
                stats.send_add(c2u, event.payload_len() as u64, t_recv, t_send);
            }

            if !*res {
                if let Some((handles, sock_mgr)) = disconnect_ctx {
                    if handles.client_connected {
                        let prev_ver = handles.version;
                        log_warn_dir!(
                            worker_id,
                            c2u,
                            "send_payload error (EDESTADDRREQ); disconnecting client socket"
                        );
                        handles.client_connected = false;
                        handles.version = match sock_mgr.set_client_sock_disconnected(
                            handles.locked_flow,
                            handles.client_peer,
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
                            handles.locked_flow,
                            prev_ver,
                            handles.version
                        );
                    }
                }
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
        }
    };
}

#[cfg(test)]
mod tests {
    use super::counts_as_session_activity;
    use crate::cli::SupportedProtocol;
    use crate::net::payload::PayloadEvent;

    #[test]
    fn forwarded_user_data_counts_as_activity_even_when_zero_length() {
        let zero = PayloadEvent::user_payload_plain(SupportedProtocol::UDP, &[]);
        let session_control =
            PayloadEvent::session_control(0, 1, SupportedProtocol::ICMP, &[], None);
        let cadence = PayloadEvent::cadence_packet(0, 2);

        assert!(counts_as_session_activity(&zero, true));
        assert!(!counts_as_session_activity(&zero, false));
        assert!(counts_as_session_activity(&session_control, true));
        assert!(!counts_as_session_activity(&cadence, true));
    }
}
