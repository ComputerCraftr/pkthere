use crate::cli::Config;
use crate::net::payload::PayloadEvent;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use crate::stats::StatsSink;
use socket2::SockAddr;

use std::io;
use std::sync::atomic::{AtomicU64, Ordering as AtomOrdering};
use std::time::Instant;

#[cfg(unix)]
const DEST_ADDR_REQUIRED: i32 = libc::EDESTADDRREQ;
#[cfg(windows)]
const DEST_ADDR_REQUIRED: i32 = 10039; // WSAEDESTADDRREQ

#[inline]
pub(crate) fn counts_as_session_activity(event: &PayloadEvent<'_>, will_forward: bool) -> bool {
    will_forward && event.is_user_data()
}

pub(crate) fn handle_send_result(
    c2u: bool,
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &Config,
    stats: &dyn StatsSink,
    last_seen_s: &AtomicU64,
    payload_len: usize,
    counts_as_session_activity: bool,
    send_res: &io::Result<bool>,
    sock_connected: bool,
    dest_sa: &SockAddr,
    disconnect_ctx: Option<(&mut SocketHandles, &SocketManager)>,
) {
    if counts_as_session_activity {
        let last_seen = t_recv.saturating_duration_since(t_start).as_secs().max(1);
        last_seen_s.store(last_seen, AtomOrdering::Relaxed);
    }

    match send_res {
        Ok(res) => {
            if cfg.stats_interval_mins != 0 {
                let t_send = Instant::now();
                stats.send_add(c2u, payload_len as u64, t_recv, t_send);
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
                            handles.client_addr,
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
                            cfg.debug_log_handles,
                            worker_id,
                            c2u,
                            "publish disconnect: addr={:?} ver {}->{}",
                            handles.client_addr,
                            prev_ver,
                            handles.version
                        );
                    }
                }
            }
        }
        Err(e) => {
            log_debug_dir!(
                cfg.debug_log_drops,
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
    use crate::net::payload::{PayloadEvent, WirePayload};

    #[test]
    fn forwarded_user_data_counts_as_activity_even_when_zero_length() {
        let zero = PayloadEvent::UserData(WirePayload {
            src_is_icmp: false,
            src_seq: 0,
            dst_proto: SupportedProtocol::UDP,
            payload: &[],
            pub_len: 0,
        });
        let keepalive = PayloadEvent::SyncKeepalive(WirePayload {
            src_is_icmp: true,
            src_seq: 1,
            dst_proto: SupportedProtocol::ICMP,
            payload: &[],
            pub_len: 0,
        });

        assert!(counts_as_session_activity(&zero, true));
        assert!(!counts_as_session_activity(&zero, false));
        assert!(!counts_as_session_activity(&keepalive, true));
    }
}
