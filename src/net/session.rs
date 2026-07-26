use crate::diagnostics::PacketTraceId;
use crate::net::managed_socket::ManagedSendResult;
use crate::net::payload::PayloadEvent;
use crate::worker_support::PacketContext;
use crate::worker_support::{PacketDisposition, log_packet_send_disposition};
use socket2::SockAddr;

use std::io;
use std::time::Instant;

pub(crate) struct SendOutcome<'a> {
    pub(crate) result: &'a io::Result<ManagedSendResult>,
    pub(crate) attempted_at: Instant,
    pub(crate) completed_at: Instant,
    pub(crate) account_success: bool,
    pub(crate) destination: &'a SockAddr,
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
    Sent {
        retried_unconnected: bool,
        used_unconnected: bool,
    },
    Deferred,
    Failed,
}

pub(crate) fn handle_send_result(
    context: &mut PacketContext<'_, '_>,
    c2u: bool,
    event: &PayloadEvent<'_>,
    outcome: SendOutcome<'_>,
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
        attempted_at,
        completed_at,
        account_success,
        destination: dest_sa,
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
            log_debug!(
                cfg.debug_logs.packets,
                "[handle_send_result] worker {} c2u={} sent_len={} destination={:?} path={:?}",
                worker_id,
                c2u,
                res.length,
                dest_sa.as_socket(),
                res.path
            );
            if account_success && cfg.stats_interval_mins != 0 && event.is_user_payload() {
                stats.send_add(
                    c2u,
                    event.payload_len() as u64,
                    *t_recv,
                    attempted_at,
                    completed_at,
                );
            }

            if account_success && let Some(trace) = trace {
                log_packet_send_disposition(
                    cfg,
                    trace,
                    match trace_kind {
                        SendTraceKind::Forward => PacketDisposition::Forwarded,
                        SendTraceKind::ReplySessionControl => {
                            PacketDisposition::ReplySessionControl
                        }
                    },
                    res.used_unconnected_send(),
                );
            }
            HandledSendOutcome::Sent {
                retried_unconnected: false,
                used_unconnected: res.used_unconnected_send(),
            }
        }
        Err(e) => {
            log_debug_dir!(
                cfg.debug_logs.drops,
                worker_id,
                c2u,
                "managed socket send error (dest_sa '{:?}'): {}",
                dest_sa.as_socket(),
                e
            );
            if event.is_user_payload() {
                stats.user_send_error(c2u);
            } else {
                stats.control_send_error(c2u);
            }
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
mod tests;
