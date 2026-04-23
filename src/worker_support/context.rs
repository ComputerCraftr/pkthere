use crate::cli::RuntimeConfig;
use crate::flow_state::FlowRuntimeState;
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState};
use crate::stats::StatsSink;
use std::time::Instant;

#[derive(Clone, Copy)]
pub(crate) struct PacketContext<'a> {
    pub(crate) worker_id: usize,
    pub(crate) t_start: Instant,
    pub(crate) t_event: Instant,
    pub(crate) cfg: &'a RuntimeConfig,
    pub(crate) stats: &'a dyn StatsSink,
    pub(crate) flow_state: &'a FlowRuntimeState,
}

impl<'a> PacketContext<'a> {
    #[inline]
    pub(crate) fn new(
        worker_id: usize,
        t_start: Instant,
        t_event: Instant,
        cfg: &'a RuntimeConfig,
        stats: &'a dyn StatsSink,
        flow_state: &'a FlowRuntimeState,
    ) -> Self {
        Self {
            worker_id,
            t_start,
            t_event,
            cfg,
            stats,
            flow_state,
        }
    }
}

pub(crate) struct SequenceContext<'a> {
    pub(crate) client_state: &'a SharedIcmpSequenceState,
    pub(crate) client_cache: &'a mut IcmpSequenceCache,
    pub(crate) upstream_state: &'a SharedIcmpSequenceState,
    pub(crate) upstream_cache: &'a mut IcmpSequenceCache,
}

impl<'a> SequenceContext<'a> {
    #[inline]
    pub(crate) fn new(
        client_state: &'a SharedIcmpSequenceState,
        client_cache: &'a mut IcmpSequenceCache,
        upstream_state: &'a SharedIcmpSequenceState,
        upstream_cache: &'a mut IcmpSequenceCache,
    ) -> Self {
        Self {
            client_state,
            client_cache,
            upstream_state,
            upstream_cache,
        }
    }
}
