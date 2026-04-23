use crate::cli::IcmpReplyIdRequest;
use crate::flow_key::{FlowEndpoint, FlowTuple, SocketLegFlow};
use crate::net::params::CanonicalAddr;

#[inline]
pub(super) fn upstream_leg_flow(
    local_reply: CanonicalAddr,
    local_source_id_request: IcmpReplyIdRequest,
    remote: CanonicalAddr,
) -> SocketLegFlow {
    let local_reply_ep = FlowEndpoint::from_canonical(local_reply);
    let source_id = match local_source_id_request.resolved_reply_id(local_reply.id) {
        Some(id) => id,
        None => local_reply.id,
    };
    let local_source_ep = FlowEndpoint::from_canonical(local_reply).with_id(source_id);
    let remote_ep = FlowEndpoint::from_canonical(remote);
    SocketLegFlow::new(
        Some(FlowTuple::new(remote_ep, local_reply_ep)),
        Some(FlowTuple::new(local_source_ep, remote_ep)),
    )
}
