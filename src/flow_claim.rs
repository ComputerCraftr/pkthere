use crate::flow_key::ClientFlowKey;

use std::collections::HashMap;
use std::sync::Mutex;

pub(crate) struct FlowClaimTable {
    claims: Mutex<HashMap<ClientFlowKey, usize>>,
}

impl FlowClaimTable {
    pub fn new() -> Self {
        Self {
            claims: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_claim(&self, flow: ClientFlowKey, worker_pair_id: usize) -> bool {
        let mut claims = self.claims.lock().unwrap();
        match claims.get(&flow).copied() {
            Some(existing) => existing == worker_pair_id,
            None => {
                claims.insert(flow, worker_pair_id);
                true
            }
        }
    }

    pub fn release(&self, flow: ClientFlowKey, worker_pair_id: usize) {
        let mut claims = self.claims.lock().unwrap();
        if claims.get(&flow).copied() == Some(worker_pair_id) {
            claims.remove(&flow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FlowClaimTable;
    use crate::flow_key::ClientFlowKey;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn distinct_flows_can_be_claimed_by_distinct_workers() {
        let claims = FlowClaimTable::new();
        let a = ClientFlowKey::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000));
        let b = ClientFlowKey::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001));
        assert!(claims.try_claim(a, 0));
        assert!(claims.try_claim(b, 1));
    }

    #[test]
    fn same_flow_is_claimed_by_only_one_worker() {
        let claims = FlowClaimTable::new();
        let flow = ClientFlowKey::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000));
        assert!(claims.try_claim(flow, 0));
        assert!(!claims.try_claim(flow, 1));
        claims.release(flow, 0);
        assert!(claims.try_claim(flow, 1));
    }
}
