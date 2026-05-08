pub fn locked_worker_flow(stats: &serde_json::Value) -> &serde_json::Value {
    stats["worker_flows"]
        .as_array()
        .and_then(|flows| {
            flows.iter().find(|flow| {
                flow["locked"].as_bool().unwrap_or(false)
                    || !flow["listener_flow_outbound"].is_null()
                    || !flow["flow_key"].is_null()
            })
        })
        .expect("expected at least one worker flow entry")
}

pub fn listener_outbound_remote(worker: &serde_json::Value) -> &str {
    worker["listener_flow_outbound"]
        .as_str()
        .and_then(|flow| flow.split_once(" -> ").map(|(_, dst)| dst))
        .expect("listener_flow_outbound must contain 'src -> dst'")
}
