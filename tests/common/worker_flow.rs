pub fn locked_worker_flow(stats: &serde_json::Value) -> &serde_json::Value {
    stats["worker_flows"]
        .as_array()
        .and_then(|flows| {
            flows.iter().find(|flow| {
                flow["locked"].as_bool().unwrap_or(false)
                    || !flow["client_remote_canonical"].is_null()
                    || !flow["flow_key"].is_null()
            })
        })
        .expect("expected at least one worker flow entry")
}
