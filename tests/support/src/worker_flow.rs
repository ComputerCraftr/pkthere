pub fn find_locked_worker_flow(stats: &serde_json::Value) -> Option<&serde_json::Value> {
    stats["worker_flows"].as_array().and_then(|flows| {
        flows.iter().find(|flow| {
            flow["locked"].as_bool().expect("worker locked field bool")
                || !flow["listener_flow_outbound"].is_null()
                || !flow["flow_key"].is_null()
        })
    })
}

pub fn locked_worker_flow(stats: &serde_json::Value) -> &serde_json::Value {
    find_locked_worker_flow(stats).expect("expected at least one worker flow entry")
}

pub fn flow_tuple<'a>(worker: &'a serde_json::Value, field: &str) -> (&'a str, &'a str) {
    worker_str(worker, field)
        .split_once(" -> ")
        .expect("flow field must contain 'src -> dst'")
}

pub fn worker_str<'a>(worker: &'a serde_json::Value, field: &str) -> &'a str {
    worker[field]
        .as_str()
        .expect("worker field must be a string")
}

pub fn assert_flow_tuple(
    worker: &serde_json::Value,
    field: &str,
    expected_src: &str,
    expected_dst: &str,
) {
    let (src, dst) = flow_tuple(worker, field);
    assert_eq!(src, expected_src, "{field} source mismatch");
    assert_eq!(dst, expected_dst, "{field} destination mismatch");
}

#[cfg(test)]
mod tests;
