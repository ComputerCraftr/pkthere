pub fn locked_worker_flow(stats: &serde_json::Value) -> &serde_json::Value {
    stats["worker_flows"]
        .as_array()
        .and_then(|flows| {
            flows.iter().find(|flow| {
                flow["locked"].as_bool().expect("worker locked field bool")
                    || !flow["listener_flow_outbound"].is_null()
                    || !flow["flow_key"].is_null()
            })
        })
        .expect("expected at least one worker flow entry")
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
mod tests {
    use serde_json::json;

    #[test]
    fn flow_tuple_splits_exact_source_and_destination() {
        let worker = json!({"listener_flow_outbound":"127.0.0.1:1202 -> 127.0.0.1:54666"});
        assert_eq!(
            super::flow_tuple(&worker, "listener_flow_outbound"),
            ("127.0.0.1:1202", "127.0.0.1:54666")
        );
    }

    #[test]
    #[should_panic(expected = "flow field must contain 'src -> dst'")]
    fn flow_tuple_rejects_malformed_flow_string() {
        let worker = json!({"listener_flow_outbound":"127.0.0.1:1202"});
        super::flow_tuple(&worker, "listener_flow_outbound");
    }
}
