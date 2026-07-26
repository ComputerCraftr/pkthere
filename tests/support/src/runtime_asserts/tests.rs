use super::StatsWaitOutcome;

#[test]
fn stats_timeout_diagnostics_preserve_last_seen_stats() {
    let outcome = StatsWaitOutcome {
        matched: false,
        last_seen: Some(serde_json::json!({"locked": true})),
        recent_stdout_tail: Some("last output".to_string()),
        recent_stderr_tail: None,
    };
    let details = outcome.failure_details();
    assert!(details.contains("\"locked\":true"));
    assert!(details.contains("last output"));
}
