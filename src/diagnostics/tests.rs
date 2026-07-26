#[test]
fn stamps_schema_and_monotonic_sequence() {
    let first = super::stamp(serde_json::json!({}));
    let second = super::stamp(serde_json::json!({}));
    assert_eq!(first["diagnostic_schema"], 3);
    let first_sequence = first["diagnostic_sequence"]
        .as_u64()
        .expect("first diagnostic sequence is required");
    let second_sequence = second["diagnostic_sequence"]
        .as_u64()
        .expect("second diagnostic sequence is required");
    assert_eq!(
        second_sequence,
        first_sequence
            .checked_add(1)
            .expect("diagnostic test sequence must not overflow")
    );
}
