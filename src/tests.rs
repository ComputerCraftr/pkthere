use super::socket_mode_reason;

#[test]
fn socket_mode_reason_reports_debug_only_when_debug_causes_unconnected_mode() {
    assert_eq!(socket_mode_reason(true, false, false), "debug");
    assert_eq!(socket_mode_reason(true, true, true), "policy");
    assert_eq!(socket_mode_reason(false, false, false), "policy");
    assert_eq!(socket_mode_reason(false, true, true), "default");
}
