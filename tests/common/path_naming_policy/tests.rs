use super::is_snake_case;

#[test]
fn snake_case_rejects_junk_drawer_separator_patterns() {
    assert!(is_snake_case("packet_admission"));
    assert!(is_snake_case("ipv6_packet"));
    assert!(!is_snake_case("packet__admission"));
    assert!(!is_snake_case("packet_admission_"));
    assert!(!is_snake_case("_packet_admission"));
}
