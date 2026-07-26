use super::render_session_diagnostics;

#[test]
fn diagnostics_include_latest_stats_and_both_output_tails() {
    let rendered = render_session_diagnostics(
        "node-a",
        "pkthere --here UDP:127.0.0.1:0",
        None,
        "boot\n[INFO] {\"locked\":true}\nlast stdout",
        "first stderr\nlast stderr",
        2,
    );
    assert!(rendered.contains("node-a"));
    assert!(rendered.contains("{\"locked\":true}"));
    assert!(rendered.contains("last stdout"));
    assert!(rendered.contains("last stderr"));
}
