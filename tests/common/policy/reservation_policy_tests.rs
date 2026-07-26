use super::{PolicyKind, tests::findings_at};

#[test]
fn flow_topology_tokens_cannot_be_detached_from_their_outer_reservation() {
    let source = r#"
        fn detach(
            reservation: &mut ClientFlowReservation<'_>,
        ) -> Result<FlowTopologyWriteReservation<'_>, FlowTopologyError> {
            reservation.take_topology()
        }
    "#;
    let findings = findings_at(
        "src/worker.rs",
        source,
        PolicyKind::InteriorMutabilityAuthority,
    );
    assert_eq!(findings.len(), 1);
    assert!(findings[0].detail.contains("remain borrowed"));
}
