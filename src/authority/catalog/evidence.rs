use super::super::{
    BadStateId, DiagnosticClass, FunctionIdentity, InvariantId, NegativeControlExpectation,
    ResourceIdentity,
};

pub(crate) const NEGATIVE_CONTROL_EXPECTATIONS: &[NegativeControlExpectation] = &[
    NegativeControlExpectation {
        invariant: InvariantId::SendCompletion,
        diagnostic_class: DiagnosticClass::BadTerminalState,
        source: FunctionIdentity::SendCompleteSuccess,
        offending_edge: None,
        resource: Some(ResourceIdentity::OwnedField {
            owner: super::super::TypeIdentity::SendCompletionCore,
            field: super::super::FieldIdentity::DeferredControl,
            source_field: "deferred",
            resource_type: super::super::TypeIdentity::DeferredPeerControl,
        }),
        bad_terminal_state: Some(BadStateId::StrandedDeferredControl),
    },
    NegativeControlExpectation {
        invariant: InvariantId::ReresolvePublication,
        diagnostic_class: DiagnosticClass::BadTerminalState,
        source: FunctionIdentity::ReresolvePublishFlow,
        offending_edge: None,
        resource: Some(ResourceIdentity::OwnedField {
            owner: super::super::TypeIdentity::ReresolvePublicationCore,
            field: super::super::FieldIdentity::ReresolveFlowVisibility,
            source_field: "flow",
            resource_type: super::super::TypeIdentity::FlowVisibilityLease,
        }),
        bad_terminal_state: Some(BadStateId::MixedReresolvePublication),
    },
];
