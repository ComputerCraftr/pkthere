/// Sole transaction entry point for capturing manager state around a
/// flow-owned diagnostic snapshot. The flow lease is dropped before the
/// second manager capture, and partial resources never escape.
pub(super) struct DiagnosticCaptureTransaction<ManagerSnapshot, FlowLease, FlowSnapshot> {
    manager_before: ManagerSnapshot,
    flow_lease: FlowLease,
    flow_snapshot: FlowSnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DiagnosticCaptureTransactionError<Error> {
    Operation(Error),
    Changed,
}

impl DiagnosticCaptureTransaction<(), (), ()> {
    pub(super) fn run<ManagerSnapshot, FlowLease, FlowSnapshot, Error>(
        mut capture_manager: impl FnMut() -> Result<ManagerSnapshot, Error>,
        acquire_flow: impl FnOnce() -> Result<FlowLease, Error>,
        capture_flow: impl for<'lease> FnOnce(&'lease FlowLease) -> FlowSnapshot,
        flow_is_current: impl FnOnce(&FlowLease) -> bool,
        same_manager_publication: impl FnOnce(&ManagerSnapshot, &ManagerSnapshot) -> bool,
    ) -> Result<(ManagerSnapshot, FlowSnapshot), DiagnosticCaptureTransactionError<Error>> {
        let manager_before =
            capture_manager().map_err(DiagnosticCaptureTransactionError::Operation)?;
        let flow_lease = acquire_flow().map_err(DiagnosticCaptureTransactionError::Operation)?;
        let flow_snapshot = capture_flow(&flow_lease);
        let transaction = DiagnosticCaptureTransaction {
            manager_before,
            flow_lease,
            flow_snapshot,
        };
        let flow_remained_current = flow_is_current(&transaction.flow_lease);
        let DiagnosticCaptureTransaction {
            manager_before,
            flow_lease,
            flow_snapshot,
        } = transaction;
        drop(flow_lease);
        if !flow_remained_current {
            return Err(DiagnosticCaptureTransactionError::Changed);
        }
        let manager_after =
            capture_manager().map_err(DiagnosticCaptureTransactionError::Operation)?;
        if !same_manager_publication(&manager_before, &manager_after) {
            return Err(DiagnosticCaptureTransactionError::Changed);
        }
        Ok((manager_before, flow_snapshot))
    }
}
