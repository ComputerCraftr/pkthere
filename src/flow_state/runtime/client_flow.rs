use super::{ClientFlowReservation, FlowRuntimeState, Instant};
use crate::net::sock_mgr::transaction_lock::{MANAGER_RESERVATION_TIMEOUT, ReservationError};

impl FlowRuntimeState {
    pub(crate) fn try_reserve_client_flow_until(
        &self,
        deadline: Instant,
    ) -> Result<ClientFlowReservation<'_>, ReservationError> {
        let reservation = self.client_flow_reservation.reserve_until(deadline)?;
        let topology = match self
            .topology
            .reserve_until_with_runtime_wake(deadline, self)
        {
            Ok(topology) => topology,
            Err(error) => {
                if matches!(
                    error.class(),
                    crate::runtime_support::FailureClass::RetryableContention
                ) {
                    self.publish_admission_snapshot(self.flow_epoch());
                }
                return Err(match error.class() {
                    crate::runtime_support::FailureClass::RetryableContention => {
                        ReservationError::TimedOut
                    }
                    crate::runtime_support::FailureClass::Shutdown => ReservationError::Shutdown,
                    crate::runtime_support::FailureClass::PacketRejected
                    | crate::runtime_support::FailureClass::OperationFailed
                    | crate::runtime_support::FailureClass::FatalInvariant => {
                        ReservationError::OwnershipLost
                    }
                });
            }
        };
        let expected_epoch = topology.previous_epoch();
        let publication_epoch = topology.publication_epoch();
        Ok(ClientFlowReservation {
            state: self,
            topology: Some(topology),
            reservation: Some(reservation),
            expected_epoch,
            publication_epoch,
        })
    }

    pub(crate) fn try_reserve_client_flow(
        &self,
    ) -> Result<ClientFlowReservation<'_>, ReservationError> {
        self.try_reserve_client_flow_until(Instant::now() + MANAGER_RESERVATION_TIMEOUT)
    }

    #[cfg(test)]
    pub(crate) fn reserve_client_flow(&self) -> ClientFlowReservation<'_> {
        self.try_reserve_client_flow()
            .expect("reserve client-flow transaction for test")
    }

    #[cfg(test)]
    pub(crate) fn client_flow_mutex_is_available_for_test(&self) -> bool {
        self.client_flow_reservation
            .coordination_mutex_is_available_for_test()
    }
}
