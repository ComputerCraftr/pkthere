pub(crate) trait TopologyTransactionOwner: Sized {
    type Error;
    type Receipt;

    fn apply_socket_transitions(&mut self) -> Result<(), Self::Error>;
    fn prepare_manager_state(&mut self) -> Result<(), Self::Error>;
    fn commit_session_state(
        &mut self,
        expected_flow_epoch: u64,
        resulting_flow_epoch: u64,
    ) -> Result<Self::Receipt, Self::Error>;
    fn publish_manager_state(self) -> Result<(), Self::Error>;
    fn publish_committed_state(self, receipt: Self::Receipt) -> Result<(), Self::Error>;
}

#[must_use]
pub(super) struct ReservedTopologyTransaction<Owner> {
    owner: Owner,
}

#[must_use]
pub(crate) struct SocketTransitionsAppliedTopology<Owner> {
    owner: Owner,
}

#[must_use]
pub(crate) struct PreparedTopology<Owner> {
    owner: Owner,
}

#[must_use]
pub(crate) struct SessionCommittedTopology<Owner: TopologyTransactionOwner> {
    owner: Owner,
    receipt: Owner::Receipt,
}

impl<Owner: TopologyTransactionOwner> ReservedTopologyTransaction<Owner> {
    pub(super) const fn new(owner: Owner) -> Self {
        Self { owner }
    }

    pub(super) fn socket_transitions_applied(
        mut self,
    ) -> Result<SocketTransitionsAppliedTopology<Owner>, Owner::Error> {
        self.owner.apply_socket_transitions()?;
        Ok(SocketTransitionsAppliedTopology { owner: self.owner })
    }
}

impl<Owner: TopologyTransactionOwner> SocketTransitionsAppliedTopology<Owner> {
    pub(crate) fn manager_state_prepared(
        mut self,
    ) -> Result<PreparedTopology<Owner>, Owner::Error> {
        self.owner.prepare_manager_state()?;
        Ok(PreparedTopology { owner: self.owner })
    }
}

impl<Owner: TopologyTransactionOwner> PreparedTopology<Owner> {
    pub(crate) fn commit_session(
        mut self,
        expected_flow_epoch: u64,
        resulting_flow_epoch: u64,
    ) -> Result<SessionCommittedTopology<Owner>, Owner::Error> {
        let receipt = self
            .owner
            .commit_session_state(expected_flow_epoch, resulting_flow_epoch)?;
        Ok(SessionCommittedTopology {
            owner: self.owner,
            receipt,
        })
    }

    pub(crate) fn publish_manager_only(self) -> Result<(), Owner::Error> {
        self.owner.publish_manager_state()
    }
}

impl<Owner: TopologyTransactionOwner> SessionCommittedTopology<Owner> {
    pub(crate) fn publish(self) -> Result<(), Owner::Error> {
        self.owner.publish_committed_state(self.receipt)
    }
}
