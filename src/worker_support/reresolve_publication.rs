pub(crate) trait ManagerTopologyPublication {
    type Error;
    type Output;

    fn publish_manager_topology(self) -> Result<Self::Output, Self::Error>;
}

pub(crate) trait FlowVisibilityPublication {
    type Error;

    fn publish_flow_visibility(self) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub(crate) enum ReresolvePublicationError<ManagerError, FlowError> {
    Manager(ManagerError),
    FlowAfterManager(FlowError),
}

/// Consuming owner of the manager/topology bundle and every flow visibility
/// lease participating in one re-resolution publication.
pub(crate) struct ReresolvePublicationCore<Manager, Flow> {
    manager: Manager,
    flow: Flow,
}

impl<Manager, Flow> ReresolvePublicationCore<Manager, Flow>
where
    Manager: ManagerTopologyPublication,
    Flow: FlowVisibilityPublication,
{
    pub(crate) const fn new(manager: Manager, flow: Flow) -> Self {
        Self { manager, flow }
    }

    pub(crate) fn publish(
        self,
    ) -> Result<Manager::Output, ReresolvePublicationError<Manager::Error, Flow::Error>> {
        let output = self
            .manager
            .publish_manager_topology()
            .map_err(ReresolvePublicationError::Manager)?;
        self.flow
            .publish_flow_visibility()
            .map_err(ReresolvePublicationError::FlowAfterManager)?;
        Ok(output)
    }
}
