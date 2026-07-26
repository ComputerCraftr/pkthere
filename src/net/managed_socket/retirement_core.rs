pub(crate) trait SocketRetirementOwner: Sized {
    type Error;

    fn retire_descriptor(&mut self) -> Result<(), Self::Error>;
    fn bind_replacement(&mut self) -> Result<(), Self::Error>;
    fn publish_retirement(self) -> Result<(), Self::Error>;
}

#[must_use]
#[derive(Debug)]
pub(super) struct SocketRetirementTransaction<Owner> {
    owner: Owner,
}

#[must_use]
#[derive(Debug)]
pub(crate) struct RetiredSocketTransaction<Owner> {
    owner: Owner,
}

#[must_use]
#[derive(Debug)]
pub(crate) struct ReplacementBoundSocketTransaction<Owner> {
    owner: Owner,
}

impl<Owner: SocketRetirementOwner> SocketRetirementTransaction<Owner> {
    pub(super) fn retire(mut self) -> Result<RetiredSocketTransaction<Owner>, Owner::Error> {
        self.owner.retire_descriptor()?;
        Ok(RetiredSocketTransaction { owner: self.owner })
    }
}

pub(super) fn retire_socket<Owner: SocketRetirementOwner>(
    owner: Owner,
) -> Result<RetiredSocketTransaction<Owner>, Owner::Error> {
    SocketRetirementTransaction { owner }.retire()
}

impl<Owner: SocketRetirementOwner> RetiredSocketTransaction<Owner> {
    pub(crate) fn replacement_bound(
        mut self,
    ) -> Result<ReplacementBoundSocketTransaction<Owner>, Owner::Error> {
        self.owner.bind_replacement()?;
        Ok(ReplacementBoundSocketTransaction { owner: self.owner })
    }

    pub(crate) fn commit(self) -> Result<(), Owner::Error> {
        self.owner.publish_retirement()
    }
}

impl<Owner: SocketRetirementOwner> ReplacementBoundSocketTransaction<Owner> {
    pub(crate) fn commit(self) -> Result<(), Owner::Error> {
        self.owner.publish_retirement()
    }
}
