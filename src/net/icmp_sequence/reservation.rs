use super::{
    ArmedOutboundDataSequence, OutboundRequestSequence, RekeyRequired, SessionId,
    SharedIcmpSequenceState, TransmitSequenceWindow, transmit_authority,
};
use std::sync::atomic::Ordering;

/// Borrowed proof that one worker cache contains the exact active transmit
/// session and generation selected before destination socket admission.
#[must_use = "a prepared transmit-session capability must be reserved or released"]
pub(crate) struct PreparedOutboundSession<'cache> {
    shared: &'cache SharedIcmpSequenceState,
    session: &'cache TransmitSequenceWindow,
    generation: crate::atomic_core::PreparedSessionGeneration,
    session_id: SessionId,
}

impl<'cache> PreparedOutboundSession<'cache> {
    pub(super) const fn new(
        shared: &'cache SharedIcmpSequenceState,
        session: &'cache TransmitSequenceWindow,
        generation: crate::atomic_core::PreparedSessionGeneration,
        session_id: SessionId,
    ) -> Self {
        Self {
            shared,
            session,
            generation,
            session_id,
        }
    }

    pub(crate) fn activation_recovery_already_claimed(&self) -> Result<bool, RekeyRequired> {
        if !self.generation.is_current(&self.shared.generation) {
            return Err(RekeyRequired {
                session_id: self.session_id,
            });
        }
        Ok(self
            .session
            .activation_recovery_claimed
            .load(Ordering::Acquire))
    }

    fn reserve(self) -> Result<OutboundRequestSequence<'cache>, RekeyRequired> {
        if !self.generation.is_current(&self.shared.generation) {
            return Err(RekeyRequired {
                session_id: self.session_id,
            });
        }
        let authority = transmit_authority(self.shared, self.session_id, 0);
        let sequence = self.session.reserve()?;
        Ok(OutboundRequestSequence {
            generation: self.generation.generation(),
            session_id: self.session_id,
            sequence,
            session: self.session,
            reserved: true,
            _authority: authority,
        })
    }
}

impl<'cache> crate::worker_support::StableProtocolReservation for PreparedOutboundSession<'cache> {
    type Protocol = OutboundRequestSequence<'cache>;
    type Error = RekeyRequired;

    fn reserve(self) -> Result<Self::Protocol, Self::Error> {
        PreparedOutboundSession::reserve(self)
    }
}

pub(crate) struct OutboundDataReservation<'cache> {
    prepared: Option<PreparedOutboundSession<'cache>>,
    tracked: bool,
    claim_activation_recovery: bool,
}

pub(crate) struct OutboundDataProtocol<'cache> {
    _reservation: Option<OutboundRequestSequence<'cache>>,
    evidence: Option<ArmedOutboundDataSequence<'cache>>,
    sequence: Option<u16>,
    activation_recovery_claimed: bool,
}

impl OutboundDataProtocol<'_> {
    pub(crate) const fn sequence(&self) -> Option<u16> {
        self.sequence
    }

    pub(crate) const fn activation_recovery_claimed(&self) -> bool {
        self.activation_recovery_claimed
    }

    pub(crate) fn complete_data(
        &mut self,
        sent: bool,
    ) -> Result<Option<crate::flow_state::DeferredPeerControl>, RekeyRequired> {
        self.evidence
            .take()
            .map_or(Ok(None), |evidence| evidence.complete(sent))
    }
}

impl<'cache> crate::worker_support::StableProtocolReservation for OutboundDataReservation<'cache> {
    type Protocol = OutboundDataProtocol<'cache>;
    type Error = RekeyRequired;

    fn reserve(self) -> Result<Self::Protocol, Self::Error> {
        let mut reservation = self
            .prepared
            .map(PreparedOutboundSession::reserve)
            .transpose()?;
        let sequence = reservation.as_ref().map(OutboundRequestSequence::sequence);
        let evidence = if self.tracked {
            reservation
                .as_mut()
                .map(OutboundRequestSequence::arm_data_evidence)
                .transpose()?
        } else {
            None
        };
        if let Some(reservation) = reservation.as_ref() {
            reservation.publish();
        }
        let activation_recovery_claimed = if self.claim_activation_recovery {
            reservation.as_ref().map_or(
                Ok(false),
                OutboundRequestSequence::claim_activation_recovery,
            )?
        } else {
            false
        };
        Ok(OutboundDataProtocol {
            _reservation: reservation,
            evidence,
            sequence,
            activation_recovery_claimed,
        })
    }
}

pub(crate) fn outbound_data_reservation(
    prepared: Option<PreparedOutboundSession<'_>>,
    tracked: bool,
    claim_activation_recovery: bool,
) -> OutboundDataReservation<'_> {
    OutboundDataReservation {
        prepared,
        tracked,
        claim_activation_recovery,
    }
}

impl<'cache> crate::worker_support::StableProtocolReservation
    for Option<PreparedOutboundSession<'cache>>
{
    type Protocol = Option<OutboundRequestSequence<'cache>>;
    type Error = RekeyRequired;

    fn reserve(self) -> Result<Self::Protocol, Self::Error> {
        self.map(PreparedOutboundSession::reserve).transpose()
    }
}
