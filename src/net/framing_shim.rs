use crate::net::packet_headers::{
    ICMP_CONTROL_CHALLENGE_ACK, ICMP_CONTROL_CHALLENGE_NEGOTIATE, ICMP_CONTROL_GENERATION_ADVANCE,
    ICMP_CONTROL_GENERATION_ADVANCE_ACK, ICMP_CONTROL_NEGOTIATE, ICMP_CONTROL_NEGOTIATE_ACK,
    ICMP_CONTROL_RESET_REQUIRED, ICMP_CONTROL_SESSION_ACTIVATED, ICMP_TUNNEL_CHALLENGE_BODY_LEN,
    ICMP_TUNNEL_CONTROL_HEADER_LEN, ICMP_TUNNEL_CONTROL_VERSION,
    ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN, ICMP_TUNNEL_NEGOTIATE_BODY_LEN,
    ICMP_TUNNEL_POOL_GENERATION_LEN, ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN,
    ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN, ICMP_TUNNEL_SESSION_ID_LEN,
    ICMP_TUNNEL_SESSION_KEY_LEN, ICMP_TUNNEL_SESSION_ORDINAL_LEN, IcmpMalformedReason,
    SHIM_IS_CADENCE, SHIM_IS_DATA, SHIM_SOURCE_ID_EQUALS_HEADER, icmp_control_body_len,
};
use pkthere_wire::be16_16;
use std::io;
use std::num::NonZeroU16;
use std::num::NonZeroU64;

const ICMP_TUNNEL_FLAGS_LEN: usize = size_of::<u8>();
const ICMP_TUNNEL_EXPLICIT_SOURCE_LEN: usize = size_of::<u16>();
const ICMP_TUNNEL_ALLOWED_FLAGS: u8 = SHIM_IS_DATA | SHIM_IS_CADENCE | SHIM_SOURCE_ID_EQUALS_HEADER;
pub(crate) const ICMP_TUNNEL_EXPLICIT_DATA_LEN: usize =
    ICMP_TUNNEL_FLAGS_LEN + ICMP_TUNNEL_EXPLICIT_SOURCE_LEN + ICMP_TUNNEL_SESSION_ID_LEN;
pub(crate) const ICMP_TUNNEL_COMPACT_CONTROL_LEN: usize =
    ICMP_TUNNEL_FLAGS_LEN + ICMP_TUNNEL_NEGOTIATE_BODY_LEN;
pub(crate) const ICMP_TUNNEL_COMPACT_RESET_REQUIRED_LEN: usize =
    ICMP_TUNNEL_FLAGS_LEN + ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN;
pub(crate) const ICMP_TUNNEL_EXPLICIT_RESET_REQUIRED_LEN: usize =
    ICMP_TUNNEL_FLAGS_LEN + ICMP_TUNNEL_EXPLICIT_SOURCE_LEN + ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN;
pub(crate) const ICMP_TUNNEL_SHIM_MAX_LEN: usize =
    ICMP_TUNNEL_FLAGS_LEN + ICMP_TUNNEL_EXPLICIT_SOURCE_LEN + ICMP_TUNNEL_CHALLENGE_BODY_LEN;
pub(crate) const ICMP_TUNNEL_COMPACT_MAX_CONTROL_LEN: usize =
    ICMP_TUNNEL_FLAGS_LEN + ICMP_TUNNEL_CHALLENGE_BODY_LEN;
const _: () = assert!(ICMP_TUNNEL_COMPACT_CONTROL_LEN == 25);
const _: () = assert!(ICMP_TUNNEL_COMPACT_RESET_REQUIRED_LEN == 30);
const _: () = assert!(ICMP_TUNNEL_EXPLICIT_RESET_REQUIRED_LEN == 32);
const _: () = assert!(ICMP_TUNNEL_COMPACT_MAX_CONTROL_LEN == 64);
const _: () = assert!(ICMP_TUNNEL_SHIM_MAX_LEN == 66);
const _: () = assert!(ICMP_TUNNEL_EXPLICIT_DATA_LEN == 11);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SessionId(NonZeroU64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct PoolGeneration(NonZeroU64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SessionKey {
    pool_generation: PoolGeneration,
    ordinal: u32,
    session_id: SessionId,
}

impl SessionKey {
    pub(crate) const fn new(
        pool_generation: u64,
        ordinal: u32,
        session_id: SessionId,
    ) -> Option<Self> {
        if session_id.response_session_id().is_none() {
            return None;
        }
        match PoolGeneration::new(pool_generation) {
            Some(pool_generation) => Some(Self {
                pool_generation,
                ordinal,
                session_id,
            }),
            None => None,
        }
    }

    pub(crate) const fn initial(session_id: SessionId) -> Option<Self> {
        if session_id.response_session_id().is_none() {
            return None;
        }
        Some(Self {
            pool_generation: PoolGeneration(session_id.0),
            ordinal: 0,
            session_id,
        })
    }

    pub(crate) const fn pool_generation(self) -> u64 {
        self.pool_generation.get()
    }

    pub(crate) const fn generation(self) -> PoolGeneration {
        self.pool_generation
    }

    pub(crate) const fn ordinal(self) -> u32 {
        self.ordinal
    }

    pub(crate) const fn session_id(self) -> SessionId {
        self.session_id
    }

    pub(crate) fn response_session_id(self) -> SessionId {
        match self.session_id.response_session_id() {
            Some(session_id) => session_id,
            None => crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "validated ICMP session key lost its reserved response identity"
            )),
        }
    }

    pub(crate) fn response_key(self) -> Self {
        Self {
            pool_generation: self.pool_generation,
            ordinal: self.ordinal,
            session_id: self.response_session_id(),
        }
    }

    pub(crate) fn fresh_initial() -> io::Result<Self> {
        let pool_generation = PoolGeneration::fresh()?;
        let session_id = SessionId::fresh()?;
        Ok(Self {
            pool_generation,
            ordinal: 0,
            session_id,
        })
    }

    pub(crate) fn fresh_in_generation(
        pool_generation: PoolGeneration,
        ordinal: u32,
    ) -> io::Result<Self> {
        Ok(Self {
            pool_generation,
            ordinal,
            session_id: SessionId::fresh()?,
        })
    }

    pub(crate) fn with_fresh_generation(session_id: SessionId) -> io::Result<Self> {
        if session_id.response_session_id().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ICMP session ID lacks response identity headroom",
            ));
        }
        Ok(Self {
            pool_generation: PoolGeneration::fresh()?,
            ordinal: 0,
            session_id,
        })
    }

    #[cfg(test)]
    pub(crate) const fn for_tests() -> Self {
        match Self::initial(SessionId::for_tests()) {
            Some(key) => key,
            None => panic!("fixed test session reserves a response identity"),
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_tests_with(session_id: SessionId, ordinal: u32) -> Self {
        match Self::new(1, ordinal, session_id) {
            Some(key) => key,
            None => panic!("test session key reserves a response identity"),
        }
    }
}

mod identity;
#[cfg(test)]
use identity::SessionIdentityAllocator;
pub(crate) type HandshakeInstance = SessionId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdNegotiation {
    Negotiate {
        reply_id: NonZeroU16,
        session_key: SessionKey,
        reset_challenge: u64,
    },
    Acknowledge {
        reply_id: NonZeroU16,
        session_key: SessionKey,
        reset_challenge: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RejectedFrameKind {
    Data = 1,
    Negotiate = 2,
}

impl RejectedFrameKind {
    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Data),
            2 => Some(Self::Negotiate),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectedFrameEvidence {
    Data {
        session: SessionId,
        sequence: u16,
    },
    Negotiate {
        candidate: SessionKey,
        sequence: u16,
    },
}

impl RejectedFrameEvidence {
    pub(crate) const fn kind(self) -> RejectedFrameKind {
        match self {
            Self::Data { .. } => RejectedFrameKind::Data,
            Self::Negotiate { .. } => RejectedFrameKind::Negotiate,
        }
    }

    pub(crate) const fn session_id(self) -> SessionId {
        match self {
            Self::Data { session, .. } => session,
            Self::Negotiate { candidate, .. } => candidate.session_id(),
        }
    }

    pub(crate) const fn sequence(self) -> u16 {
        match self {
            Self::Data { sequence, .. } | Self::Negotiate { sequence, .. } => sequence,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResetRequired {
    rejected_kind: RejectedFrameKind,
    rejected_session: SessionId,
    rejected_sequence: u16,
    receiver_generation: Option<PoolGeneration>,
    challenge: NonZeroU64,
}

impl ResetRequired {
    #[cfg(test)]
    pub(crate) const fn new(
        rejected_session: SessionId,
        rejected_sequence: u16,
        receiver_generation: Option<PoolGeneration>,
        challenge: NonZeroU64,
    ) -> Self {
        Self::for_evidence(
            RejectedFrameEvidence::Data {
                session: rejected_session,
                sequence: rejected_sequence,
            },
            receiver_generation,
            challenge,
        )
    }

    pub(crate) const fn for_evidence(
        evidence: RejectedFrameEvidence,
        receiver_generation: Option<PoolGeneration>,
        challenge: NonZeroU64,
    ) -> Self {
        Self {
            rejected_kind: evidence.kind(),
            rejected_session: evidence.session_id(),
            rejected_sequence: evidence.sequence(),
            receiver_generation,
            challenge,
        }
    }

    pub(crate) const fn rejected_kind(self) -> RejectedFrameKind {
        self.rejected_kind
    }

    pub(crate) const fn rejected_session(self) -> SessionId {
        self.rejected_session
    }

    pub(crate) const fn rejected_sequence(self) -> u16 {
        self.rejected_sequence
    }

    pub(crate) const fn receiver_generation(self) -> Option<PoolGeneration> {
        self.receiver_generation
    }

    pub(crate) const fn challenge(self) -> NonZeroU64 {
        self.challenge
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChallengeControl {
    reply_id: NonZeroU16,
    challenge: NonZeroU64,
    receiver_generation: Option<PoolGeneration>,
    rejected: RejectedFrameEvidence,
    new_session: SessionKey,
}

impl ChallengeControl {
    pub(crate) const fn new(
        reply_id: u16,
        challenge: NonZeroU64,
        receiver_generation: Option<PoolGeneration>,
        rejected: RejectedFrameEvidence,
        new_session: SessionKey,
    ) -> Option<Self> {
        match NonZeroU16::new(reply_id) {
            Some(reply_id) => Some(Self {
                reply_id,
                challenge,
                receiver_generation,
                rejected,
                new_session,
            }),
            None => None,
        }
    }

    pub(crate) const fn reply_id(self) -> u16 {
        self.reply_id.get()
    }

    pub(crate) const fn challenge(self) -> NonZeroU64 {
        self.challenge
    }

    pub(crate) const fn receiver_generation(self) -> Option<PoolGeneration> {
        self.receiver_generation
    }

    pub(crate) const fn rejected(self) -> RejectedFrameEvidence {
        self.rejected
    }

    pub(crate) const fn new_session(self) -> SessionKey {
        self.new_session
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GenerationAdvance {
    current: SessionKey,
    proposed_generation: PoolGeneration,
}

impl GenerationAdvance {
    pub(crate) const fn new(current: SessionKey, proposed_generation: PoolGeneration) -> Self {
        Self {
            current,
            proposed_generation,
        }
    }

    pub(crate) const fn current(self) -> SessionKey {
        self.current
    }

    pub(crate) const fn proposed_generation(self) -> PoolGeneration {
        self.proposed_generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionActivated {
    session_key: SessionKey,
    accepted_sequence: u16,
}

impl SessionActivated {
    pub(crate) const fn new(session_key: SessionKey, accepted_sequence: u16) -> Self {
        Self {
            session_key,
            accepted_sequence,
        }
    }

    pub(crate) const fn session_key(self) -> SessionKey {
        self.session_key
    }

    pub(crate) const fn accepted_sequence(self) -> u16 {
        self.accepted_sequence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpTunnelControl {
    Negotiate(ReplyIdNegotiation),
    NegotiateAck(ReplyIdNegotiation),
    ResetRequired(ResetRequired),
    ChallengeNegotiate(ChallengeControl),
    ChallengeAck(ChallengeControl),
    GenerationAdvance(GenerationAdvance),
    GenerationAdvanceAck(GenerationAdvance),
    SessionActivated(SessionActivated),
}

impl IcmpTunnelControl {
    pub(crate) const fn session_id(self) -> SessionId {
        match self {
            Self::Negotiate(negotiation) | Self::NegotiateAck(negotiation) => {
                negotiation.session_key().session_id()
            }
            Self::ResetRequired(reset) => reset.rejected_session(),
            Self::ChallengeNegotiate(challenge) | Self::ChallengeAck(challenge) => {
                challenge.new_session().session_id()
            }
            Self::GenerationAdvance(advance) | Self::GenerationAdvanceAck(advance) => {
                advance.current().session_id()
            }
            Self::SessionActivated(activated) => activated.session_key().session_id(),
        }
    }
}

impl ReplyIdNegotiation {
    #[inline]
    #[cfg(test)]
    pub(crate) const fn negotiate(reply_id: u16) -> Option<Self> {
        Self::negotiate_with_instance(
            reply_id,
            SessionId(NonZeroU64::new(1).expect("one is nonzero")),
        )
    }

    #[inline]
    pub(crate) fn fresh_negotiation(reply_id: u16) -> io::Result<Option<Self>> {
        Ok(Self::negotiate_with_key(
            reply_id,
            SessionKey::fresh_initial()?,
        ))
    }

    #[inline]
    #[cfg(test)]
    pub(crate) const fn negotiate_with_instance(
        reply_id: u16,
        instance: HandshakeInstance,
    ) -> Option<Self> {
        match SessionKey::initial(instance) {
            Some(session_key) => Self::negotiate_with_key(reply_id, session_key),
            None => None,
        }
    }

    #[inline]
    pub(crate) const fn negotiate_with_key(reply_id: u16, session_key: SessionKey) -> Option<Self> {
        Self::negotiate_with_key_and_challenge(reply_id, session_key, 0)
    }

    #[inline]
    pub(crate) const fn negotiate_with_key_and_challenge(
        reply_id: u16,
        session_key: SessionKey,
        reset_challenge: u64,
    ) -> Option<Self> {
        match NonZeroU16::new(reply_id) {
            Some(reply_id) => Some(Self::Negotiate {
                reply_id,
                session_key,
                reset_challenge,
            }),
            None => None,
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) const fn acknowledge(reply_id: u16) -> Option<Self> {
        Self::acknowledge_instance(
            reply_id,
            SessionId(NonZeroU64::new(1).expect("one is nonzero")),
        )
    }

    #[inline]
    #[cfg(test)]
    pub(crate) const fn acknowledge_instance(
        reply_id: u16,
        instance: HandshakeInstance,
    ) -> Option<Self> {
        match SessionKey::initial(instance) {
            Some(session_key) => Self::acknowledge_key(reply_id, session_key),
            None => None,
        }
    }

    #[inline]
    #[cfg(test)]
    pub(crate) const fn acknowledge_key(reply_id: u16, session_key: SessionKey) -> Option<Self> {
        Self::acknowledge_key_and_challenge(reply_id, session_key, 0)
    }

    #[inline]
    pub(crate) const fn acknowledge_key_and_challenge(
        reply_id: u16,
        session_key: SessionKey,
        reset_challenge: u64,
    ) -> Option<Self> {
        match NonZeroU16::new(reply_id) {
            Some(reply_id) => Some(Self::Acknowledge {
                reply_id,
                session_key,
                reset_challenge,
            }),
            None => None,
        }
    }

    #[inline]
    pub(crate) const fn reply_id(self) -> u16 {
        match self {
            Self::Negotiate { reply_id, .. } | Self::Acknowledge { reply_id, .. } => reply_id.get(),
        }
    }

    #[inline]
    pub(crate) const fn instance(self) -> HandshakeInstance {
        self.session_key().session_id()
    }

    #[inline]
    pub(crate) const fn session_key(self) -> SessionKey {
        match self {
            Self::Negotiate { session_key, .. } | Self::Acknowledge { session_key, .. } => {
                session_key
            }
        }
    }

    #[inline]
    pub(crate) const fn reset_challenge(self) -> u64 {
        match self {
            Self::Negotiate {
                reset_challenge, ..
            }
            | Self::Acknowledge {
                reset_challenge, ..
            } => reset_challenge,
        }
    }

    #[inline]
    pub(crate) const fn is_negotiate(self) -> bool {
        matches!(self, Self::Negotiate { .. })
    }

    #[inline]
    pub(crate) const fn is_ack(self) -> bool {
        matches!(self, Self::Acknowledge { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpTunnelFrameKind {
    Cadence,
    UserPayload,
    #[cfg(test)]
    SessionControl,
    #[cfg(test)]
    ResetRequired(ResetRequired),
}

#[cfg(test)]
pub(crate) fn parse_icmp_reply_negotiation(
    shim: u8,
    payload: &[u8],
) -> Result<Option<ReplyIdNegotiation>, IcmpMalformedReason> {
    if (shim & SHIM_IS_CADENCE) != 0 {
        if shim & SHIM_IS_DATA != 0 || shim & !ICMP_TUNNEL_ALLOWED_FLAGS != 0 || !payload.is_empty()
        {
            return Err(IcmpMalformedReason::IllegalFrameFlags);
        }
        return Ok(None);
    }
    if (shim & SHIM_IS_DATA) != 0 {
        if shim & !ICMP_TUNNEL_ALLOWED_FLAGS != 0 {
            return Err(IcmpMalformedReason::IllegalFrameFlags);
        }
        return Ok(None);
    }
    match parse_icmp_control(shim, payload)? {
        Some(IcmpTunnelControl::Negotiate(negotiation))
        | Some(IcmpTunnelControl::NegotiateAck(negotiation)) => Ok(Some(negotiation)),
        Some(
            IcmpTunnelControl::ResetRequired(_)
            | IcmpTunnelControl::ChallengeNegotiate(_)
            | IcmpTunnelControl::ChallengeAck(_)
            | IcmpTunnelControl::GenerationAdvance(_)
            | IcmpTunnelControl::GenerationAdvanceAck(_)
            | IcmpTunnelControl::SessionActivated(_),
        )
        | None => Ok(None),
    }
}

#[cfg(test)]
pub(crate) fn parse_icmp_reset_required(
    shim: u8,
    payload: &[u8],
) -> Result<Option<ResetRequired>, IcmpMalformedReason> {
    match parse_icmp_control(shim, payload)? {
        Some(IcmpTunnelControl::ResetRequired(reset)) => Ok(Some(reset)),
        Some(_) | None => Ok(None),
    }
}

pub(crate) fn parse_icmp_control(
    shim: u8,
    payload: &[u8],
) -> Result<Option<IcmpTunnelControl>, IcmpMalformedReason> {
    if shim & (SHIM_IS_DATA | SHIM_IS_CADENCE) != 0 {
        if shim & !ICMP_TUNNEL_ALLOWED_FLAGS != 0
            || shim & (SHIM_IS_DATA | SHIM_IS_CADENCE) == (SHIM_IS_DATA | SHIM_IS_CADENCE)
        {
            return Err(IcmpMalformedReason::IllegalFrameFlags);
        }
        return Ok(None);
    }
    if shim & !ICMP_TUNNEL_ALLOWED_FLAGS != 0
        || payload.len() < ICMP_TUNNEL_CONTROL_HEADER_LEN
        || payload[0] != ICMP_TUNNEL_CONTROL_VERSION
    {
        return Err(IcmpMalformedReason::InvalidSessionControlFlags);
    }
    let opcode = payload[1];
    match opcode {
        ICMP_CONTROL_NEGOTIATE | ICMP_CONTROL_NEGOTIATE_ACK => {
            require_control_len(payload, ICMP_TUNNEL_NEGOTIATE_BODY_LEN)?;
            let reply_id = read_nonzero_reply_id(payload, 2)?;
            let session_key = read_session_key(payload, 4)?;
            let negotiation = if opcode == ICMP_CONTROL_NEGOTIATE {
                ReplyIdNegotiation::negotiate_with_key(reply_id, session_key)
            } else {
                ReplyIdNegotiation::acknowledge_key_and_challenge(reply_id, session_key, 0)
            }
            .ok_or(IcmpMalformedReason::ZeroReplyId)?;
            Ok(Some(if opcode == ICMP_CONTROL_NEGOTIATE {
                IcmpTunnelControl::Negotiate(negotiation)
            } else {
                IcmpTunnelControl::NegotiateAck(negotiation)
            }))
        }
        ICMP_CONTROL_RESET_REQUIRED => {
            require_control_len(payload, ICMP_TUNNEL_RESET_REQUIRED_BODY_LEN)?;
            let rejected_kind = RejectedFrameKind::from_wire(payload[2])
                .ok_or(IcmpMalformedReason::InvalidSessionControlFlags)?;
            let rejected_session = read_session_id(payload, 3)?;
            let rejected_sequence = read_u16(payload, 11);
            let receiver_generation = PoolGeneration::new(read_u64(payload, 13));
            let challenge = NonZeroU64::new(read_u64(payload, 21))
                .ok_or(IcmpMalformedReason::InvalidSessionControlFlags)?;
            Ok(Some(IcmpTunnelControl::ResetRequired(ResetRequired {
                rejected_kind,
                rejected_session,
                rejected_sequence,
                receiver_generation,
                challenge,
            })))
        }
        ICMP_CONTROL_CHALLENGE_NEGOTIATE | ICMP_CONTROL_CHALLENGE_ACK => {
            require_control_len(payload, ICMP_TUNNEL_CHALLENGE_BODY_LEN)?;
            let reply_id = read_nonzero_reply_id(payload, 2)?;
            let challenge = NonZeroU64::new(read_u64(payload, 4))
                .ok_or(IcmpMalformedReason::InvalidSessionControlFlags)?;
            let receiver_generation = PoolGeneration::new(read_u64(payload, 12));
            let rejected_kind = RejectedFrameKind::from_wire(payload[20])
                .ok_or(IcmpMalformedReason::InvalidSessionControlFlags)?;
            let rejected_wire_key = read_wire_rejected_key(payload, 21, rejected_kind)?;
            let rejected_sequence = read_u16(payload, 41);
            let rejected = match rejected_kind {
                RejectedFrameKind::Data => RejectedFrameEvidence::Data {
                    session: rejected_wire_key.session_id(),
                    sequence: rejected_sequence,
                },
                RejectedFrameKind::Negotiate => RejectedFrameEvidence::Negotiate {
                    candidate: rejected_wire_key,
                    sequence: rejected_sequence,
                },
            };
            let new_session = read_session_key(payload, 43)?;
            let control = ChallengeControl::new(
                reply_id,
                challenge,
                receiver_generation,
                rejected,
                new_session,
            )
            .ok_or(IcmpMalformedReason::ZeroReplyId)?;
            Ok(Some(if opcode == ICMP_CONTROL_CHALLENGE_NEGOTIATE {
                IcmpTunnelControl::ChallengeNegotiate(control)
            } else {
                IcmpTunnelControl::ChallengeAck(control)
            }))
        }
        ICMP_CONTROL_GENERATION_ADVANCE | ICMP_CONTROL_GENERATION_ADVANCE_ACK => {
            require_control_len(payload, ICMP_TUNNEL_GENERATION_ADVANCE_BODY_LEN)?;
            let current = read_session_key(payload, 2)?;
            let proposed_generation = PoolGeneration::new(read_u64(payload, 22))
                .ok_or(IcmpMalformedReason::InvalidSessionControlFlags)?;
            let advance = GenerationAdvance::new(current, proposed_generation);
            Ok(Some(if opcode == ICMP_CONTROL_GENERATION_ADVANCE {
                IcmpTunnelControl::GenerationAdvance(advance)
            } else {
                IcmpTunnelControl::GenerationAdvanceAck(advance)
            }))
        }
        ICMP_CONTROL_SESSION_ACTIVATED => {
            require_control_len(payload, ICMP_TUNNEL_SESSION_ACTIVATED_BODY_LEN)?;
            Ok(Some(IcmpTunnelControl::SessionActivated(
                SessionActivated::new(read_session_key(payload, 2)?, read_u16(payload, 22)),
            )))
        }
        _ => Err(IcmpMalformedReason::InvalidSessionControlFlags),
    }
}

fn require_control_len(payload: &[u8], expected: usize) -> Result<(), IcmpMalformedReason> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(IcmpMalformedReason::SessionControlReplyIdLength)
    }
}

fn read_nonzero_reply_id(payload: &[u8], offset: usize) -> Result<u16, IcmpMalformedReason> {
    let value = read_u16(payload, offset);
    if value == 0 {
        Err(IcmpMalformedReason::ZeroReplyId)
    } else {
        Ok(value)
    }
}

fn read_session_id(payload: &[u8], offset: usize) -> Result<SessionId, IcmpMalformedReason> {
    SessionId::new(read_u64(payload, offset)).ok_or(IcmpMalformedReason::ZeroSessionId)
}

fn read_session_key(payload: &[u8], offset: usize) -> Result<SessionKey, IcmpMalformedReason> {
    let generation = read_u64(payload, offset);
    let ordinal = read_u32(payload, offset + ICMP_TUNNEL_POOL_GENERATION_LEN);
    let session_id = read_session_id(
        payload,
        offset + ICMP_TUNNEL_POOL_GENERATION_LEN + ICMP_TUNNEL_SESSION_ORDINAL_LEN,
    )?;
    SessionKey::new(generation, ordinal, session_id)
        .ok_or(IcmpMalformedReason::InvalidSessionControlFlags)
}

fn read_wire_rejected_key(
    payload: &[u8],
    offset: usize,
    kind: RejectedFrameKind,
) -> Result<SessionKey, IcmpMalformedReason> {
    match kind {
        RejectedFrameKind::Negotiate => read_session_key(payload, offset),
        RejectedFrameKind::Data => {
            let generation = read_u64(payload, offset);
            let ordinal = read_u32(payload, offset + ICMP_TUNNEL_POOL_GENERATION_LEN);
            if generation != 0 || ordinal != 0 {
                return Err(IcmpMalformedReason::InvalidSessionControlFlags);
            }
            let session = read_session_id(
                payload,
                offset + ICMP_TUNNEL_POOL_GENERATION_LEN + ICMP_TUNNEL_SESSION_ORDINAL_LEN,
            )?;
            SessionKey::initial(session).ok_or(IcmpMalformedReason::InvalidSessionControlFlags)
        }
    }
}

fn read_u16(payload: &[u8], offset: usize) -> u16 {
    let Some([high, low]) = payload.get(offset..offset.saturating_add(size_of::<u16>())) else {
        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "validated ICMP control u16 field exceeded its packet extent"
        ));
    };
    be16_16(*high, *low)
}

fn read_u32(payload: &[u8], offset: usize) -> u32 {
    let Some([a, b, c, d]) = payload.get(offset..offset.saturating_add(size_of::<u32>())) else {
        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "validated ICMP control u32 field exceeded its packet extent"
        ));
    };
    u32::from_be_bytes([*a, *b, *c, *d])
}

fn read_u64(payload: &[u8], offset: usize) -> u64 {
    let Some([a, b, c, d, e, f, g, h]) =
        payload.get(offset..offset.saturating_add(size_of::<u64>()))
    else {
        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "validated ICMP control u64 field exceeded its packet extent"
        ));
    };
    u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h])
}

mod encode;
pub(crate) use encode::{
    encode_icmp_control_prefix_with_source, encode_icmp_tunnel_prefix_with_source,
};

#[cfg(test)]
mod tests;
