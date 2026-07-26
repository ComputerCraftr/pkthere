use super::{ManagedSocket, ManagedSocketError};
use pkthere_socket_policy::{
    CapabilityEvidence, CapabilityEvidenceId, CapabilityUnsupportedReason,
    CapabilityUnverifiedReason, ResolvedSocketPolicy, SocketCreateSpec,
};
use socket2::{SockAddr, Socket};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;

pub(in crate::net) enum Created {}
pub(in crate::net) enum Configured {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::net) struct RealizationRequirements {
    required_local_bind: SocketAddr,
    expected_peer: Option<SocketAddr>,
}

impl RealizationRequirements {
    pub(in crate::net) const fn unconnected(required_local_bind: SocketAddr) -> Self {
        Self {
            required_local_bind,
            expected_peer: None,
        }
    }

    pub(in crate::net) const fn connected(
        required_local_bind: SocketAddr,
        expected_peer: SocketAddr,
    ) -> Self {
        Self {
            required_local_bind,
            expected_peer: Some(expected_peer),
        }
    }

    pub(crate) const fn required_local_bind(self) -> SocketAddr {
        self.required_local_bind
    }

    pub(crate) const fn expected_peer(self) -> Option<SocketAddr> {
        self.expected_peer
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SocketEvidenceId {
    Measured(CapabilityEvidenceId),
    Unsupported(CapabilityUnsupportedReason),
    RuntimePostconditionsOnly(CapabilityUnverifiedReason),
}

pub(in crate::net) struct RealizingSocket<State> {
    socket: Option<Socket>,
    spec: SocketCreateSpec,
    requirements: Option<RealizationRequirements>,
    _state: PhantomData<State>,
}

pub(in crate::net) struct VerifiedRealizedSocket {
    pub(super) socket: Socket,
    pub(super) policy: ResolvedSocketPolicy,
    pub(super) evidence: SocketEvidenceId,
    pub(super) requirements: RealizationRequirements,
}

#[derive(Debug)]
pub(in crate::net) enum SocketRealizationError {
    Setup(SocketCreateSpec, io::Error),
    Inspection(SocketCreateSpec, io::Error),
    LocalPostcondition {
        expected: SocketAddr,
        observed: SocketAddr,
    },
    PeerPostcondition {
        expected: Option<SocketAddr>,
        observed: Option<SocketAddr>,
    },
    PolicyPathMismatch,
    RequiredEvidenceUnverified(CapabilityUnverifiedReason),
}

impl fmt::Display for SocketRealizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(spec, source) => {
                write!(formatter, "socket setup failed for {spec:?}: {source}")
            }
            Self::Inspection(spec, source) => {
                write!(
                    formatter,
                    "socket verification failed for {spec:?}: {source}"
                )
            }
            Self::LocalPostcondition { expected, observed } => write!(
                formatter,
                "socket local-address postcondition failed: expected {expected}, observed {observed}"
            ),
            Self::PeerPostcondition { expected, observed } => write!(
                formatter,
                "socket peer postcondition failed: expected {expected:?}, observed {observed:?}"
            ),
            Self::PolicyPathMismatch => formatter.write_str(
                "resolved socket policy does not match the realized creation path or family",
            ),
            Self::RequiredEvidenceUnverified(reason) => write!(
                formatter,
                "socket lifecycle requires unavailable exact evidence: {reason:?}"
            ),
        }
    }
}

impl std::error::Error for SocketRealizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Setup(_, source) | Self::Inspection(_, source) => Some(source),
            Self::LocalPostcondition { .. }
            | Self::PeerPostcondition { .. }
            | Self::PolicyPathMismatch
            | Self::RequiredEvidenceUnverified(_) => None,
        }
    }
}

impl From<SocketRealizationError> for io::Error {
    fn from(error: SocketRealizationError) -> Self {
        io::Error::other(error)
    }
}

impl RealizingSocket<Created> {
    pub(in crate::net) fn new(socket: Socket, spec: SocketCreateSpec) -> Self {
        Self {
            socket: Some(socket),
            spec,
            requirements: None,
            _state: PhantomData,
        }
    }

    pub(in crate::net) fn configure(
        mut self,
        configure: impl FnOnce(&Socket) -> io::Result<RealizationRequirements>,
    ) -> Result<RealizingSocket<Configured>, SocketRealizationError> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            SocketRealizationError::Setup(
                self.spec,
                io::Error::other("realizing socket lost descriptor before setup"),
            )
        })?;
        let requirements =
            configure(socket).map_err(|source| SocketRealizationError::Setup(self.spec, source))?;
        Ok(RealizingSocket {
            socket: self.socket.take(),
            spec: self.spec,
            requirements: Some(requirements),
            _state: PhantomData,
        })
    }

    pub(in crate::net) fn configure_connected(
        mut self,
        peer: SocketAddr,
        configure: impl FnOnce(&Socket) -> io::Result<()>,
    ) -> Result<RealizingSocket<Configured>, SocketRealizationError> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            SocketRealizationError::Setup(
                self.spec,
                io::Error::other("realizing socket lost descriptor before connected setup"),
            )
        })?;
        configure(socket).map_err(|source| SocketRealizationError::Setup(self.spec, source))?;
        {
            let _operation =
                crate::authority::audited_operation(crate::authority::OperationId::SocketConnect);
            socket
                .connect(&SockAddr::from(peer))
                .map_err(|source| SocketRealizationError::Setup(self.spec, source))?;
        }
        let required_local_bind = inspect_local(socket)
            .map_err(|source| SocketRealizationError::Inspection(self.spec, source))?;
        Ok(RealizingSocket {
            socket: self.socket.take(),
            spec: self.spec,
            requirements: Some(RealizationRequirements::connected(
                required_local_bind,
                peer,
            )),
            _state: PhantomData,
        })
    }
}

impl RealizingSocket<Configured> {
    pub(in crate::net) fn verify(
        mut self,
        policy: ResolvedSocketPolicy,
    ) -> Result<VerifiedRealizedSocket, SocketRealizationError> {
        if policy.creation_path != self.spec.path
            || policy.disconnect.fingerprint.family != self.spec.domain
            || policy.disconnect.fingerprint.socket_type != self.spec.socket_type
        {
            return Err(SocketRealizationError::PolicyPathMismatch);
        }
        let evidence = match policy.disconnect.evidence {
            CapabilityEvidence::Measured { evidence_id, .. } => {
                SocketEvidenceId::Measured(evidence_id)
            }
            CapabilityEvidence::Unsupported(reason) => SocketEvidenceId::Unsupported(reason),
            CapabilityEvidence::Unverified(reason) => {
                if policy.reuse.reconnects_in_place() {
                    return Err(SocketRealizationError::RequiredEvidenceUnverified(reason));
                }
                SocketEvidenceId::RuntimePostconditionsOnly(reason)
            }
        };
        let socket = self.socket.as_ref().ok_or_else(|| {
            SocketRealizationError::Inspection(
                self.spec,
                io::Error::other("realizing socket lost descriptor before verification"),
            )
        })?;
        let requirements = self.requirements.ok_or_else(|| {
            SocketRealizationError::Inspection(
                self.spec,
                io::Error::other("socket verification requirements were not recorded"),
            )
        })?;
        let observed_local = inspect_local(socket)
            .map_err(|source| SocketRealizationError::Inspection(self.spec, source))?;
        if observed_local != requirements.required_local_bind {
            return Err(SocketRealizationError::LocalPostcondition {
                expected: requirements.required_local_bind,
                observed: observed_local,
            });
        }
        let observed_peer = if policy.peer_verification
            == pkthere_socket_policy::PeerVerification::ConnectSuccess
            && requirements.expected_peer.is_some()
        {
            None
        } else {
            inspect_peer(socket)
                .map_err(|source| SocketRealizationError::Inspection(self.spec, source))?
        };
        if !policy
            .peer_verification
            .accepts_observation(requirements.expected_peer, observed_peer)
        {
            return Err(SocketRealizationError::PeerPostcondition {
                expected: requirements.expected_peer,
                observed: observed_peer,
            });
        }
        let socket = self.socket.take().ok_or_else(|| {
            SocketRealizationError::Inspection(
                self.spec,
                io::Error::other("realizing socket lost descriptor during verification"),
            )
        })?;
        Ok(VerifiedRealizedSocket {
            socket,
            policy,
            evidence,
            requirements,
        })
    }
}

impl VerifiedRealizedSocket {
    pub(in crate::net) const fn required_local_bind(&self) -> SocketAddr {
        self.requirements.required_local_bind
    }

    pub(in crate::net) fn into_managed(self) -> Result<ManagedSocket, ManagedSocketError> {
        ManagedSocket::from_verified_realization(self)
    }
}

fn inspect_local(socket: &Socket) -> io::Result<SocketAddr> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketLocalInspection);
    socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("verified socket has a non-INET local address"))
}

fn inspect_peer(socket: &Socket) -> io::Result<Option<SocketAddr>> {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::SocketPeerInspection);
    match socket.peer_addr() {
        Ok(peer) => Ok(peer.as_socket()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotConnected | io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
