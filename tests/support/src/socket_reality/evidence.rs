use crate::managed_child::ProcessExit;
use socket2::{Domain, Protocol, Type};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use super::witness::{ClientSendObservation, EndpointObservation};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProbeSocketId(pub u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsErrorEvidence {
    pub raw_os_error: Option<i32>,
    pub kind: io::ErrorKind,
    pub message: String,
}

impl From<&io::Error> for OsErrorEvidence {
    fn from(error: &io::Error) -> Self {
        Self {
            raw_os_error: error.raw_os_error(),
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallResult<T> {
    Ok(T),
    OsError(OsErrorEvidence),
}

impl<T> CallResult<T> {
    pub fn from_io(result: io::Result<T>) -> Self {
        match result {
            Ok(value) => Self::Ok(value),
            Err(error) => Self::OsError(OsErrorEvidence::from(&error)),
        }
    }

    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    pub fn as_ok(&self) -> Option<&T> {
        match self {
            Self::Ok(value) => Some(value),
            Self::OsError(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketCreateEvidence {
    pub socket_id: ProbeSocketId,
    pub domain: Domain,
    pub socket_type: Type,
    pub protocol: Option<Protocol>,
    pub result: CallResult<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveApi {
    Recv,
    RecvFrom,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketCall {
    Bind {
        requested: SocketAddr,
        result: CallResult<()>,
    },
    Connect {
        target: SocketAddr,
        result: CallResult<()>,
    },
    GetSockName {
        result: CallResult<SocketAddr>,
    },
    SetReadTimeout {
        milliseconds: u64,
        result: CallResult<()>,
    },
    Send {
        destination: Option<SocketAddr>,
        bytes: Vec<u8>,
        result: CallResult<usize>,
    },
    Receive {
        api: ReceiveApi,
        result: CallResult<ReceiveEvidence>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedSocketCall {
    pub sequence: u64,
    pub call: SocketCall,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveEvidence {
    pub bytes: Vec<u8>,
    pub source: Option<SocketAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeSocketEvidence {
    pub create: SocketCreateEvidence,
    pub calls: Vec<OrderedSocketCall>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectSocketEvidence {
    pub sockets: Vec<ProbeSocketEvidence>,
}

impl DirectSocketEvidence {
    pub fn socket(&self, id: ProbeSocketId) -> Option<&ProbeSocketEvidence> {
        self.sockets
            .iter()
            .find(|socket| socket.create.socket_id == id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatagramReceiveEvidence {
    pub direct: DirectSocketEvidence,
    pub receiver: ProbeSocketId,
    pub sender: ProbeSocketId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectedFilterEvidence {
    pub direct: DirectSocketEvidence,
    pub receiver: ProbeSocketId,
    pub accepted_peer: ProbeSocketId,
    pub rejected_peer: ProbeSocketId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpDgramEvidence {
    pub direct: DirectSocketEvidence,
    pub socket: ProbeSocketId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReusePortFanoutEvidence {
    pub receiver_count: usize,
    pub successful_bind_count: usize,
    pub sent_flow_count: usize,
    pub received_flow_counts: Vec<usize>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawReceiveEvidence {
    Direct {
        direct: DirectSocketEvidence,
        socket: ProbeSocketId,
    },
    ProductionForwarder(ForwarderEvidence),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwarderProcessEvidence {
    pub label: String,
    pub command_arguments: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_status: Option<ExitStatusEvidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitStatusEvidence {
    pub code: Option<i32>,
    pub success: bool,
}

impl From<ProcessExit> for ExitStatusEvidence {
    fn from(status: ProcessExit) -> Self {
        Self {
            code: status.code,
            success: status.success,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwarderEvidence {
    pub processes: Vec<ForwarderProcessEvidence>,
    pub client_sent: Vec<u8>,
    pub client_received: CallResult<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientReceiveEvidence {
    pub probe_id: u64,
    pub payload: CallResult<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwarderLifecycleEvidence {
    pub process: ForwarderProcessEvidence,
    pub client_sends: Vec<ClientSendObservation>,
    pub client_receives: Vec<ClientReceiveEvidence>,
    pub endpoint_observations: Vec<EndpointObservation>,
    pub negative_observation_window: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealityEvidence {
    DatagramReceive(DatagramReceiveEvidence),
    ConnectedFilter(ConnectedFilterEvidence),
    IcmpDgram(IcmpDgramEvidence),
    ReusePortFanout(ReusePortFanoutEvidence),
    RawReceive(RawReceiveEvidence),
    RawFourId(ForwarderEvidence),
    Lifecycle(ForwarderLifecycleEvidence),
}
