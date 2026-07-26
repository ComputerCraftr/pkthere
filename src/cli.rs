use crate::endpoint::LogicalEndpoint;
use crate::net::socket::resolve_first;

use std::io;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::process;

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_STATS_INTERVAL_MINS: u32 = 60;
const DEFAULT_MAX_PAYLOAD: usize = 1500;
const DEFAULT_ICMP_SYNC_PPS: u32 = 0;
pub(crate) const DEFAULT_ICMP_SESSION_POOL_SIZE: usize = 4;
pub(crate) const MAX_ICMP_SESSION_POOL_SIZE: usize = 32;
pub(crate) const MAX_ICMP_HANDSHAKE_TIMEOUT_SECS: u64 = 3_600;
const DEFAULT_WORKERS: usize = 1;
pub(crate) const MAX_WORKER_PAIRS: usize = 256;
pub(crate) const MAX_FORWARDING_THREADS: usize = MAX_WORKER_PAIRS * 2;
const DEFAULT_RERESOLVE_SECS: u64 = 0;

pub(crate) use pkthere_socket_policy::TimeoutAction;
pub(crate) use pkthere_wire::SupportedProtocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReresolveMode {
    None,
    Upstream,
    Listen,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerFlowMode {
    SharedFlow,
    SingleFlow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListenMode {
    Fixed,
    Dynamic, // WildcardLearn for ICMP, Ephemeral for UDP
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum IcmpReplyIdRequest {
    #[default]
    Default,
    Wildcard,
    Fixed(u16),
}

impl IcmpReplyIdRequest {
    #[inline]
    pub const fn requested_socket_id(self) -> u16 {
        match self {
            Self::Fixed(id) => id,
            Self::Default | Self::Wildcard => 0,
        }
    }

    #[inline]
    pub fn resolved_reply_id(self, realized_id: u16) -> Option<u16> {
        match self {
            Self::Fixed(id) => Some(id),
            Self::Default | Self::Wildcard if realized_id != 0 => Some(realized_id),
            Self::Default | Self::Wildcard => None,
        }
    }
}

impl WorkerFlowMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "shared-flow" => Some(Self::SharedFlow),
            "single-flow" => Some(Self::SingleFlow),
            _ => None,
        }
    }

    #[inline]
    pub const fn to_str(self) -> &'static str {
        match self {
            Self::SharedFlow => "shared-flow",
            Self::SingleFlow => "single-flow",
        }
    }
}

impl std::fmt::Display for WorkerFlowMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl ReresolveMode {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Some(ReresolveMode::None),
            "upstream" => Some(ReresolveMode::Upstream),
            "listen" => Some(ReresolveMode::Listen),
            "both" => Some(ReresolveMode::Both),
            _ => None,
        }
    }

    #[inline]
    pub const fn allow_upstream(self) -> bool {
        matches!(self, ReresolveMode::Upstream | ReresolveMode::Both)
    }

    #[inline]
    pub const fn allow_listen(self) -> bool {
        matches!(self, ReresolveMode::Listen | ReresolveMode::Both)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DebugBehavior {
    pub client_unconnected: bool,
    pub upstream_unconnected: bool,
    pub fast_stats: bool,
    pub icmp_kernel_echo_self_handshake: bool,
    pub force_raw_icmp_wildcard_upstream: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DebugLogs {
    pub drops: bool,
    pub handshake: bool,
    pub handles: bool,
    pub packets: bool,
    pub packet_dump: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeOptions {
    pub workers: usize,                   // listener/upstream worker pairs
    pub worker_flow_mode: WorkerFlowMode, // shared-flow | single-flow
    pub timeout_secs: u64,                // idle timeout for single client
    pub icmp_handshake_timeout_secs: u64, // reply-ID handshake timeout
    pub on_timeout: TimeoutAction,        // Drop | Exit
    pub stats_interval_mins: u32,         // JSON stats print interval (0 disables stats thread)
    pub max_payload: usize,               // optional user-specified MTU/payload limit
    pub icmp_sync_pps: u32, // 0 = disabled; >0 targets a best-effort ICMP request rate
    pub icmp_session_pool_size: usize, // ready reserve sessions per ICMP transmit leg
    pub reresolve_secs: u64, // 0 = disabled
    pub reresolve_mode: ReresolveMode, // which side(s) to re-resolve
    pub debug_reresolve_address_file: Option<PathBuf>,
    #[cfg(unix)]
    pub run_as_user: Option<String>,
    #[cfg(unix)]
    pub run_as_group: Option<String>,
    pub debug_behavior: DebugBehavior,
    pub debug_logs: DebugLogs,
}

#[derive(Clone, Debug)]
pub(crate) struct RequestedConfig {
    pub listen_request: LogicalEndpoint, // CLI UDP port or ICMP listener id
    pub listener_source_id_request: IcmpReplyIdRequest, // ICMP listener outbound source-ID preference
    pub listener_reply_id_request: IcmpReplyIdRequest,  // ICMP listener reply-ID preference
    pub listen_proto: SupportedProtocol,                // UDP | ICMP
    pub listen_mode: ListenMode,                        // Fixed or Dynamic (:0)
    pub listen_str: String,                             // original --here host:port string
    pub upstream_request: LogicalEndpoint, // CLI remote UDP port or ICMP peer/listener id
    pub upstream_source_id_request: IcmpReplyIdRequest, // ICMP upstream outbound source-ID preference
    pub upstream_reply_id_request: IcmpReplyIdRequest,  // ICMP upstream reply-ID preference
    pub upstream_proto: SupportedProtocol,              // UDP | ICMP
    pub upstream_str: String,                           // FQDN:port or IP:port
    pub options: RuntimeOptions,
}

impl Deref for RequestedConfig {
    type Target = RuntimeOptions;

    fn deref(&self) -> &Self::Target {
        &self.options
    }
}

impl DerefMut for RequestedConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.options
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfig {
    pub listen: LogicalEndpoint, // actual bound UDP port or ICMP local id
    pub listener_source_id_request: IcmpReplyIdRequest, // ICMP listener outbound source-ID preference
    pub listener_reply_id_request: IcmpReplyIdRequest,  // ICMP listener reply-ID preference
    pub listen_proto: SupportedProtocol,                // UDP | ICMP
    pub listen_mode: ListenMode,                        // Fixed or Dynamic (:0)
    pub listen_str: String,                             // original --here host:port string
    pub upstream: LogicalEndpoint,                      // remote UDP port or ICMP peer/listener id
    pub upstream_source_id_request: IcmpReplyIdRequest, // ICMP upstream outbound source-ID preference
    pub upstream_reply_id_request: IcmpReplyIdRequest,  // ICMP upstream reply-ID preference
    pub upstream_proto: SupportedProtocol,              // UDP | ICMP
    pub upstream_str: String,                           // FQDN:port or IP:port
    pub options: RuntimeOptions,
}

impl Deref for RuntimeConfig {
    type Target = RuntimeOptions;

    fn deref(&self) -> &Self::Target {
        &self.options
    }
}

impl DerefMut for RuntimeConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.options
    }
}

impl RuntimeConfig {
    #[inline]
    pub(crate) const fn is_icmp_sync_enabled(&self) -> bool {
        self.options.icmp_sync_pps > 0 && matches!(self.upstream_proto, SupportedProtocol::ICMP)
    }
}

pub(crate) fn realize_config(
    requested: RequestedConfig,
    listen: LogicalEndpoint,
) -> io::Result<RuntimeConfig> {
    if requested.listen_proto == SupportedProtocol::ICMP
        && requested.listen_mode == ListenMode::Fixed
        && requested.listen_request.id() != listen.id()
    {
        return Err(io::Error::other(format!(
            "ICMP fixed-id listener requested id {} but socket local id is {}; use a raw-capable deployment or --here ICMP:host:0 for wildcard-learn mode",
            requested.listen_request.id(),
            listen.id()
        )));
    }

    if listen.to_socket_addr() == requested.upstream_request.to_socket_addr() {
        return Err(io::Error::other(format!(
            "Port conflict: listener address {} is identical to upstream destination address {}; they must be different to avoid loops",
            listen.to_socket_addr(),
            requested.upstream_request.to_socket_addr()
        )));
    }

    Ok(RuntimeConfig {
        listen,
        listener_source_id_request: requested.listener_source_id_request,
        listener_reply_id_request: requested.listener_reply_id_request,
        listen_proto: requested.listen_proto,
        listen_mode: requested.listen_mode,
        listen_str: requested.listen_str,
        upstream: requested.upstream_request,
        upstream_source_id_request: requested.upstream_source_id_request,
        upstream_reply_id_request: requested.upstream_reply_id_request,
        upstream_proto: requested.upstream_proto,
        upstream_str: requested.upstream_str,
        options: requested.options,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedEndpointTarget {
    proto: SupportedProtocol,
    host: String,
    id: u16,
}

#[inline]
fn id_request_from_u16(id: u16) -> IcmpReplyIdRequest {
    if id == 0 {
        IcmpReplyIdRequest::Wildcard
    } else {
        IcmpReplyIdRequest::Fixed(id)
    }
}

#[inline]
fn parse_proto_and_rest<'a>(
    s: &'a str,
    flag: &str,
) -> Result<(SupportedProtocol, &'a str), String> {
    s.split_once(':')
        .and_then(|(proto_str, rest)| SupportedProtocol::from_str(proto_str).map(|p| (p, rest)))
        .ok_or_else(|| format!("{flag} must be UDP:<host>:<id> or ICMP:<host>:<id> (got '{s}')"))
}

fn parse_endpoint_target(s: &str, flag: &str) -> Result<ParsedEndpointTarget, String> {
    let (proto, rest) = parse_proto_and_rest(s, flag)?;
    if rest.is_empty() {
        return Err(format!("{flag} requires a non-empty host"));
    }

    let host;
    let id_str;
    if let Some(bracket_rest) = rest.strip_prefix('[') {
        let close = bracket_rest.find(']').ok_or_else(|| {
            format!("{flag} invalid IPv6 address: missing closing ']' (got '{s}')")
        })?;
        let host_end = close + 2;
        host = rest[..host_end].to_string();
        let suffix = &rest[host_end..];
        id_str = suffix
            .strip_prefix(':')
            .ok_or_else(|| format!("{flag} must be UDP:<host>:<id> or ICMP:<host>:<id>"))?;
        if id_str.is_empty() || id_str.contains(':') {
            return Err(format!(
                "{flag} must contain exactly one endpoint ID in UDP:<host>:<id> or ICMP:<host>:<id>"
            ));
        }
    } else if rest.contains("::") {
        if proto == SupportedProtocol::ICMP {
            return Err(format!("{flag} ICMP IPv6 addresses must use brackets"));
        }
        return Err(format!("{flag} IPv6 addresses must use brackets"));
    } else if let Some((host_part, id_part)) = rest.split_once(':') {
        host = host_part.to_string();
        id_str = id_part;
        if host.is_empty() || id_str.is_empty() || id_str.contains(':') {
            return Err(format!(
                "{flag} must contain exactly one endpoint ID in UDP:<host>:<id> or ICMP:<host>:<id>"
            ));
        }
    } else {
        return Err(format!(
            "{flag} must be UDP:<host>:<id> or ICMP:<host>:<id>"
        ));
    }

    let id = id_str
        .parse::<u16>()
        .map_err(|e| format!("invalid {flag} endpoint ID: {e}"))?;
    Ok(ParsedEndpointTarget { proto, host, id })
}

#[inline]
fn resolve_host_id(host: &str, id: u16, flag: &str) -> (String, LogicalEndpoint) {
    let resolve_arg = format!("{host}:{id}");
    match resolve_first(&resolve_arg) {
        Ok(sa) => (sa.to_string(), LogicalEndpoint::from_socket_addr(sa)),
        Err(e) => {
            log_error!("{flag}: failed to resolve {resolve_arg}: {e}");
            process::exit(2)
        }
    }
}

mod parser;
pub(crate) use parser::parse_args;

#[cfg(test)]
mod tests;
