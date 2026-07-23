use crate::endpoint::LogicalEndpoint;
use crate::net::params::{
    MAX_SAFE_ICMP_IPV4_PAYLOAD, MAX_SAFE_ICMP_IPV6_PAYLOAD, MAX_SAFE_UDP_IPV4_PAYLOAD,
    MAX_SAFE_UDP_IPV6_PAYLOAD,
};
use crate::net::socket::resolve_first;

use std::io;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::{env, process};

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_STATS_INTERVAL_MINS: u32 = 60;
const DEFAULT_MAX_PAYLOAD: usize = 1500;
const DEFAULT_ICMP_SYNC_PPS: u32 = 0;
const DEFAULT_WORKERS: usize = 1;
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

pub(crate) fn parse_args() -> RequestedConfig {
    // One place for usage. Program name is filled dynamically.
    fn print_usage_and_exit(code: i32) -> ! {
        let prog = env::args()
            .next()
            .unwrap_or_else(|| String::from("pkthere"));
        log_error!(
            "Usage: {prog} --here <protocol:host:id> --there <protocol:host:id>\n\
             \n\
             Options:\n\
             \t--timeout-secs N         Idle timeout for the single client (default: 10)\n\
             \t--icmp-handshake-timeout-secs N\n\
             \t                         Reply-ID handshake timeout (default: --timeout-secs)\n\
             \t--on-timeout drop|exit   What to do on timeout (default: drop)\n\
             \t--stats-interval-mins N  JSON stats print interval minutes (0=disabled, default: 60)\n\
             \t--workers N              Number of listener/upstream worker pairs, not flows (reuse-port, default: 1)\n\
             \t--worker-flow-mode WHAT  shared-flow = one global locked flow across worker pairs;\n\
             \t                         single-flow = worker-pair-local locked flows and worker-pair-local ICMP sync state\n\
             \t                         worker modes affect ownership/distribution only; they do not scale shared/global options upward\n\
             \t                         single-flow with --workers 1 is valid but behaves like shared-flow for ownership\n\
             \t--here UDP:host:0                  Bind an ephemeral local UDP port\n\
             \t--there UDP:host:port              Fixed remote UDP destination port\n\
             \t--there-source-id port|0           Upstream UDP/ICMP local source id (0/omitted = kernel/generated)\n\
             \t--here ICMP:host:D                 Listen for ICMP destination id D (D=0 wildcard-learns peer source id)\n\
             \t--here-source-id S                 ICMP listener logical source id for replies (default = realized listen id)\n\
             \t--here-reply-id R                  ICMP listener advertised reply destination id (default = realized listen id)\n\
             \t--there ICMP:host:D                Send to remote ICMP destination id D\n\
             \t--there-source-id S                ICMP upstream logical source id carried in tunnel packets\n\
             \t--there-reply-id R                 ICMP upstream local reply destination id negotiated by session control\n\
             \t--max-payload N          Payload limit (default: 1500)\n\
             \t--icmp-sync-pps N        Global total best-effort ICMP sync request target in packets/s (0=disabled, default: 0)\n\
             \t--reresolve-secs N       Re-resolve host(s) every N seconds (0=disabled)\n\
             \t--reresolve-mode WHAT    Which sockets to re-resolve: upstream|listen|both|none (default: upstream)\n\
             \t--debug-reresolve-address-file PATH\n\
             \t                         Debug-only revisioned address source for deterministic re-resolution tests\n\
             \t--user NAME              Drop privileges to this user (Unix only)\n\
             \t--group NAME             Drop privileges to this group (Unix only)\n\
             \t--debug-client-unconnected Leave locked client/listener socket unconnected for debug/relock behavior\n\
             \t--debug-upstream-unconnected Leave upstream socket unconnected and always send via send_to for debugging\n\
             \t--debug-icmp-kernel-echo-self-handshake Allow ICMP DGRAM kernel-echo self reflection to complete reply-ID negotiation for tests/debugging\n\
             \t--debug-force-raw-icmp-wildcard-upstream Force RAW for wildcard --there ICMP:host:0 tests with collapsed no-disjoint IDs\n\
             \t--debug-fast-stats       Shorten stats cadence for tests/debugging\n\
             \t--debug-log WHAT         Enable one debug log category WHAT = drops|handshake|handles|packets|packet-dump (repeatable)\n\
             \t-h, --help               Show this help and exit"
        );
        process::exit(code)
    }

    // DRY helper: set an Option<T> once; error if the flag was already provided
    fn set_once<T>(slot: &mut Option<T>, val: T, flag: &str) {
        if slot.is_some() {
            log_error!("{flag} specified multiple times");
            print_usage_and_exit(2)
        }
        *slot = Some(val);
    }

    // Generic number parser with good errors.
    fn parse_num<T>(s: &str, flag: &str) -> T
    where
        T: std::str::FromStr,
        <T as std::str::FromStr>::Err: std::fmt::Display,
    {
        s.parse::<T>().unwrap_or_else(|e| {
            log_error!("invalid {flag}: {e}");
            print_usage_and_exit(2)
        })
    }

    fn parse_id_flag(s: &str, flag: &str) -> u16 {
        parse_num::<u16>(s, flag)
    }

    // Helper function: consume the next value from the iterator or exit.
    fn get_next_value<I: Iterator<Item = String>>(
        it: &mut std::iter::Peekable<I>,
        flag: &str,
    ) -> String {
        it.next().unwrap_or_else(|| {
            log_error!("{flag} requires a value");
            print_usage_and_exit(2)
        })
    }

    // Required endpoints and optional role-scoped source/reply IDs.
    let mut listen_opt: Option<ParsedEndpointTarget> = None;
    let mut upstream_opt: Option<ParsedEndpointTarget> = None;
    let mut here_source_id: Option<u16> = None;
    let mut here_reply_id: Option<u16> = None;
    let mut there_source_id: Option<u16> = None;
    let mut there_reply_id: Option<u16> = None;

    // Optional (track presence to reject duplicates cleanly)
    let mut timeout_secs: Option<u64> = None;
    let mut icmp_handshake_timeout_secs: Option<u64> = None;
    let mut on_timeout: Option<TimeoutAction> = None;
    let mut stats_interval_mins: Option<u32> = None;
    let mut max_payload: Option<usize> = None; // default 1500
    let mut icmp_sync_pps: Option<u32> = None; // default 0 (disabled)
    let mut workers: Option<usize> = None; // default 1
    let mut worker_flow_mode: Option<WorkerFlowMode> = None; // default shared-flow
    let mut reresolve_secs: Option<u64> = None; // 0 if None
    let mut reresolve_mode: Option<ReresolveMode> = None; // default upstream
    let mut debug_reresolve_address_file: Option<PathBuf> = None;

    #[cfg(unix)]
    let mut run_as_user: Option<String> = None;
    #[cfg(unix)]
    let mut run_as_group: Option<String> = None;
    let mut debug_behavior = DebugBehavior::default();
    let mut debug_logs = DebugLogs::default();

    // Parse flags using an iterator (no manual index math)
    let mut args_iter = env::args().skip(1).peekable();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "--here" => {
                let val = get_next_value(&mut args_iter, "--here");
                let parsed = parse_endpoint_target(&val, "--here").unwrap_or_else(|msg| {
                    log_error!("{msg}");
                    print_usage_and_exit(2)
                });
                set_once(&mut listen_opt, parsed, "--here");
            }
            "--here-source-id" => {
                let val = get_next_value(&mut args_iter, "--here-source-id");
                let parsed = parse_id_flag(&val, "--here-source-id");
                set_once(&mut here_source_id, parsed, "--here-source-id");
            }
            "--here-reply-id" => {
                let val = get_next_value(&mut args_iter, "--here-reply-id");
                let parsed = parse_id_flag(&val, "--here-reply-id");
                set_once(&mut here_reply_id, parsed, "--here-reply-id");
            }
            "--there" => {
                let val = get_next_value(&mut args_iter, "--there");
                let parsed = parse_endpoint_target(&val, "--there").unwrap_or_else(|msg| {
                    log_error!("{msg}");
                    print_usage_and_exit(2)
                });
                set_once(&mut upstream_opt, parsed, "--there");
            }
            "--there-source-id" => {
                let val = get_next_value(&mut args_iter, "--there-source-id");
                let parsed = parse_id_flag(&val, "--there-source-id");
                set_once(&mut there_source_id, parsed, "--there-source-id");
            }
            "--there-reply-id" => {
                let val = get_next_value(&mut args_iter, "--there-reply-id");
                let parsed = parse_id_flag(&val, "--there-reply-id");
                set_once(&mut there_reply_id, parsed, "--there-reply-id");
            }
            "--timeout-secs" => {
                let val = get_next_value(&mut args_iter, "--timeout-secs");
                let parsed = parse_num::<u64>(&val, "--timeout-secs");
                set_once(&mut timeout_secs, parsed, "--timeout-secs");
            }
            "--icmp-handshake-timeout-secs" => {
                let val = get_next_value(&mut args_iter, "--icmp-handshake-timeout-secs");
                let parsed = parse_num::<u64>(&val, "--icmp-handshake-timeout-secs");
                set_once(
                    &mut icmp_handshake_timeout_secs,
                    parsed,
                    "--icmp-handshake-timeout-secs",
                );
            }
            "--on-timeout" => {
                let val = get_next_value(&mut args_iter, "--on-timeout");
                let action = match val.as_str() {
                    "drop" => TimeoutAction::Drop,
                    "exit" => TimeoutAction::Exit,
                    _ => {
                        log_error!("--on-timeout must be drop|exit");
                        print_usage_and_exit(2)
                    }
                };
                set_once(&mut on_timeout, action, "--on-timeout");
            }
            "--stats-interval-mins" => {
                let val = get_next_value(&mut args_iter, "--stats-interval-mins");
                let parsed = parse_num::<u32>(&val, "--stats-interval-mins");
                set_once(&mut stats_interval_mins, parsed, "--stats-interval-mins");
            }
            "--max-payload" => {
                let val = get_next_value(&mut args_iter, "--max-payload");
                let parsed = parse_num::<usize>(&val, "--max-payload");
                if parsed > MAX_SAFE_UDP_IPV6_PAYLOAD {
                    log_error!(
                        "--max-payload must be <= {} (requested {})",
                        MAX_SAFE_UDP_IPV6_PAYLOAD,
                        parsed
                    );
                    print_usage_and_exit(2)
                }
                set_once(&mut max_payload, parsed, "--max-payload");
            }
            "--icmp-sync-pps" => {
                let val = get_next_value(&mut args_iter, "--icmp-sync-pps");
                let parsed = parse_num::<u32>(&val, "--icmp-sync-pps");
                set_once(&mut icmp_sync_pps, parsed, "--icmp-sync-pps");
            }
            "--workers" => {
                let val = get_next_value(&mut args_iter, "--workers");
                let parsed = parse_num::<usize>(&val, "--workers");
                if parsed == 0 {
                    log_error!("--workers must be >= 1");
                    print_usage_and_exit(2)
                }
                set_once(&mut workers, parsed, "--workers");
            }
            "--worker-flow-mode" => {
                let val = get_next_value(&mut args_iter, "--worker-flow-mode");
                let parsed = WorkerFlowMode::from_str(&val).unwrap_or_else(|| {
                    log_error!("--worker-flow-mode must be shared-flow|single-flow (got '{val}')");
                    print_usage_and_exit(2)
                });
                set_once(&mut worker_flow_mode, parsed, "--worker-flow-mode");
            }
            "--reresolve-secs" => {
                let val = get_next_value(&mut args_iter, "--reresolve-secs");
                let parsed = parse_num::<u64>(&val, "--reresolve-secs");
                set_once(&mut reresolve_secs, parsed, "--reresolve-secs");
            }
            "--reresolve-mode" => {
                let val = get_next_value(&mut args_iter, "--reresolve-mode");
                let parsed = ReresolveMode::from_str(&val).unwrap_or_else(|| {
                    log_error!("--reresolve-mode must be upstream|listen|both|none (got '{val}')");
                    print_usage_and_exit(2)
                });
                set_once(&mut reresolve_mode, parsed, "--reresolve-mode");
            }
            "--debug-reresolve-address-file" => {
                let val = get_next_value(&mut args_iter, "--debug-reresolve-address-file");
                set_once(
                    &mut debug_reresolve_address_file,
                    PathBuf::from(val),
                    "--debug-reresolve-address-file",
                );
            }
            #[cfg(unix)]
            "--user" => {
                let val = get_next_value(&mut args_iter, "--user");
                set_once(&mut run_as_user, val, "--user");
            }
            #[cfg(unix)]
            "--group" => {
                let val = get_next_value(&mut args_iter, "--group");
                set_once(&mut run_as_group, val, "--group");
            }
            "--debug-client-unconnected" => {
                debug_behavior.client_unconnected = true;
            }
            "--debug-upstream-unconnected" => {
                debug_behavior.upstream_unconnected = true;
            }
            "--debug-icmp-kernel-echo-self-handshake" => {
                debug_behavior.icmp_kernel_echo_self_handshake = true;
            }
            "--debug-force-raw-icmp-wildcard-upstream" => {
                debug_behavior.force_raw_icmp_wildcard_upstream = true;
            }
            "--debug-fast-stats" => {
                debug_behavior.fast_stats = true;
            }
            "--debug-log" => {
                let val = get_next_value(&mut args_iter, "--debug-log");
                match val.as_str() {
                    "drops" => debug_logs.drops = true,
                    "handshake" => debug_logs.handshake = true,
                    "handles" => debug_logs.handles = true,
                    "packets" => debug_logs.packets = true,
                    "packet-dump" => debug_logs.packet_dump = true,
                    _ => {
                        log_error!(
                            "--debug-log expects exactly one of drops, handshake, handles, packets, or packet-dump per flag occurrence (got '{val}')"
                        );
                        print_usage_and_exit(2)
                    }
                }
            }
            "-h" | "--help" => print_usage_and_exit(0),
            other => {
                log_error!("unknown arg: {other}");
                print_usage_and_exit(2)
            }
        }
    }

    let listen_endpoint = match listen_opt {
        Some(t) => t,
        None => {
            log_error!("missing required flag: --here UDP:<host>:<id>|ICMP:<host>:<id>");
            print_usage_and_exit(2)
        }
    };
    let upstream_endpoint = match upstream_opt {
        Some(t) => t,
        None => {
            log_error!("missing required flag: --there UDP:<host>:<id>|ICMP:<host>:<id>");
            print_usage_and_exit(2)
        }
    };
    let here_id = listen_endpoint.id;
    let there_id = upstream_endpoint.id;

    let listen_proto = listen_endpoint.proto;
    let upstream_proto = upstream_endpoint.proto;

    if listen_proto == SupportedProtocol::UDP
        && (here_source_id.is_some() || here_reply_id.is_some())
    {
        log_error!(
            "UDP listeners use the --here UDP:<host>:<port> endpoint ID only; --here-source-id/--here-reply-id are ICMP-only"
        );
        print_usage_and_exit(2)
    }
    if upstream_proto == SupportedProtocol::UDP && there_reply_id.is_some() {
        log_error!("UDP upstreams do not support --there-reply-id");
        print_usage_and_exit(2)
    }
    if listen_proto != SupportedProtocol::ICMP && here_reply_id.is_some() {
        log_error!("--here-reply-id requires --here ICMP:<host>:<id>");
        print_usage_and_exit(2)
    }
    if upstream_proto != SupportedProtocol::ICMP && there_reply_id.is_some() {
        log_error!("--there-reply-id requires --there ICMP:<host>:<id>");
        print_usage_and_exit(2)
    }

    let (listen_str, listen_request) = resolve_host_id(&listen_endpoint.host, here_id, "--here");
    let listen_mode_parsed = if here_id == 0 {
        ListenMode::Dynamic
    } else {
        ListenMode::Fixed
    };
    let (upstream_str, upstream_request) =
        resolve_host_id(&upstream_endpoint.host, there_id, "--there");

    let listener_source_id_request = if listen_proto == SupportedProtocol::ICMP {
        here_source_id.map_or(IcmpReplyIdRequest::Default, id_request_from_u16)
    } else {
        IcmpReplyIdRequest::Default
    };
    let listener_reply_id_request = if listen_proto == SupportedProtocol::ICMP {
        here_reply_id.map_or(IcmpReplyIdRequest::Default, id_request_from_u16)
    } else {
        IcmpReplyIdRequest::Default
    };
    let upstream_source_id_request = match upstream_proto {
        SupportedProtocol::ICMP | SupportedProtocol::UDP => {
            there_source_id.map_or(IcmpReplyIdRequest::Default, id_request_from_u16)
        }
    };
    let upstream_reply_id_request = if upstream_proto == SupportedProtocol::ICMP {
        there_reply_id.map_or(IcmpReplyIdRequest::Default, id_request_from_u16)
    } else {
        IcmpReplyIdRequest::Default
    };

    if icmp_sync_pps.is_some() && upstream_proto != SupportedProtocol::ICMP {
        log_error!("--icmp-sync-pps requires --there ICMP:<host>:<id>");
        print_usage_and_exit(2)
    }
    if debug_behavior.icmp_kernel_echo_self_handshake && upstream_proto != SupportedProtocol::ICMP {
        log_error!("--debug-icmp-kernel-echo-self-handshake requires --there ICMP:<host>:<id>");
        print_usage_and_exit(2)
    }
    if debug_behavior.force_raw_icmp_wildcard_upstream
        && (upstream_proto != SupportedProtocol::ICMP
            || upstream_request.id() != 0
            || upstream_reply_id_request.requested_socket_id() != 0)
    {
        log_error!(
            "--debug-force-raw-icmp-wildcard-upstream requires wildcard --there ICMP:<host>:0"
        );
        print_usage_and_exit(2)
    }

    // Defaults
    let timeout_secs = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let icmp_handshake_timeout_secs = icmp_handshake_timeout_secs.unwrap_or(timeout_secs);
    let on_timeout = on_timeout.unwrap_or(TimeoutAction::Drop);
    let stats_interval_mins = stats_interval_mins.unwrap_or(DEFAULT_STATS_INTERVAL_MINS);
    let max_payload = max_payload.unwrap_or(DEFAULT_MAX_PAYLOAD);
    let icmp_sync_pps = icmp_sync_pps.unwrap_or(DEFAULT_ICMP_SYNC_PPS);
    let workers = workers.unwrap_or(DEFAULT_WORKERS);
    let worker_flow_mode = worker_flow_mode.unwrap_or(WorkerFlowMode::SharedFlow);
    let reresolve_secs = reresolve_secs.unwrap_or(DEFAULT_RERESOLVE_SECS);
    let reresolve_mode = reresolve_mode.unwrap_or(ReresolveMode::Upstream);

    let absolute_max_payload = if listen_request.ip().is_ipv4() || upstream_request.ip().is_ipv4() {
        if listen_proto == SupportedProtocol::ICMP || upstream_proto == SupportedProtocol::ICMP {
            MAX_SAFE_ICMP_IPV4_PAYLOAD
        } else {
            MAX_SAFE_UDP_IPV4_PAYLOAD
        }
    } else if listen_proto == SupportedProtocol::ICMP || upstream_proto == SupportedProtocol::ICMP {
        MAX_SAFE_ICMP_IPV6_PAYLOAD
    } else {
        MAX_SAFE_UDP_IPV6_PAYLOAD
    };

    if max_payload > absolute_max_payload {
        log_error!(
            "--max-payload {max_payload} exceeds the maximum supported by the selected protocols and address families ({absolute_max_payload})"
        );
        print_usage_and_exit(2);
    }

    if upstream_proto == SupportedProtocol::UDP && upstream_request.id() == 0 {
        log_error!(
            "--there UDP:host:0 is invalid: UDP upstream requires a fixed remote destination port"
        );
        print_usage_and_exit(2)
    }
    RequestedConfig {
        listen_request,
        listener_source_id_request,
        listener_reply_id_request,
        listen_proto,
        listen_mode: listen_mode_parsed,
        listen_str,
        upstream_request,
        upstream_source_id_request,
        upstream_reply_id_request,
        upstream_proto,
        upstream_str,
        options: RuntimeOptions {
            workers,
            worker_flow_mode,
            timeout_secs,
            icmp_handshake_timeout_secs,
            on_timeout,
            stats_interval_mins,
            max_payload,
            icmp_sync_pps,
            reresolve_secs,
            reresolve_mode,
            debug_reresolve_address_file,
            #[cfg(unix)]
            run_as_user,
            #[cfg(unix)]
            run_as_group,
            debug_behavior,
            debug_logs,
        },
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
