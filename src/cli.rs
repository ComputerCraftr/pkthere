use crate::net::params::{
    CanonicalAddr, MAX_SAFE_ICMP_IPV4_PAYLOAD, MAX_SAFE_ICMP_IPV6_PAYLOAD,
    MAX_SAFE_UDP_IPV4_PAYLOAD, MAX_SAFE_UDP_IPV6_PAYLOAD,
};
use crate::net::socket::resolve_first;

use std::io;
use std::{env, process};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedProtocol {
    UDP,
    ICMP,
}

impl SupportedProtocol {
    pub const fn from_str(s: &str) -> Option<Self> {
        match s {
            s if s.eq_ignore_ascii_case("udp") => Some(Self::UDP),
            s if s.eq_ignore_ascii_case("icmp") => Some(Self::ICMP),
            _ => None,
        }
    }

    pub const fn to_str(&self) -> &'static str {
        match self {
            Self::UDP => "UDP",
            Self::ICMP => "ICMP",
        }
    }
}

impl std::fmt::Display for SupportedProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutAction {
    Drop,
    Exit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReresolveMode {
    None,
    Upstream,
    Listen,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerFlowMode {
    SharedFlow,
    SingleFlow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenMode {
    Fixed,
    Dynamic, // WildcardLearn for ICMP, Ephemeral for UDP
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
pub struct DebugBehavior {
    pub no_connect: bool,
    pub fast_stats: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DebugLogs {
    pub drops: bool,
    pub handles: bool,
    pub packets: bool,
}

#[derive(Clone, Debug)]
pub struct RequestedConfig {
    pub listen_request: CanonicalAddr, // CLI UDP port or ICMP listener id
    pub listen_proto: SupportedProtocol, // UDP | ICMP
    pub listen_mode: ListenMode,       // Fixed or Dynamic (:0)
    pub listen_str: String,            // original --here host:port string
    pub workers: usize,                // listener/upstream worker pairs
    pub worker_flow_mode: WorkerFlowMode, // shared-flow | single-flow
    pub upstream_request: CanonicalAddr, // CLI remote UDP port or ICMP peer/listener id
    pub upstream_local_id: u16,        // CLI requested local ID for ICMP upstreams
    pub upstream_proto: SupportedProtocol, // UDP | ICMP
    pub upstream_str: String,          // FQDN:port or IP:port
    pub timeout_secs: u64,             // idle timeout for single client
    pub on_timeout: TimeoutAction,     // Drop | Exit
    pub stats_interval_mins: u32,      // JSON stats print interval (0 disables stats thread)
    pub max_payload: usize,            // optional user-specified MTU/payload limit
    pub icmp_sync_pps: u32,            // 0 = disabled; >0 targets a best-effort ICMP request rate
    pub reresolve_secs: u64,           // 0 = disabled
    pub reresolve_mode: ReresolveMode, // which side(s) to re-resolve
    #[cfg(unix)]
    pub run_as_user: Option<String>,
    #[cfg(unix)]
    pub run_as_group: Option<String>,
    pub debug_behavior: DebugBehavior,
    pub debug_logs: DebugLogs,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub listen: CanonicalAddr, // actual bound UDP port or ICMP local id
    pub listen_proto: SupportedProtocol, // UDP | ICMP
    pub listen_mode: ListenMode, // Fixed or Dynamic (:0)
    pub listen_str: String,    // original --here host:port string
    pub workers: usize,        // listener/upstream worker pairs
    pub worker_flow_mode: WorkerFlowMode, // shared-flow | single-flow
    pub upstream: CanonicalAddr, // remote UDP port or ICMP peer/listener id
    pub upstream_local_id: u16, // CLI requested local source ID
    pub upstream_proto: SupportedProtocol, // UDP | ICMP
    pub upstream_str: String,  // FQDN:port or IP:port
    pub timeout_secs: u64,     // idle timeout for single client
    pub on_timeout: TimeoutAction, // Drop | Exit
    pub stats_interval_mins: u32, // JSON stats print interval (0 disables stats thread)
    pub max_payload: usize,    // optional user-specified MTU/payload limit
    pub icmp_sync_pps: u32,    // 0 = disabled; >0 targets a best-effort ICMP request rate
    pub reresolve_secs: u64,   // 0 = disabled
    pub reresolve_mode: ReresolveMode, // which side(s) to re-resolve
    #[cfg(unix)]
    pub run_as_user: Option<String>,
    #[cfg(unix)]
    pub run_as_group: Option<String>,
    pub debug_behavior: DebugBehavior,
    pub debug_logs: DebugLogs,
}

pub fn realize_config(
    requested: RequestedConfig,
    listen: CanonicalAddr,
) -> io::Result<RuntimeConfig> {
    if requested.listen_proto == SupportedProtocol::ICMP
        && requested.listen_mode == ListenMode::Fixed
        && requested.listen_request.id != listen.id
    {
        return Err(io::Error::other(format!(
            "ICMP fixed-id listener requested id {} but socket local id is {}; use a raw-capable deployment or --here ICMP:host:0 for wildcard-learn mode",
            requested.listen_request.id, listen.id
        )));
    }

    if listen.addr == requested.upstream_request.addr {
        return Err(io::Error::other(format!(
            "Port conflict: listener address {} is identical to upstream destination address {}; they must be different to avoid loops",
            listen.addr, requested.upstream_request.addr
        )));
    }

    Ok(RuntimeConfig {
        listen,
        listen_proto: requested.listen_proto,
        listen_mode: requested.listen_mode,
        listen_str: requested.listen_str,
        workers: requested.workers,
        worker_flow_mode: requested.worker_flow_mode,
        upstream: requested.upstream_request,
        upstream_local_id: requested.upstream_local_id,
        upstream_proto: requested.upstream_proto,
        upstream_str: requested.upstream_str,
        timeout_secs: requested.timeout_secs,
        on_timeout: requested.on_timeout,
        stats_interval_mins: requested.stats_interval_mins,
        max_payload: requested.max_payload,
        icmp_sync_pps: requested.icmp_sync_pps,
        reresolve_secs: requested.reresolve_secs,
        reresolve_mode: requested.reresolve_mode,
        #[cfg(unix)]
        run_as_user: requested.run_as_user,
        #[cfg(unix)]
        run_as_group: requested.run_as_group,
        debug_behavior: requested.debug_behavior,
        debug_logs: requested.debug_logs,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedIcmpCliTarget {
    resolve_arg: String,
    local_id: u16,
}

#[inline]
fn parse_cli_num<T>(s: &str, flag: &str, what: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    s.parse::<T>()
        .map_err(|e| format!("{flag}: invalid {what} '{s}': {e}"))
}

#[inline]
fn parse_proto_and_rest<'a>(
    s: &'a str,
    flag: &str,
) -> Result<(SupportedProtocol, &'a str), String> {
    s.split_once(':')
        .and_then(|(proto_str, rest)| SupportedProtocol::from_str(proto_str).map(|p| (p, rest)))
        .ok_or_else(|| {
            format!(
                "{flag} must be UDP:<ip>:<port> or ICMP:<ip>:<id> (UDP :0 = ephemeral local bind on --here; ICMP :0 = wildcard listener on --here or dynamic local source id on --there) (got '{s}')"
            )
        })
}

fn parse_icmp_cli_target(
    addr_str: &str,
    flag: &str,
    allow_local_id: bool,
) -> Result<ParsedIcmpCliTarget, String> {
    let expected = if allow_local_id {
        "ICMP:<host>:<remote_id> or ICMP:[<ipv6>]:<remote_id>[:<local_id>]"
    } else {
        "ICMP:<host>:<id> or ICMP:[<ipv6>]:<id>"
    };

    let parse_ids = |host: &str, ids: &[&str]| -> Result<ParsedIcmpCliTarget, String> {
        if host.is_empty() {
            return Err(format!("{flag} must use {expected}"));
        }
        if ids.len() != 1 && !(allow_local_id && ids.len() == 2) {
            return Err(format!("{flag} must use {expected}"));
        }

        let remote_id = parse_cli_num::<u16>(ids[0], flag, "ICMP id")?;
        let local_id = if ids.len() == 2 {
            parse_cli_num::<u16>(ids[1], flag, "ICMP local id")?
        } else {
            0
        };

        Ok(ParsedIcmpCliTarget {
            resolve_arg: format!("{host}:{remote_id}"),
            local_id,
        })
    };

    if let Some(rest) = addr_str.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| {
            format!("{flag} invalid ICMP IPv6 address: missing closing ']' (got '{addr_str}')")
        })?;
        let host = &addr_str[..=close + 1];
        let suffix = &addr_str[close + 2..];
        let ids = suffix
            .strip_prefix(':')
            .ok_or_else(|| format!("{flag} must use {expected}"))?;
        let parts: Vec<&str> = ids.split(':').collect();
        return parse_ids(host, &parts);
    }

    let parts: Vec<&str> = addr_str.split(':').collect();
    if parts.len() > 3 || (parts.len() > 2 && !allow_local_id) {
        return Err(format!(
            "{flag} ICMP IPv6 addresses must use brackets: ICMP:[<ipv6>]:<id>"
        ));
    }
    if parts.len() < 2 {
        return Err(format!("{flag} must use {expected}"));
    }

    parse_ids(parts[0], &parts[1..])
}

pub fn parse_args() -> RequestedConfig {
    // One place for usage. Program name is filled dynamically.
    fn print_usage_and_exit(code: i32) -> ! {
        let prog = env::args().next().unwrap_or_else(|| "pkthere".into());
        log_error!(
            "Usage: {prog} --here <protocol:listen_ip:port_id> --there <protocol:upstream_host_or_ip:port_id>\n\
             \n\
             Options:\n\
             \t--timeout-secs N         Idle timeout for the single client (default: 10)\n\
             \t--on-timeout drop|exit   What to do on timeout (default: drop)\n\
             \t--stats-interval-mins N  JSON stats print interval minutes (0=disabled, default: 60)\n\
             \t--workers N              Number of listener/upstream worker pairs, not flows (reuse-port, default: 1)\n\
             \t--worker-flow-mode WHAT  shared-flow = one global locked flow across worker pairs;\n\
             \t                         single-flow = worker-pair-local locked flows and worker-pair-local ICMP sync state\n\
             \t                         worker modes affect ownership/distribution only; they do not scale shared/global options upward\n\
             \t                         single-flow with --workers 1 is valid but behaves like shared-flow for ownership\n\
             \t--here UDP:host:0        Bind an ephemeral local UDP port\n\
             \t--there UDP:host:port    Fixed remote UDP destination port\n\
             \t--here ICMP:host:0       Wildcard-learn ICMP listener (learn peer ICMP id on first lock)\n\
             \t--here ICMP:host:N       Fixed ICMP listener id N (requires raw sockets on Linux/Android)\n\
             \t--there ICMP:host:0      Dynamic local ICMP source id (kernel-assigned ping-socket id)\n\
             \t--there ICMP:host:N      Fixed remote ICMP peer/listener id N (requires raw sockets on Linux/Android)\n\
             \t--max-payload N          Payload limit (default: 1500)\n\
             \t--icmp-sync-pps N        Global total best-effort ICMP sync request target in packets/s (0=disabled, default: 0)\n\
             \t--reresolve-secs N       Re-resolve host(s) every N seconds (0=disabled)\n\
             \t--reresolve-mode WHAT    Which sockets to re-resolve: upstream|listen|both|none (default: upstream)\n\
             \t--user NAME              Drop privileges to this user (Unix only)\n\
             \t--group NAME             Drop privileges to this group (Unix only)\n\
             \t--debug-no-connect       Keep sockets unconnected for debug/relock behavior\n\
             \t--debug-fast-stats       Shorten stats cadence for tests/debugging\n\
             \t--debug-log WHAT         Enable debug log category WHAT = drops|handles|packets (repeatable)\n\
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

    // Address helpers.
    fn parse_here(s: &str) -> (String, CanonicalAddr, SupportedProtocol, ListenMode) {
        let (proto, addr_str) = parse_proto_and_rest(s, "--here").unwrap_or_else(|msg| {
            log_error!("{msg}");
            print_usage_and_exit(2)
        });

        let (resolve_arg, mode) = match proto {
            SupportedProtocol::UDP => {
                let id_part = addr_str.rsplit_once(':').map_or("0", |(_, p)| p);
                let mode = if id_part == "0" {
                    ListenMode::Dynamic
                } else {
                    ListenMode::Fixed
                };
                (addr_str.to_string(), mode)
            }
            SupportedProtocol::ICMP => {
                let parsed =
                    parse_icmp_cli_target(addr_str, "--here", false).unwrap_or_else(|msg| {
                        log_error!("{msg}");
                        print_usage_and_exit(2)
                    });
                let mode = if parsed.resolve_arg.ends_with(":0") {
                    ListenMode::Dynamic
                } else {
                    ListenMode::Fixed
                };
                (parsed.resolve_arg, mode)
            }
        };

        match resolve_first(&resolve_arg) {
            Ok(sa) => (
                sa.to_string(),
                CanonicalAddr::from_socket_addr(sa),
                proto,
                mode,
            ),
            Err(e) => {
                log_error!(
                    "--here: failed to parse and resolve host:port or ip:port (got '{s}'): {e}"
                );
                print_usage_and_exit(2)
            }
        }
    }
    fn validate_there(s: &str) -> (String, CanonicalAddr, u16, SupportedProtocol) {
        let (proto, addr_str) = parse_proto_and_rest(s, "--there").unwrap_or_else(|msg| {
            log_error!("{msg}");
            print_usage_and_exit(2)
        });

        let (resolve_arg, local_id) = match proto {
            SupportedProtocol::UDP => (addr_str.to_string(), 0),
            SupportedProtocol::ICMP => {
                let parsed =
                    parse_icmp_cli_target(addr_str, "--there", true).unwrap_or_else(|msg| {
                        log_error!("{msg}");
                        print_usage_and_exit(2)
                    });
                (parsed.resolve_arg, parsed.local_id)
            }
        };

        match resolve_first(&resolve_arg) {
            Ok(sa) => (
                sa.to_string(),
                CanonicalAddr::from_socket_addr(sa),
                local_id,
                proto,
            ),
            Err(e) => {
                log_error!(
                    "--there: failed to parse and resolve host:port or ip:port (got '{s}'): {e}"
                );
                print_usage_and_exit(2)
            }
        }
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

    // Required
    let mut listen_opt: Option<(String, CanonicalAddr, SupportedProtocol, ListenMode)> = None;
    let mut upstream_opt: Option<(String, CanonicalAddr, u16, SupportedProtocol)> = None;

    // Optional (track presence to reject duplicates cleanly)
    let mut timeout_secs: Option<u64> = None;
    let mut on_timeout: Option<TimeoutAction> = None;
    let mut stats_interval_mins: Option<u32> = None;
    let mut max_payload: Option<usize> = None; // default 1500
    let mut icmp_sync_pps: Option<u32> = None; // default 0 (disabled)
    let mut workers: Option<usize> = None; // default 1
    let mut worker_flow_mode: Option<WorkerFlowMode> = None; // default shared-flow
    let mut reresolve_secs: Option<u64> = None; // 0 if None
    let mut reresolve_mode: Option<ReresolveMode> = None; // default upstream

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
                let parsed = parse_here(&val);
                set_once(&mut listen_opt, parsed, "--here");
            }
            "--there" => {
                let val = get_next_value(&mut args_iter, "--there");
                let parsed = validate_there(&val);
                set_once(&mut upstream_opt, parsed, "--there");
            }
            "--timeout-secs" => {
                let val = get_next_value(&mut args_iter, "--timeout-secs");
                let parsed = parse_num::<u64>(&val, "--timeout-secs");
                set_once(&mut timeout_secs, parsed, "--timeout-secs");
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
            "--debug-no-connect" => {
                debug_behavior.no_connect = true;
            }
            "--debug-fast-stats" => {
                debug_behavior.fast_stats = true;
            }
            "--debug-log" => {
                let val = get_next_value(&mut args_iter, "--debug-log");
                for part in val.split(',') {
                    let flag = part.trim();
                    if flag.is_empty() {
                        continue;
                    }
                    match flag {
                        "drops" => debug_logs.drops = true,
                        "handles" => debug_logs.handles = true,
                        "packets" => debug_logs.packets = true,
                        _ => {
                            log_error!(
                                "--debug-log expects drops, handles, or packets (got '{flag}')"
                            );
                            print_usage_and_exit(2)
                        }
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

    let (listen_str, listen_request, listen_proto, listen_mode_parsed) = match listen_opt {
        Some(t) => t,
        None => {
            log_error!("missing required flag: --here <protocol:listen_ip:port>");
            print_usage_and_exit(2)
        }
    };
    let (upstream_str, upstream_request, upstream_local_id, upstream_proto) = match upstream_opt {
        Some(t) => t,
        None => {
            log_error!("missing required flag: --there <protocol:upstream_host_or_ip:port>");
            print_usage_and_exit(2)
        }
    };

    if icmp_sync_pps.is_some() && upstream_proto != SupportedProtocol::ICMP {
        log_error!("--icmp-sync-pps requires --there ICMP:...");
        print_usage_and_exit(2)
    }

    // Defaults
    let timeout_secs = timeout_secs.unwrap_or(10);
    let on_timeout = on_timeout.unwrap_or(TimeoutAction::Drop);
    let stats_interval_mins = stats_interval_mins.unwrap_or(60);
    let max_payload = max_payload.unwrap_or(1500);
    let icmp_sync_pps = icmp_sync_pps.unwrap_or(0);
    let workers = workers.unwrap_or(1);
    let worker_flow_mode = worker_flow_mode.unwrap_or(WorkerFlowMode::SharedFlow);
    let reresolve_secs = reresolve_secs.unwrap_or(0);
    let reresolve_mode = reresolve_mode.unwrap_or(ReresolveMode::Upstream);
    let _ = if listen_request.id == 0 {
        ListenMode::Dynamic
    } else {
        ListenMode::Fixed
    };

    let absolute_max_payload = if listen_request.addr.is_ipv4() || upstream_request.addr.is_ipv4() {
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

    if upstream_proto == SupportedProtocol::UDP && upstream_request.id == 0 {
        log_error!(
            "--there UDP:host:0 is invalid: UDP upstream requires a fixed remote destination port"
        );
        print_usage_and_exit(2)
    }
    RequestedConfig {
        listen_request,
        listen_proto,
        listen_mode: listen_mode_parsed,
        listen_str,
        workers,
        worker_flow_mode,
        upstream_request,
        upstream_local_id,
        upstream_proto,
        upstream_str,
        timeout_secs,
        on_timeout,
        stats_interval_mins,
        max_payload,
        icmp_sync_pps,
        reresolve_secs,
        reresolve_mode,
        #[cfg(unix)]
        run_as_user,
        #[cfg(unix)]
        run_as_group,
        debug_behavior,
        debug_logs,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DebugBehavior, DebugLogs, ListenMode, ParsedIcmpCliTarget, RequestedConfig, ReresolveMode,
        SupportedProtocol, TimeoutAction, WorkerFlowMode, parse_icmp_cli_target, realize_config,
    };
    use crate::net::params::CanonicalAddr;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

    fn requested_icmp_listener(id: u16) -> RequestedConfig {
        RequestedConfig {
            listen_request: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, id)),
                id,
            ),
            listen_proto: SupportedProtocol::ICMP,
            listen_mode: if id == 0 {
                ListenMode::Dynamic
            } else {
                ListenMode::Fixed
            },
            listen_str: format!("127.0.0.1:{id}"),
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            upstream_request: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
                9,
            ),
            upstream_local_id: 0,
            upstream_proto: SupportedProtocol::UDP,
            upstream_str: String::from("127.0.0.1:9"),
            timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 60,
            max_payload: 1500,
            icmp_sync_pps: 0,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        }
    }

    #[test]
    fn realize_config_rejects_port_conflict() {
        let mut cfg = requested_icmp_listener(0);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
        cfg.upstream_request = CanonicalAddr::new(addr, 8888);
        let listen = CanonicalAddr::new(addr, 8888);

        let res = realize_config(cfg, listen);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Port conflict"));
    }

    #[test]
    fn realize_config_rejects_fixed_id_listener_mismatch() {
        let requested = requested_icmp_listener(4242);
        let listen = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242)),
            1111,
        );
        let err = realize_config(requested, listen).expect_err("fixed-id mismatch must reject");
        assert!(
            err.to_string()
                .contains("requested id 4242 but socket local id is 1111"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn realize_config_rejects_fixed_id_listener_with_zero_realized_id() {
        let requested = requested_icmp_listener(4242);
        let listen = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242)),
            0,
        );
        let err =
            realize_config(requested, listen).expect_err("fixed-id listener must not accept id 0");
        assert!(
            err.to_string()
                .contains("requested id 4242 but socket local id is 0"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn realize_config_accepts_wildcard_listener_with_dynamic_realized_id() {
        let requested = requested_icmp_listener(0);
        let listen = CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            7777,
        );
        let runtime = realize_config(requested, listen).expect("wildcard listener must realize");
        assert_eq!(runtime.listen.id, 7777);
        assert_eq!(runtime.listen_mode, ListenMode::Dynamic);
    }

    #[test]
    fn parse_icmp_cli_target_accepts_bracketed_ipv6_remote_and_local_ids() {
        assert_eq!(
            parse_icmp_cli_target("[::1]:2002:1001", "--there", true).unwrap(),
            ParsedIcmpCliTarget {
                resolve_arg: String::from("[::1]:2002"),
                local_id: 1001,
            }
        );
    }

    #[test]
    fn parse_icmp_cli_target_accepts_bracketed_ipv6_single_id() {
        assert_eq!(
            parse_icmp_cli_target("[::1]:1234", "--there", true).unwrap(),
            ParsedIcmpCliTarget {
                resolve_arg: String::from("[::1]:1234"),
                local_id: 0,
            }
        );
    }

    #[test]
    fn parse_icmp_cli_target_rejects_bare_ipv6_without_brackets() {
        let err = parse_icmp_cli_target("::1:1234", "--there", true).unwrap_err();
        assert!(err.contains("must use brackets"), "unexpected error: {err}");
    }
}
