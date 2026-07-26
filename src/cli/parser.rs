use super::{
    DEFAULT_ICMP_SESSION_POOL_SIZE, DEFAULT_ICMP_SYNC_PPS, DEFAULT_MAX_PAYLOAD,
    DEFAULT_RERESOLVE_SECS, DEFAULT_STATS_INTERVAL_MINS, DEFAULT_TIMEOUT_SECS, DEFAULT_WORKERS,
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, LogicalEndpoint,
    MAX_ICMP_HANDSHAKE_TIMEOUT_SECS, MAX_ICMP_SESSION_POOL_SIZE, MAX_WORKER_PAIRS,
    ParsedEndpointTarget, RequestedConfig, ReresolveMode, RuntimeOptions, SupportedProtocol,
    TimeoutAction, WorkerFlowMode, id_request_from_u16, parse_endpoint_target, resolve_host_id,
};
use crate::net::params::{
    MAX_SAFE_ICMP_IPV4_PAYLOAD, MAX_SAFE_ICMP_IPV6_PAYLOAD, MAX_SAFE_UDP_IPV4_PAYLOAD,
    MAX_SAFE_UDP_IPV6_PAYLOAD,
};
use std::env;
use std::iter::Peekable;
use std::path::PathBuf;
use std::process;

#[derive(Default)]
struct EndpointArguments {
    listen: Option<ParsedEndpointTarget>,
    upstream: Option<ParsedEndpointTarget>,
    here_source_id: Option<u16>,
    here_reply_id: Option<u16>,
    there_source_id: Option<u16>,
    there_reply_id: Option<u16>,
}

#[derive(Default)]
struct RuntimeArguments {
    timeout_secs: Option<u64>,
    icmp_handshake_timeout_secs: Option<u64>,
    on_timeout: Option<TimeoutAction>,
    stats_interval_mins: Option<u32>,
    max_payload: Option<usize>,
    icmp_sync_pps: Option<u32>,
    icmp_session_pool_size: Option<usize>,
    workers: Option<usize>,
    worker_flow_mode: Option<WorkerFlowMode>,
    reresolve_secs: Option<u64>,
    reresolve_mode: Option<ReresolveMode>,
    debug_reresolve_address_file: Option<PathBuf>,
}

#[derive(Default)]
struct PrivilegeArguments {
    #[cfg(unix)]
    run_as_user: Option<String>,
    #[cfg(unix)]
    run_as_group: Option<String>,
}

#[derive(Default)]
struct DebugArguments {
    behavior: DebugBehavior,
    logs: DebugLogs,
}

#[derive(Default)]
struct ParsedArguments {
    endpoints: EndpointArguments,
    runtime: RuntimeArguments,
    privilege: PrivilegeArguments,
    debug: DebugArguments,
}

struct ResolvedEndpoints {
    listen_request: LogicalEndpoint,
    listen_proto: SupportedProtocol,
    listen_mode: ListenMode,
    listen_str: String,
    upstream_request: LogicalEndpoint,
    upstream_proto: SupportedProtocol,
    upstream_str: String,
}

pub(crate) fn parse_args() -> RequestedConfig {
    let mut parsed = ParsedArguments::default();
    let mut arguments = env::args().skip(1).peekable();
    while let Some(argument) = arguments.next() {
        if parsed.endpoints.parse(&argument, &mut arguments)
            || parsed.runtime.parse_primary(&argument, &mut arguments)
            || parsed
                .runtime
                .parse_worker_and_resolution(&argument, &mut arguments)
            || parsed.privilege.parse(&argument, &mut arguments)
            || parsed.debug.parse(&argument, &mut arguments)
        {
            continue;
        }
        match argument.as_str() {
            "-h" | "--help" => print_usage_and_exit(0),
            other => {
                log_error!("unknown arg: {other}");
                print_usage_and_exit(2)
            }
        }
    }
    parsed.finish()
}

impl EndpointArguments {
    fn parse<I>(&mut self, argument: &str, values: &mut Peekable<I>) -> bool
    where
        I: Iterator<Item = String>,
    {
        let (slot, flag) = match argument {
            "--here" => (&mut self.listen, "--here"),
            "--there" => (&mut self.upstream, "--there"),
            _ => {
                let (slot, flag) = match argument {
                    "--here-source-id" => (&mut self.here_source_id, "--here-source-id"),
                    "--here-reply-id" => (&mut self.here_reply_id, "--here-reply-id"),
                    "--there-source-id" => (&mut self.there_source_id, "--there-source-id"),
                    "--there-reply-id" => (&mut self.there_reply_id, "--there-reply-id"),
                    _ => return false,
                };
                let value = next_value(values, flag);
                set_once(slot, parse_num(&value, flag), flag);
                return true;
            }
        };
        let value = next_value(values, flag);
        let endpoint = parse_endpoint_target(&value, flag).unwrap_or_else(|message| {
            log_error!("{message}");
            print_usage_and_exit(2)
        });
        set_once(slot, endpoint, flag);
        true
    }
}

impl RuntimeArguments {
    fn parse_primary<I>(&mut self, argument: &str, values: &mut Peekable<I>) -> bool
    where
        I: Iterator<Item = String>,
    {
        let flag = argument;
        match argument {
            "--timeout-secs" => set_once(
                &mut self.timeout_secs,
                parse_num(&next_value(values, flag), flag),
                flag,
            ),
            "--icmp-handshake-timeout-secs" => set_once(
                &mut self.icmp_handshake_timeout_secs,
                parse_num(&next_value(values, flag), flag),
                flag,
            ),
            "--on-timeout" => {
                let value = next_value(values, flag);
                let action = match value.as_str() {
                    "drop" => TimeoutAction::Drop,
                    "exit" => TimeoutAction::Exit,
                    _ => {
                        log_error!("--on-timeout must be drop|exit");
                        print_usage_and_exit(2)
                    }
                };
                set_once(&mut self.on_timeout, action, flag);
            }
            "--stats-interval-mins" => set_once(
                &mut self.stats_interval_mins,
                parse_num(&next_value(values, flag), flag),
                flag,
            ),
            "--max-payload" => {
                let value = parse_num(&next_value(values, flag), flag);
                if value > MAX_SAFE_UDP_IPV6_PAYLOAD {
                    log_error!(
                        "--max-payload must be <= {} (requested {})",
                        MAX_SAFE_UDP_IPV6_PAYLOAD,
                        value
                    );
                    print_usage_and_exit(2);
                }
                set_once(&mut self.max_payload, value, flag);
            }
            "--icmp-sync-pps" => set_once(
                &mut self.icmp_sync_pps,
                parse_num(&next_value(values, flag), flag),
                flag,
            ),
            "--icmp-session-pool-size" => {
                let value = parse_num(&next_value(values, flag), flag);
                if !(1..=MAX_ICMP_SESSION_POOL_SIZE).contains(&value) {
                    log_error!(
                        "--icmp-session-pool-size must be between 1 and {}",
                        MAX_ICMP_SESSION_POOL_SIZE
                    );
                    print_usage_and_exit(2);
                }
                set_once(&mut self.icmp_session_pool_size, value, flag);
            }
            _ => return false,
        }
        true
    }

    fn parse_worker_and_resolution<I>(&mut self, argument: &str, values: &mut Peekable<I>) -> bool
    where
        I: Iterator<Item = String>,
    {
        let flag = argument;
        match argument {
            "--workers" => {
                let value = parse_num(&next_value(values, flag), flag);
                if !(1..=MAX_WORKER_PAIRS).contains(&value) {
                    log_error!("--workers must be between 1 and {MAX_WORKER_PAIRS}");
                    print_usage_and_exit(2);
                }
                set_once(&mut self.workers, value, flag);
            }
            "--worker-flow-mode" => {
                let value = next_value(values, flag);
                let mode = WorkerFlowMode::from_str(&value).unwrap_or_else(|| {
                    log_error!(
                        "--worker-flow-mode must be shared-flow|single-flow (got '{value}')"
                    );
                    print_usage_and_exit(2)
                });
                set_once(&mut self.worker_flow_mode, mode, flag);
            }
            "--reresolve-secs" => set_once(
                &mut self.reresolve_secs,
                parse_num(&next_value(values, flag), flag),
                flag,
            ),
            "--reresolve-mode" => {
                let value = next_value(values, flag);
                let mode = ReresolveMode::from_str(&value).unwrap_or_else(|| {
                    log_error!(
                        "--reresolve-mode must be upstream|listen|both|none (got '{value}')"
                    );
                    print_usage_and_exit(2)
                });
                set_once(&mut self.reresolve_mode, mode, flag);
            }
            "--debug-reresolve-address-file" => set_once(
                &mut self.debug_reresolve_address_file,
                PathBuf::from(next_value(values, flag)),
                flag,
            ),
            _ => return false,
        }
        true
    }
}

impl PrivilegeArguments {
    fn parse<I>(&mut self, argument: &str, values: &mut Peekable<I>) -> bool
    where
        I: Iterator<Item = String>,
    {
        #[cfg(unix)]
        match argument {
            "--user" => set_once(
                &mut self.run_as_user,
                next_value(values, "--user"),
                "--user",
            ),
            "--group" => set_once(
                &mut self.run_as_group,
                next_value(values, "--group"),
                "--group",
            ),
            _ => return false,
        }
        #[cfg(not(unix))]
        {
            drop((argument, values));
            return false;
        }
        #[cfg(unix)]
        return true;
    }
}

impl DebugArguments {
    fn parse<I>(&mut self, argument: &str, values: &mut Peekable<I>) -> bool
    where
        I: Iterator<Item = String>,
    {
        match argument {
            "--debug-client-unconnected" => self.behavior.client_unconnected = true,
            "--debug-upstream-unconnected" => self.behavior.upstream_unconnected = true,
            "--debug-icmp-kernel-echo-self-handshake" => {
                self.behavior.icmp_kernel_echo_self_handshake = true;
            }
            "--debug-force-raw-icmp-wildcard-upstream" => {
                self.behavior.force_raw_icmp_wildcard_upstream = true;
            }
            "--debug-fast-stats" => self.behavior.fast_stats = true,
            "--debug-log" => {
                let value = next_value(values, "--debug-log");
                match value.as_str() {
                    "drops" => self.logs.drops = true,
                    "handshake" => self.logs.handshake = true,
                    "handles" => self.logs.handles = true,
                    "packets" => self.logs.packets = true,
                    "packet-dump" => self.logs.packet_dump = true,
                    _ => {
                        log_error!(
                            "--debug-log expects exactly one of drops, handshake, handles, packets, or packet-dump per flag occurrence (got '{value}')"
                        );
                        print_usage_and_exit(2)
                    }
                }
            }
            _ => return false,
        }
        true
    }
}

impl ParsedArguments {
    fn finish(self) -> RequestedConfig {
        let endpoints = resolve_endpoints(&self.endpoints);
        validate_protocol_options(&self, &endpoints);
        let options = build_runtime_options(self.runtime, self.privilege, self.debug, &endpoints);
        let listener_source_id_request =
            listener_id_request(endpoints.listen_proto, self.endpoints.here_source_id);
        let listener_reply_id_request =
            listener_id_request(endpoints.listen_proto, self.endpoints.here_reply_id);
        let upstream_source_id_request = self
            .endpoints
            .there_source_id
            .map_or(IcmpReplyIdRequest::Default, id_request_from_u16);
        let upstream_reply_id_request =
            listener_id_request(endpoints.upstream_proto, self.endpoints.there_reply_id);
        RequestedConfig {
            listen_request: endpoints.listen_request,
            listener_source_id_request,
            listener_reply_id_request,
            listen_proto: endpoints.listen_proto,
            listen_mode: endpoints.listen_mode,
            listen_str: endpoints.listen_str,
            upstream_request: endpoints.upstream_request,
            upstream_source_id_request,
            upstream_reply_id_request,
            upstream_proto: endpoints.upstream_proto,
            upstream_str: endpoints.upstream_str,
            options,
        }
    }
}

fn resolve_endpoints(arguments: &EndpointArguments) -> ResolvedEndpoints {
    let listen = arguments.listen.as_ref().unwrap_or_else(|| {
        log_error!("missing required flag: --here UDP:<host>:<id>|ICMP:<host>:<id>");
        print_usage_and_exit(2)
    });
    let upstream = arguments.upstream.as_ref().unwrap_or_else(|| {
        log_error!("missing required flag: --there UDP:<host>:<id>|ICMP:<host>:<id>");
        print_usage_and_exit(2)
    });
    let (listen_str, listen_request) = resolve_host_id(&listen.host, listen.id, "--here");
    let (upstream_str, upstream_request) = resolve_host_id(&upstream.host, upstream.id, "--there");
    ResolvedEndpoints {
        listen_request,
        listen_proto: listen.proto,
        listen_mode: if listen.id == 0 {
            ListenMode::Dynamic
        } else {
            ListenMode::Fixed
        },
        listen_str,
        upstream_request,
        upstream_proto: upstream.proto,
        upstream_str,
    }
}

fn validate_protocol_options(arguments: &ParsedArguments, endpoints: &ResolvedEndpoints) {
    let ids = &arguments.endpoints;
    if endpoints.listen_proto == SupportedProtocol::UDP
        && (ids.here_source_id.is_some() || ids.here_reply_id.is_some())
    {
        cli_error(
            "UDP listeners use the --here UDP:<host>:<port> endpoint ID only; --here-source-id/--here-reply-id are ICMP-only",
        );
    }
    if endpoints.upstream_proto == SupportedProtocol::UDP && ids.there_reply_id.is_some() {
        cli_error("UDP upstreams do not support --there-reply-id");
    }
    if arguments.runtime.icmp_sync_pps.is_some()
        && endpoints.upstream_proto != SupportedProtocol::ICMP
    {
        cli_error("--icmp-sync-pps requires --there ICMP:<host>:<id>");
    }
    if arguments.runtime.icmp_session_pool_size.is_some()
        && endpoints.listen_proto != SupportedProtocol::ICMP
        && endpoints.upstream_proto != SupportedProtocol::ICMP
    {
        cli_error("--icmp-session-pool-size requires an ICMP listener or upstream");
    }
    if arguments.debug.behavior.icmp_kernel_echo_self_handshake
        && endpoints.upstream_proto != SupportedProtocol::ICMP
    {
        cli_error("--debug-icmp-kernel-echo-self-handshake requires --there ICMP:<host>:<id>");
    }
    let upstream_reply_id = ids
        .there_reply_id
        .map_or(IcmpReplyIdRequest::Default, id_request_from_u16);
    if arguments.debug.behavior.force_raw_icmp_wildcard_upstream
        && (endpoints.upstream_proto != SupportedProtocol::ICMP
            || endpoints.upstream_request.id() != 0
            || upstream_reply_id.requested_socket_id() != 0)
    {
        cli_error(
            "--debug-force-raw-icmp-wildcard-upstream requires wildcard --there ICMP:<host>:0",
        );
    }
    if endpoints.upstream_proto == SupportedProtocol::UDP && endpoints.upstream_request.id() == 0 {
        cli_error(
            "--there UDP:host:0 is invalid: UDP upstream requires a fixed remote destination port",
        );
    }
}

fn build_runtime_options(
    arguments: RuntimeArguments,
    privilege: PrivilegeArguments,
    debug: DebugArguments,
    endpoints: &ResolvedEndpoints,
) -> RuntimeOptions {
    #[cfg(not(unix))]
    let PrivilegeArguments {} = privilege;
    let timeout_secs = arguments.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let handshake_timeout = arguments
        .icmp_handshake_timeout_secs
        .unwrap_or(timeout_secs);
    if handshake_timeout > MAX_ICMP_HANDSHAKE_TIMEOUT_SECS {
        cli_error(&format!(
            "--icmp-handshake-timeout-secs must be <= {MAX_ICMP_HANDSHAKE_TIMEOUT_SECS}"
        ));
    }
    let max_payload = arguments.max_payload.unwrap_or(DEFAULT_MAX_PAYLOAD);
    let absolute_max = maximum_payload(endpoints);
    if max_payload > absolute_max {
        cli_error(&format!(
            "--max-payload {max_payload} exceeds the maximum supported by the selected protocols and address families ({absolute_max})"
        ));
    }
    RuntimeOptions {
        workers: arguments.workers.unwrap_or(DEFAULT_WORKERS),
        worker_flow_mode: arguments
            .worker_flow_mode
            .unwrap_or(WorkerFlowMode::SharedFlow),
        timeout_secs,
        icmp_handshake_timeout_secs: handshake_timeout,
        on_timeout: arguments.on_timeout.unwrap_or(TimeoutAction::Drop),
        stats_interval_mins: arguments
            .stats_interval_mins
            .unwrap_or(DEFAULT_STATS_INTERVAL_MINS),
        max_payload,
        icmp_sync_pps: arguments.icmp_sync_pps.unwrap_or(DEFAULT_ICMP_SYNC_PPS),
        icmp_session_pool_size: arguments
            .icmp_session_pool_size
            .unwrap_or(DEFAULT_ICMP_SESSION_POOL_SIZE),
        reresolve_secs: arguments.reresolve_secs.unwrap_or(DEFAULT_RERESOLVE_SECS),
        reresolve_mode: arguments.reresolve_mode.unwrap_or(ReresolveMode::Upstream),
        debug_reresolve_address_file: arguments.debug_reresolve_address_file,
        #[cfg(unix)]
        run_as_user: privilege.run_as_user,
        #[cfg(unix)]
        run_as_group: privilege.run_as_group,
        debug_behavior: debug.behavior,
        debug_logs: debug.logs,
    }
}

fn maximum_payload(endpoints: &ResolvedEndpoints) -> usize {
    let includes_ipv4 =
        endpoints.listen_request.ip().is_ipv4() || endpoints.upstream_request.ip().is_ipv4();
    let includes_icmp = endpoints.listen_proto == SupportedProtocol::ICMP
        || endpoints.upstream_proto == SupportedProtocol::ICMP;
    match (includes_ipv4, includes_icmp) {
        (true, true) => MAX_SAFE_ICMP_IPV4_PAYLOAD,
        (true, false) => MAX_SAFE_UDP_IPV4_PAYLOAD,
        (false, true) => MAX_SAFE_ICMP_IPV6_PAYLOAD,
        (false, false) => MAX_SAFE_UDP_IPV6_PAYLOAD,
    }
}

fn listener_id_request(protocol: SupportedProtocol, value: Option<u16>) -> IcmpReplyIdRequest {
    if protocol == SupportedProtocol::ICMP {
        value.map_or(IcmpReplyIdRequest::Default, id_request_from_u16)
    } else {
        IcmpReplyIdRequest::Default
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) {
    if slot.replace(value).is_some() {
        log_error!("{flag} specified multiple times");
        print_usage_and_exit(2);
    }
}

fn parse_num<T>(value: &str, flag: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse().unwrap_or_else(|error| {
        log_error!("invalid {flag}: {error}");
        print_usage_and_exit(2)
    })
}

fn next_value<I>(values: &mut Peekable<I>, flag: &str) -> String
where
    I: Iterator<Item = String>,
{
    values.next().unwrap_or_else(|| {
        log_error!("{flag} requires a value");
        print_usage_and_exit(2)
    })
}

fn cli_error(message: &str) -> ! {
    log_error!("{message}");
    print_usage_and_exit(2)
}

fn print_usage_and_exit(code: i32) -> ! {
    let program = env::args()
        .next()
        .unwrap_or_else(|| String::from("pkthere"));
    log_error!(
        "Usage: {program} --here <protocol:host:id> --there <protocol:host:id>\n\
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
         \t--icmp-session-pool-size N\n\
         \t                         Ready reserve sessions per ICMP transmit leg (1..=32, default: 4)\n\
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
