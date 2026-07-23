use super::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ParsedEndpointTarget,
    RequestedConfig, ReresolveMode, RuntimeOptions, SupportedProtocol, TimeoutAction,
    WorkerFlowMode, parse_endpoint_target, realize_config,
};
use crate::endpoint::LogicalEndpoint;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

fn requested_icmp_listener(id: u16) -> RequestedConfig {
    RequestedConfig {
        listen_request: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, id)),
            id,
        ),
        listener_source_id_request: IcmpReplyIdRequest::Default,
        listener_reply_id_request: IcmpReplyIdRequest::Default,
        listen_proto: SupportedProtocol::ICMP,
        listen_mode: if id == 0 {
            ListenMode::Dynamic
        } else {
            ListenMode::Fixed
        },
        listen_str: format!("127.0.0.1:{id}"),
        upstream_request: LogicalEndpoint::from_socket_addr_with_id(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)),
            9,
        ),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::UDP,
        upstream_str: String::from("127.0.0.1:9"),
        options: RuntimeOptions {
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            timeout_secs: 10,
            icmp_handshake_timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 60,
            max_payload: 1500,
            icmp_sync_pps: 0,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            debug_reresolve_address_file: None,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        },
    }
}

#[test]
fn realize_config_rejects_port_conflict() {
    let mut cfg = requested_icmp_listener(0);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888);
    cfg.upstream_request = LogicalEndpoint::from_socket_addr_with_id(addr, 8888);
    let listen = LogicalEndpoint::from_socket_addr_with_id(addr, 8888);

    let res = realize_config(cfg, listen);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Port conflict"));
}

#[test]
fn realize_config_moves_every_runtime_option_unchanged() {
    let requested = requested_icmp_listener(0);
    let expected = requested.options.clone();
    let listen = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4242)),
        4242,
    );

    let realized = realize_config(requested, listen).expect("realize wildcard listener");

    assert_eq!(realized.options, expected);
}

#[test]
fn realize_config_rejects_fixed_id_listener_mismatch() {
    let requested = requested_icmp_listener(4242);
    let listen = LogicalEndpoint::from_socket_addr_with_id(
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
    let listen = LogicalEndpoint::from_socket_addr_with_id(
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
    let listen = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        7777,
    );
    let runtime = realize_config(requested, listen).expect("wildcard listener must realize");
    assert_eq!(runtime.listen.id(), 7777);
    assert_eq!(runtime.listen_mode, ListenMode::Dynamic);
    assert_eq!(
        runtime.listener_reply_id_request,
        IcmpReplyIdRequest::Default
    );
}

#[test]
fn realize_config_preserves_explicit_listener_reply_id() {
    let mut requested = requested_icmp_listener(1001);
    requested.listener_reply_id_request = IcmpReplyIdRequest::Fixed(2002);
    let listen = LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001)),
        1001,
    );
    let runtime = realize_config(requested, listen).expect("reply id must realize");
    assert_eq!(runtime.listen.id(), 1001);
    assert_eq!(
        runtime.listener_reply_id_request,
        IcmpReplyIdRequest::Fixed(2002)
    );
}

#[test]
fn parse_endpoint_target_accepts_bracketed_ipv6_with_id() {
    assert_eq!(
        parse_endpoint_target("ICMP:[::1]:9999", "--there").unwrap(),
        ParsedEndpointTarget {
            proto: SupportedProtocol::ICMP,
            host: String::from("[::1]"),
            id: 9999,
        }
    );
}

#[test]
fn parse_endpoint_target_accepts_udp_with_id() {
    assert_eq!(
        parse_endpoint_target("UDP:127.0.0.1:0", "--here").unwrap(),
        ParsedEndpointTarget {
            proto: SupportedProtocol::UDP,
            host: String::from("127.0.0.1"),
            id: 0,
        }
    );
}

#[test]
fn parse_endpoint_target_rejects_old_positional_icmp_ids() {
    let err = parse_endpoint_target("ICMP:127.0.0.1:9999:40000", "--there").unwrap_err();
    assert!(
        err.contains("exactly one endpoint ID"),
        "unexpected error: {err}"
    );
}

#[test]
fn parse_endpoint_target_rejects_host_only_endpoint() {
    let err = parse_endpoint_target("UDP:127.0.0.1", "--here").unwrap_err();
    assert!(
        err.contains("UDP:<host>:<id>") || err.contains("ICMP:<host>:<id>"),
        "unexpected error: {err}"
    );
}

#[test]
fn parse_endpoint_target_rejects_bare_ipv6_without_brackets() {
    let err = parse_endpoint_target("ICMP:::1", "--there").unwrap_err();
    assert!(err.contains("IPv6"), "unexpected error: {err}");
}

#[test]
fn reresolve_mode_parse_and_allow_matrix_is_complete() {
    let cases = [
        ("none", ReresolveMode::None, false, false),
        ("upstream", ReresolveMode::Upstream, true, false),
        ("listen", ReresolveMode::Listen, false, true),
        ("both", ReresolveMode::Both, true, true),
    ];

    for (text, mode, allow_upstream, allow_listen) in cases {
        let parsed = ReresolveMode::from_str(text).expect("mode should parse");
        assert_eq!(parsed, mode);
        assert_eq!(parsed.allow_upstream(), allow_upstream, "{text}");
        assert_eq!(parsed.allow_listen(), allow_listen, "{text}");
    }

    assert_eq!(ReresolveMode::from_str("invalid"), None);
}
