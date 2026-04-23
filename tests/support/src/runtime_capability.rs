use pkthere_socket_policy::current_icmp_platform_capabilities;

pub fn icmp_dgram_echo() -> bool {
    current_icmp_platform_capabilities().datagram_echo_sockets
}

pub fn enabled_forward_protocols() -> &'static [&'static str] {
    if icmp_dgram_echo() {
        &["UDP", "ICMP"]
    } else {
        &["UDP"]
    }
}

pub fn raw_icmp_enabled() -> bool {
    std::env::var("PKTHERE_ALLOW_RAW_ICMP").is_ok_and(|value| value == "1")
}

pub fn dgram_to_bound_raw_icmp_requests() -> bool {
    raw_icmp_enabled() && current_icmp_platform_capabilities().dgram_to_bound_raw_loopback
}

pub fn raw_to_bound_raw_icmp_requests() -> bool {
    raw_icmp_enabled() && current_icmp_platform_capabilities().raw_to_bound_raw_loopback
}
