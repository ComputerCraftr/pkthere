pub fn icmp_dgram_echo() -> bool {
    true
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

pub fn raw_icmp_socket_io() -> bool {
    raw_icmp_enabled()
}

pub fn dgram_to_bound_raw_icmp_requests() -> bool {
    raw_icmp_enabled()
        && pkthere_socket_policy::current_icmp_platform_capabilities().dgram_to_bound_raw_loopback
}

pub fn raw_to_bound_raw_icmp_requests() -> bool {
    raw_icmp_enabled()
        && pkthere_socket_policy::current_icmp_platform_capabilities().raw_to_bound_raw_loopback
}

pub fn production_raw_icmp_forwarding() -> bool {
    raw_icmp_enabled()
}
