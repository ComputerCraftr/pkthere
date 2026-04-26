use socket2::{Domain, Protocol, Socket, Type};

#[path = "src/net/icmp_parse.rs"]
mod icmp_parse;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(supports_kernel_icmp_echo)");
    println!("cargo::rustc-check-cfg=cfg(supports_raw_icmp_capability)");

    let allow_raw_env = std::env::var("PKTHERE_ALLOW_RAW_ICMP")
        .map(|v| v == "1")
        .unwrap_or(false);
    let allow_kernel_echo_env = std::env::var("PKTHERE_ALLOW_KERNEL_ICMP_ECHO")
        .map(|v| v == "1")
        .unwrap_or(false);

    // 1. Probe for raw ICMP capability (SOCK_RAW)
    if allow_raw_env || Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok() {
        println!("cargo:rustc-cfg=supports_raw_icmp_capability");
    }

    // 2. Probe for kernel echo response (can work via DGRAM or RAW)
    if allow_kernel_echo_env || icmp_parse::probe_kernel_icmp_echo().is_ok() {
        println!("cargo:rustc-cfg=supports_kernel_icmp_echo");
    }

    println!("cargo:rerun-if-env-changed=PKTHERE_ALLOW_RAW_ICMP");
    println!("cargo:rerun-if-env-changed=PKTHERE_ALLOW_KERNEL_ICMP_ECHO");
    println!("cargo:rerun-if-changed=build.rs");
}
