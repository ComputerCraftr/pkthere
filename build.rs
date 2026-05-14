#[path = "build_support/icmp_probe.rs"]
mod icmp_probe;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(supports_kernel_icmp_echo)");
    println!("cargo::rustc-check-cfg=cfg(supports_raw_icmp_capability)");

    let allow_raw_env = std::env::var("PKTHERE_ALLOW_RAW_ICMP")
        .map(|v| v == "1")
        .unwrap_or(false);
    let allow_kernel_echo_env = std::env::var("PKTHERE_ALLOW_KERNEL_ICMP_ECHO")
        .map(|v| v == "1")
        .unwrap_or(false);

    // 1. Probe for requested-bound RAW ICMP delivery, not only SOCK_RAW creation.
    if allow_raw_env || icmp_probe::probe_raw_icmp_capability().is_ok() {
        println!("cargo:rustc-cfg=supports_raw_icmp_capability");
    }

    // 2. Probe for kernel echo response (can work via DGRAM or RAW)
    if allow_kernel_echo_env || icmp_probe::probe_kernel_icmp_echo().is_ok() {
        println!("cargo:rustc-cfg=supports_kernel_icmp_echo");
    }

    println!("cargo:rerun-if-env-changed=PKTHERE_ALLOW_RAW_ICMP");
    println!("cargo:rerun-if-env-changed=PKTHERE_ALLOW_KERNEL_ICMP_ECHO");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/icmp_probe.rs");
    println!("cargo:rerun-if-changed=src/net/icmp_echo_parse.rs");
}
