use pkthere_test_support::socket_reality::case::RealityCase;
use pkthere_test_support::socket_reality::case::RealityOperation;
use pkthere_test_support::socket_reality::requirement::{
    RealityProfile, RealityRequirement, requirements,
};
use pkthere_test_support::socket_reality::{collect, diagnostic, verify};
use pkthere_wire::SupportedProtocol;
use socket2::Type;

#[test]
fn udp_reality_matches_policy() {
    run_requirements(RealityProfile::Native, |case| {
        case.protocol == SupportedProtocol::UDP
    });
}

#[test]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "macos")),
    ignore = "the target policy does not expose ICMP DGRAM echo sockets"
)]
fn icmp_dgram_reality_matches_policy() {
    run_requirements(RealityProfile::Native, |case| {
        case.protocol == SupportedProtocol::ICMP && case.socket_type == Type::DGRAM
    });
}

#[test]
#[ignore = "privileged RAW socket reality runs explicitly after platform capability setup"]
fn raw_icmp_forwarder_packet_dump_matches_policy() {
    run_requirements(RealityProfile::Privileged, |case| {
        case.protocol == SupportedProtocol::ICMP && case.socket_type == Type::RAW
    });
}

fn run_requirements(profile: RealityProfile, include: impl Fn(RealityCase) -> bool) {
    for requirement in requirements(profile)
        .into_iter()
        .filter(|requirement| capability_supports(requirement.case))
        .filter(|requirement| include(requirement.case))
    {
        run_requirement(requirement);
    }
}

fn capability_supports(case: RealityCase) -> bool {
    case.operation != RealityOperation::RawFourIdForwarding
        || cfg!(windows)
        || pkthere_test_support::runtime_capability::raw_to_bound_raw_icmp_requests()
}

fn run_requirement(requirement: RealityRequirement) {
    let case = requirement.case;
    let evidence = collect::collect(&case)
        .unwrap_or_else(|error| panic!("collect socket reality for {case:?}: {error}"));
    let verified = verify::verify_requirement(requirement, &evidence).unwrap_or_else(|error| {
        panic!("verify socket reality for {case:?}: {error}\nrecorded evidence:\n{evidence:#?}")
    });
    eprintln!(
        "socket-reality {}",
        diagnostic::diagnostic_json(&verified, &evidence)
    );
}
