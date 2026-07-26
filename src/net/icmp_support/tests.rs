use super::choose_upstream_icmp_ids;
use pkthere_socket_policy::{
    IcmpPolicyIntent, ResolvedIcmpSocketPolicy, SocketRole, resolve_icmp_socket_policy_with_intent,
};
use socket2::Type;

fn raw_policy() -> ResolvedIcmpSocketPolicy {
    resolve_icmp_socket_policy_with_intent(
        SocketRole::Upstream,
        Type::RAW,
        IcmpPolicyIntent::default(),
    )
}

fn dgram_policy() -> ResolvedIcmpSocketPolicy {
    resolve_icmp_socket_policy_with_intent(
        SocketRole::Upstream,
        Type::DGRAM,
        IcmpPolicyIntent::default(),
    )
}

fn raw_collapsed_policy() -> ResolvedIcmpSocketPolicy {
    resolve_icmp_socket_policy_with_intent(
        SocketRole::Upstream,
        Type::RAW,
        IcmpPolicyIntent {
            disable_disjoint_ids: true,
            allow_debug_kernel_echo_self_handshake: false,
        },
    )
}

fn chosen_pair(decision: super::ChosenIcmpIds) -> (u16, u16) {
    (decision.local_id, decision.remote_id)
}

#[test]
fn upstream_icmp_id_selection_follows_priority_order() {
    // 1. Kernel assigned (wins even over request) -> forces BOTH local and remote
    assert_eq!(
        chosen_pair(choose_upstream_icmp_ids(11, 22, 5678, dgram_policy(),)),
        (5678, 5678)
    );
    assert_eq!(
        chosen_pair(choose_upstream_icmp_ids(0, 0, 5678, dgram_policy())),
        (5678, 5678)
    );

    // 2. User requested (when kernel is 0) -> independent IDs respected only for RAW.
    // Collapsed policies use one effective fixed ID when they cannot wait
    // for a kernel-assigned wildcard ID.
    assert_eq!(
        chosen_pair(choose_upstream_icmp_ids(1111, 2222, 0, raw_policy())),
        (1111, 2222)
    );
    assert_eq!(
        chosen_pair(choose_upstream_icmp_ids(
            1111,
            2222,
            0,
            raw_collapsed_policy(),
        )),
        (1111, 1111)
    );

    // 3. Generated (when both are 0) -> local and remote are independent for RAW.
    let decision = choose_upstream_icmp_ids(0, 0, 0, raw_policy());
    let (l, r) = chosen_pair(decision);
    assert_ne!(l, 0);
    assert_ne!(r, 0);
    assert_ne!(l, r);

    // A kernel-assigned DGRAM-ID policy defers until getsockname reports
    // the realized ping ID. Fixed collapsed policies generate now.
    let decision = choose_upstream_icmp_ids(0, 0, 0, dgram_policy());
    let (l, r) = chosen_pair(decision);
    assert_eq!(l, r);
    if pkthere_socket_policy::current_icmp_platform_capabilities().kernel_assigned_dgram_ids {
        assert_eq!(l, 0);
    } else {
        assert_ne!(l, 0);
    }
}

#[test]
fn dgram_wildcard_defers_until_kernel_reports_local_id() {
    let pre_kernel = chosen_pair(choose_upstream_icmp_ids(0, 0, 0, dgram_policy()));
    if pkthere_socket_policy::current_icmp_platform_capabilities().kernel_assigned_dgram_ids {
        assert_eq!(pre_kernel, (0, 0));
    } else {
        assert_ne!(pre_kernel.0, 0);
        assert_eq!(pre_kernel.0, pre_kernel.1);
    }
    assert_eq!(
        chosen_pair(choose_upstream_icmp_ids(0, 0, 5678, dgram_policy())),
        (5678, 5678)
    );
}

#[test]
fn raw_wildcard_generates_disjoint_capable_ids() {
    let decision = choose_upstream_icmp_ids(0, 0, 0, raw_policy());
    let (local, remote) = chosen_pair(decision);
    assert_ne!(local, 0);
    assert_ne!(remote, 0);
    assert_ne!(local, remote);
}

#[test]
fn raw_wildcard_ignores_reported_kernel_protocol_id_and_records_generation() {
    let decision = choose_upstream_icmp_ids(0, 0, 1, raw_policy());
    assert_ne!(decision.local_id, 1);
    assert_ne!(decision.local_id, 0);
    assert_ne!(decision.remote_id, 0);
    assert_ne!(decision.local_id, decision.remote_id);
    assert_eq!(decision.local_source, super::IcmpIdSource::Generated);
    assert_eq!(decision.remote_source, super::IcmpIdSource::Generated);
    assert_eq!(decision.ignored_kernel_id, Some(1));

    let decision = choose_upstream_icmp_ids(0, 0, 58, raw_policy());
    assert_ne!(decision.local_id, 58);
    assert_ne!(decision.remote_id, 58);
    assert_eq!(decision.ignored_kernel_id, Some(58));
}

#[test]
fn raw_fixed_ids_ignore_reported_kernel_protocol_id_and_record_requests() {
    let decision = choose_upstream_icmp_ids(1111, 2222, 1, raw_policy());
    assert_eq!(decision.local_id, 1111);
    assert_eq!(decision.remote_id, 2222);
    assert_eq!(decision.local_source, super::IcmpIdSource::Requested);
    assert_eq!(decision.remote_source, super::IcmpIdSource::Requested);
    assert_eq!(decision.ignored_kernel_id, Some(1));
}

#[test]
fn forced_raw_wildcard_uses_collapsed_no_disjoint_ids() {
    let decision = choose_upstream_icmp_ids(0, 0, 0, raw_collapsed_policy());
    let (local, remote) = chosen_pair(decision);
    assert_ne!(local, 0);
    assert_eq!(local, remote);
}

#[test]
fn raw_fixed_remote_default_local_generates_distinct_local_id() {
    let decision = choose_upstream_icmp_ids(0, 1101, 0, raw_policy());
    let (local, remote) = chosen_pair(decision);
    assert_ne!(local, 0);
    assert_eq!(remote, 1101);
    assert_ne!(local, remote);
}

#[test]
fn raw_fixed_same_id_is_preserved_when_explicitly_requested() {
    assert_eq!(
        chosen_pair(choose_upstream_icmp_ids(1101, 1101, 0, raw_policy())),
        (1101, 1101)
    );
}

#[test]
fn raw_policy_untrusts_protocol_number_one_from_getsockname() {
    // requested 0, kernel reports 1, is_raw_socket true -> should UNTRUST 1 and allocate an ID
    let decision = choose_upstream_icmp_ids(0, 0, 1, raw_policy());
    let (l, r) = chosen_pair(decision);
    assert_ne!(l, 1);
    assert_ne!(l, 0);
    assert_ne!(r, 0);
    assert_ne!(l, r);

    // requested 1, kernel reports 1, is_raw_socket true -> should STILL UNTRUST 1 if it's raw
    let decision = choose_upstream_icmp_ids(1, 1, 1, raw_policy());
    let (l, r) = chosen_pair(decision);
    assert_eq!(l, 1);
    assert_eq!(l, r);

    // requested 0, kernel reports 1, is_raw_socket false (DGRAM) -> should TRUST 1
    let decision = choose_upstream_icmp_ids(0, 0, 1, dgram_policy());
    let (l, r) = chosen_pair(decision);
    assert_eq!(l, 1);
    assert_eq!(l, r);
}

#[test]
fn raw_policy_untrusts_protocol_number_58_from_getsockname() {
    // mirroring the protocol 1 (IPv4) test for protocol 58 (IPv6).
    // requested 0, kernel reports 58, is_raw_socket true -> should UNTRUST 58 and allocate an ID
    let decision = choose_upstream_icmp_ids(0, 0, 58, raw_policy());
    let (l, r) = chosen_pair(decision);
    assert_ne!(l, 58);
    assert_ne!(l, 0);
    assert_ne!(r, 0);
    assert_ne!(l, r);

    // requested 58, kernel reports 58, is_raw_socket true -> should STILL UNTRUST 58 if it's raw
    let decision = choose_upstream_icmp_ids(58, 58, 58, raw_policy());
    let (l, r) = chosen_pair(decision);
    assert_eq!(l, 58);
    assert_eq!(l, r);

    // requested 0, kernel reports 58, is_raw_socket false (DGRAM) -> should TRUST 58
    let decision = choose_upstream_icmp_ids(0, 0, 58, dgram_policy());
    let (l, r) = chosen_pair(decision);
    assert_eq!(l, 58);
    assert_eq!(l, r);
}
