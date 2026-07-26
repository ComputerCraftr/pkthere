use super::FlowClaimTable;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::ClientFlowKey;
use crate::flow_state::FlowRuntimeState;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn distinct_flows_can_be_claimed_by_distinct_workers() {
    let claims = FlowClaimTable::new();
    let a = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        1000,
    )));
    let b = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        1001,
    )));
    assert!(claims.try_claim(a, 0).is_ok());
    assert!(claims.try_claim(b, 1).is_ok());
}

#[test]
fn same_flow_is_claimed_by_only_one_worker() {
    let claims = FlowClaimTable::new();
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        1000,
    )));
    let first = claims.try_claim(flow, 0).expect("first claim");
    let generation = first.generation();
    first.commit();
    assert!(claims.try_claim(flow, 1).is_err());
    claims
        .take_committed(flow, 0, generation)
        .expect("take exact committed claim")
        .release();
    assert!(claims.try_claim(flow, 1).is_ok());
}

#[test]
fn concurrent_workers_cannot_claim_and_connect_the_same_tuple() {
    let claims = Arc::new(FlowClaimTable::new());
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        1002,
    )));
    let barrier = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|worker_pair_id| {
            let claims = Arc::clone(&claims);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                match claims.try_claim(flow, worker_pair_id) {
                    Ok(claim) => {
                        claim.commit();
                        true
                    }
                    Err(()) => false,
                }
            })
        })
        .collect::<Vec<_>>();

    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("join flow claimant"))
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes.into_iter().filter(|claimed| *claimed).count(),
        1,
        "exactly one worker may own a tuple before any socket association"
    );
}

#[test]
fn flow_claim_is_a_distinct_authority_inside_a_flow_writer() {
    let state = FlowRuntimeState::new();
    let _flow_writer = state.reserve_client_flow();
    let claims = FlowClaimTable::new();
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        1003,
    )));

    assert!(claims.try_claim(flow, 0).is_ok());
}

#[test]
fn delayed_old_generation_cannot_release_a_new_claim() {
    let claims = FlowClaimTable::new();
    let flow = ClientFlowKey::Udp(LogicalEndpoint::from_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        1004,
    )));
    let first = claims.try_claim(flow, 0).expect("first claim");
    let first_generation = first.generation();
    first.commit();
    claims
        .take_committed(flow, 0, first_generation)
        .expect("first committed claim")
        .release();

    let second = claims.try_claim(flow, 1).expect("second claim");
    let second_generation = second.generation();
    second.commit();
    assert!(claims.take_committed(flow, 0, first_generation).is_err());
    assert!(claims.take_committed(flow, 1, second_generation).is_ok());
}
