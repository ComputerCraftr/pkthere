use super::case::RealityCase;
use super::evidence::{
    CallResult, DirectSocketEvidence, ProbeSocketEvidence, RealityEvidence, SocketCall,
};
use super::names::{role_name, socket_type_name};
use super::policy_snapshot::policy_snapshot;
use super::verify::{DerivedFacts, VerifiedReality};
use pkthere_socket_policy::{
    ListenerWorkerDistribution, ListenerWorkerSocketPolicy, SocketCreateSpec, SocketCreationPolicy,
    SocketPostBindPolicy, listener_worker_socket_policy, socket_post_bind_policy,
};
use pkthere_wire::SupportedProtocol;
use serde_json::{Value, json};
use socket2::{Domain, Protocol};

pub fn diagnostic_json(verified: &VerifiedReality, evidence: &RealityEvidence) -> Value {
    json!({
        "requested_case": case_json(verified.requested),
        "production_socket_creation_policy": creation_policy_json(verified.creation_policy),
        "production_post_bind_policy": post_bind_policy_json(
            socket_post_bind_policy(verified.creation_policy.primary.path)
        ),
        "derived_facts": facts_json(&verified.facts),
        "production_policy": policy_snapshot(verified.policy),
        "listener_worker_socket_policy": listener_worker_policy_json(&verified.facts),
        "evidence": evidence_json(evidence),
    })
}

fn creation_policy_json(policy: SocketCreationPolicy) -> Value {
    json!({
        "primary": create_spec_json(policy.primary),
        "create_fallback": policy.create_fallback.map(create_spec_json),
    })
}

fn create_spec_json(spec: SocketCreateSpec) -> Value {
    json!({
        "domain": domain_name(spec.domain),
        "socket_type": socket_type_name(spec.socket_type),
        "protocol": spec.protocol.map(protocol_number),
        "path": format!("{:?}", spec.path),
    })
}

fn post_bind_policy_json(policy: SocketPostBindPolicy) -> Value {
    json!({
        "enable_windows_rcvall": policy.enable_windows_rcvall,
        "set_ipv4_header_included": policy.set_ipv4_header_included,
    })
}

fn listener_worker_policy_json(facts: &DerivedFacts) -> Value {
    let DerivedFacts::ReusePortFanout { receiver_count, .. } = facts else {
        return Value::Null;
    };
    worker_socket_policy_json(listener_worker_socket_policy(*receiver_count, true))
}

fn worker_socket_policy_json(policy: ListenerWorkerSocketPolicy) -> Value {
    json!({
        "reuse_address": policy.reuse_address,
        "reuse_port": policy.reuse_port,
        "distribution": match policy.distribution {
            ListenerWorkerDistribution::SingleSocket => "single-socket",
            ListenerWorkerDistribution::SharedState => "shared-state",
            ListenerWorkerDistribution::KernelFlowAffinity => "kernel-flow-affinity",
            ListenerWorkerDistribution::UnsupportedSeparateState =>
                "unsupported-separate-state",
        },
        "supports_requested_distribution": policy.supports_requested_distribution(),
    })
}

fn case_json(case: RealityCase) -> Value {
    json!({
        "domain": domain_name(case.domain),
        "protocol": protocol_name(case.protocol),
        "socket_type": socket_type_name(case.socket_type),
        "policy_role": role_name(case.policy_role),
        "connected": case.connected,
        "socket_path": format!("{:?}", case.socket_path),
        "target_domain": case.target_domain.map(domain_name),
        "operation": case.operation.wire_name(),
    })
}

fn facts_json(facts: &DerivedFacts) -> Value {
    match facts {
        DerivedFacts::Datagram {
            receiver,
            sender,
            source_metadata,
            byte_count,
        } => json!({
            "kind": "datagram",
            "receiver": receiver,
            "sender": sender,
            "source_metadata": source_metadata,
            "byte_count": byte_count,
        }),
        DerivedFacts::ConnectedFilter {
            rejected_peer_filtered,
            queued_wrong_peer_source_visible,
            accepted_peer_delivered,
        } => json!({
            "kind": "connected-filter",
            "rejected_peer_filtered": rejected_peer_filtered,
            "queued_wrong_peer_source_visible": queued_wrong_peer_source_visible,
            "accepted_peer_delivered": accepted_peer_delivered,
        }),
        DerivedFacts::IcmpDgram {
            requested_bind_id,
            requested_echo_id,
            kernel_receive_id,
            observed_echo_id,
            sequence,
            byte_count,
        } => json!({
            "kind": "icmp-dgram",
            "requested_bind_id": requested_bind_id,
            "requested_echo_id": requested_echo_id,
            "kernel_receive_id": kernel_receive_id,
            "observed_echo_id": observed_echo_id,
            "sequence": sequence,
            "byte_count": byte_count,
        }),
        DerivedFacts::ReusePortFanout {
            receiver_count,
            received_flow_counts,
            kernel_flow_affinity_required,
        } => json!({
            "kind": "reuse-port-fanout",
            "receiver_count": receiver_count,
            "received_flow_counts": received_flow_counts,
            "kernel_flow_affinity_required": kernel_flow_affinity_required,
        }),
        DerivedFacts::RawReceive {
            kernel_addr,
            observed_source_id,
            observed_echo_id,
            ip_header_present,
            source_metadata_present,
            id_observation,
        } => json!({
            "kind": "raw-receive",
            "kernel_addr": kernel_addr,
            "observed_source_id": observed_source_id,
            "observed_echo_id": observed_echo_id,
            "ip_header_present": ip_header_present,
            "source_metadata_present": source_metadata_present,
            "id_observation": format!("{id_observation:?}"),
        }),
        DerivedFacts::RawFourId {
            client_source_id,
            server_destination_id,
            server_source_id,
            client_reply_id,
            evidence_keys,
        } => json!({
            "kind": "raw-four-id",
            "client_source_id": client_source_id,
            "server_destination_id": server_destination_id,
            "server_source_id": server_source_id,
            "client_reply_id": client_reply_id,
            "evidence_key_count": evidence_keys.len(),
        }),
        DerivedFacts::Lifecycle {
            operation,
            old_key,
            new_key,
            observed_probe_ids,
        } => json!({
            "kind": "lifecycle",
            "operation": operation.wire_name(),
            "old_key": format!("{old_key:?}"),
            "new_key": format!("{new_key:?}"),
            "observed_probe_ids": observed_probe_ids,
        }),
    }
}

fn evidence_json(evidence: &RealityEvidence) -> Value {
    match evidence {
        RealityEvidence::DatagramReceive(evidence) => json!({
            "kind": "datagram-receive",
            "receiver": evidence.receiver.0,
            "sender": evidence.sender.0,
            "sockets": direct_json(&evidence.direct),
        }),
        RealityEvidence::ConnectedFilter(evidence) => json!({
            "kind": "connected-filter",
            "receiver": evidence.receiver.0,
            "accepted_peer": evidence.accepted_peer.0,
            "rejected_peer": evidence.rejected_peer.0,
            "sockets": direct_json(&evidence.direct),
        }),
        RealityEvidence::IcmpDgram(evidence) => json!({
            "kind": "icmp-dgram",
            "socket": evidence.socket.0,
            "sockets": direct_json(&evidence.direct),
        }),
        RealityEvidence::ReusePortFanout(evidence) => json!({
            "kind": "reuse-port-fanout",
            "receiver_count": evidence.receiver_count,
            "successful_bind_count": evidence.successful_bind_count,
            "sent_flow_count": evidence.sent_flow_count,
            "received_flow_counts": evidence.received_flow_counts,
            "error": evidence.error,
        }),
        RealityEvidence::RawReceive(evidence) => match evidence {
            super::evidence::RawReceiveEvidence::Direct { direct, socket } => json!({
                "kind": "raw-receive-direct",
                "socket": socket.0,
                "sockets": direct_json(direct),
            }),
            super::evidence::RawReceiveEvidence::ProductionForwarder(evidence) => json!({
                "kind": "raw-receive-forwarder",
                "processes": evidence.processes.iter().map(|process| json!({
                    "label": process.label,
                    "command_arguments": process.command_arguments,
                    "stdout_len": process.stdout.len(),
                    "stderr_len": process.stderr.len(),
                })).collect::<Vec<_>>(),
            }),
        },
        RealityEvidence::RawFourId(evidence) => json!({
            "kind": "raw-four-id",
            "processes": evidence.processes.iter().map(|process| json!({
                "label": process.label,
                "command_arguments": process.command_arguments,
                "exit_status": process.exit_status.map(|status| json!({
                    "code": status.code,
                    "success": status.success,
                })),
                "stdout_len": process.stdout.len(),
                "stderr_len": process.stderr.len(),
            })).collect::<Vec<_>>(),
            "client_sent_len": evidence.client_sent.len(),
            "client_received": call_result_json(&evidence.client_received, |bytes| json!({
                "byte_count": bytes.len(),
            })),
        }),
        RealityEvidence::Lifecycle(evidence) => json!({
            "kind": "lifecycle",
            "process": {
                "label": evidence.process.label,
                "command_arguments": evidence.process.command_arguments,
                "stdout_len": evidence.process.stdout.len(),
                "stderr_len": evidence.process.stderr.len(),
            },
            "client_send_count": evidence.client_sends.len(),
            "client_receive_count": evidence.client_receives.len(),
            "endpoint_observation_count": evidence.endpoint_observations.len(),
            "negative_observation_window_ms":
                evidence.negative_observation_window.as_millis(),
        }),
    }
}

fn direct_json(evidence: &DirectSocketEvidence) -> Value {
    Value::Array(evidence.sockets.iter().map(socket_json).collect())
}

fn socket_json(socket: &ProbeSocketEvidence) -> Value {
    json!({
        "socket_id": socket.create.socket_id.0,
        "create": {
            "domain": domain_name(socket.create.domain),
            "socket_type": socket_type_name(socket.create.socket_type),
            "protocol": socket.create.protocol.map(protocol_number),
            "result": call_result_json(&socket.create.result, |_| json!({})),
        },
        "calls": socket.calls.iter().map(|event| {
            let call = match &event.call {
                SocketCall::Bind { requested, result } => json!({
                    "call": "bind",
                    "requested": requested,
                    "result": call_result_json(result, |_| json!({})),
                }),
                SocketCall::Connect { target, result } => json!({
                    "call": "connect",
                    "target": target,
                    "result": call_result_json(result, |_| json!({})),
                }),
                SocketCall::GetSockName { result } => json!({
                    "call": "getsockname",
                    "result": call_result_json(result, |address| json!(address)),
                }),
                SocketCall::SetReadTimeout {
                    milliseconds,
                    result,
                } => json!({
                    "call": "set-read-timeout",
                    "milliseconds": milliseconds,
                    "result": call_result_json(result, |_| json!({})),
                }),
                SocketCall::Send { destination, bytes, result } => json!({
                    "call": "send",
                    "destination": destination,
                    "byte_count": bytes.len(),
                    "result": call_result_json(result, |length| json!(length)),
                }),
                SocketCall::Receive { api, result } => json!({
                    "call": "receive",
                    "api": format!("{api:?}"),
                    "result": call_result_json(result, |receive| json!({
                        "byte_count": receive.bytes.len(),
                        "source": receive.source,
                    })),
                }),
            };
            json!({"sequence": event.sequence, "event": call})
        }).collect::<Vec<_>>(),
    })
}

fn call_result_json<T>(result: &CallResult<T>, ok: impl FnOnce(&T) -> Value) -> Value {
    match result {
        CallResult::Ok(value) => json!({"ok": true, "value": ok(value)}),
        CallResult::OsError(error) => json!({
            "ok": false,
            "os_code": error.raw_os_error,
            "kind": format!("{:?}", error.kind),
            "message": error.message,
        }),
    }
}

fn domain_name(domain: Domain) -> &'static str {
    if domain == Domain::IPV4 {
        "ipv4"
    } else if domain == Domain::IPV6 {
        "ipv6"
    } else {
        "other"
    }
}

fn protocol_number(protocol: Protocol) -> i32 {
    protocol.into()
}

fn protocol_name(protocol: SupportedProtocol) -> &'static str {
    protocol.to_str()
}
