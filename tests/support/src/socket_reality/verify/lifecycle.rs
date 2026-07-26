use super::implementation::{error, parse_evidence_key};
use super::model::{DerivedFacts, VerificationError};
use crate::packet_diagnostics::DiagnosticLogIndex;
use crate::socket_reality::case::{RealityCase, RealityOperation};
use crate::socket_reality::evidence::ForwarderLifecycleEvidence;
use pkthere_socket_policy::{
    ListenerClearStrategy, ListenerLockLifecycle, ResolvedSocketPolicy, SocketEvidenceKey,
};
use serde_json::Value;

pub(super) fn verify_lifecycle(
    requested: RealityCase,
    policy: ResolvedSocketPolicy,
    evidence: &ForwarderLifecycleEvidence,
) -> Result<DerivedFacts, VerificationError> {
    if evidence.negative_observation_window.is_zero() {
        return Err(error(
            "lifecycle evidence omitted its bounded negative window",
        ));
    }
    let diagnostics = DiagnosticLogIndex::parse(&evidence.process.stdout, &evidence.process.stderr)
        .map_err(error)?;
    let expected = match requested.operation {
        RealityOperation::UpstreamReconnect => ([1, 2], None, "upstream"),
        RealityOperation::ListenerRebind => ([11, 12], Some(13), "listener"),
        RealityOperation::ListenerRelock => ([21, 23], Some(22), "listener"),
        _ => return Err(error("non-lifecycle operation reached lifecycle verifier")),
    };
    for probe_id in expected.0 {
        require_witnessed_probe(evidence, probe_id)?;
    }
    if let Some(negative_probe) = expected.1
        && evidence
            .endpoint_observations
            .iter()
            .any(|observation| observation.probe_id == negative_probe)
    {
        return Err(error(format!(
            "negative probe {negative_probe} reached an external endpoint during the bounded window"
        )));
    }
    for probe_id in expected.0 {
        let send = evidence
            .client_sends
            .iter()
            .find(|send| send.probe_id == probe_id)
            .ok_or_else(|| error(format!("missing send evidence for probe {probe_id}")))?;
        let bytes = evidence
            .client_receives
            .iter()
            .filter(|receive| receive.probe_id == probe_id)
            .find_map(|receive| receive.payload.as_ok())
            .ok_or_else(|| error(format!("probe {probe_id} received no echo")))?;
        if crate::socket_reality::witness::payload_digest(bytes) != send.payload_digest {
            return Err(error(format!(
                "probe {probe_id} reply digest differs from the sent payload"
            )));
        }
    }

    let (old_key, new_key, update_kind) = if requested.operation == RealityOperation::ListenerRelock
    {
        listener_relock_transition_keys(&diagnostics, policy.listener_lifecycle, expected.2)?
    } else {
        let (old, new, update) = resolver_transition_keys(&diagnostics, requested.operation)?;
        (old, new, Some(update))
    };
    require_key_has_getsockname(&diagnostics, old_key)?;
    require_key_has_getsockname(&diagnostics, new_key)?;
    if requested.operation != RealityOperation::ListenerRelock
        && old_key.socket_slot != new_key.socket_slot
    {
        return Err(error("lifecycle update changed logical socket_slot"));
    }
    match requested.operation {
        RealityOperation::UpstreamReconnect => {
            let cross_family = requested.target_domain != Some(requested.domain);
            if cross_family {
                require_cross_family_replacement(
                    &diagnostics,
                    requested,
                    old_key,
                    new_key,
                    update_kind.as_deref(),
                    "upstream",
                )?;
            } else if !requested.connection_scenario.debug_force_unconnected() {
                if policy.reuse.reconnects_in_place() {
                    if update_kind.as_deref() != Some("reconnected-in-place") {
                        return Err(error(format!(
                            "same-family upstream update reported {update_kind:?}, expected reconnected-in-place"
                        )));
                    }
                    if old_key != new_key {
                        return Err(error(
                            "reconnect-in-place changed socket evidence generation",
                        ));
                    }
                } else {
                    if update_kind.as_deref() != Some("replaced") {
                        return Err(error(format!(
                            "same-family upstream update reported {update_kind:?}, expected socket replacement"
                        )));
                    }
                    if old_key.socket_slot != new_key.socket_slot
                        || old_key.domain != new_key.domain
                        || new_key.generation != old_key.generation.saturating_add(1)
                    {
                        return Err(error(
                            "same-family upstream replacement did not preserve slot/domain and increment generation",
                        ));
                    }
                }
            } else {
                if !matches!(
                    policy.reuse.reresolve_mode,
                    pkthere_socket_policy::SocketReresolveMode::MetadataOnlyWhenUnconnected
                ) {
                    return Err(error(
                        "production policy does not select metadata-only refresh for an unconnected upstream",
                    ));
                }
                if update_kind.as_deref() != Some("metadata-updated") {
                    return Err(error(
                        "same-family unconnected upstream update did not refresh metadata only",
                    ));
                }
                if old_key != new_key {
                    return Err(error(
                        "metadata-only upstream refresh changed socket evidence identity",
                    ));
                }
            }
            let target_a_received_post_change = evidence
                .endpoint_observations
                .iter()
                .any(|observation| observation.endpoint == "target-a" && observation.probe_id == 2);
            let target_b_received_post_change = evidence
                .endpoint_observations
                .iter()
                .any(|observation| observation.endpoint == "target-b" && observation.probe_id == 2);
            if target_a_received_post_change || !target_b_received_post_change {
                return Err(error(
                    "external witnesses did not prove migration from target A to target B",
                ));
            }
        }
        RealityOperation::ListenerRebind => {
            let cross_family = requested.target_domain != Some(requested.domain);
            let expected_update = if cross_family {
                "replaced-cross-family"
            } else {
                "replaced"
            };
            if update_kind.as_deref() != Some(expected_update) {
                return Err(error(format!(
                    "listener rebind reported {:?}, expected {expected_update}",
                    update_kind
                )));
            }
            if new_key.generation != old_key.generation.saturating_add(1) {
                return Err(error("listener rebind did not increment generation"));
            }
            if requested.target_domain != Some(new_key.domain) {
                return Err(error("listener replacement used the wrong target domain"));
            }
            if cross_family {
                require_cross_family_replacement(
                    &diagnostics,
                    requested,
                    old_key,
                    new_key,
                    update_kind.as_deref(),
                    "listener",
                )?;
            }
        }
        RealityOperation::ListenerRelock => {
            match policy.listener_lifecycle {
                Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
                | Some(ListenerLockLifecycle::Connected {
                    clear: ListenerClearStrategy::ReplaceOwnerSameBind,
                }) => {
                    if old_key.socket_slot != new_key.socket_slot
                        || old_key.domain != new_key.domain
                        || new_key.generation != old_key.generation.saturating_add(1)
                    {
                        return Err(error(
                            "listener owner replacement did not preserve slot/domain and increment generation",
                        ));
                    }
                }
                _ if old_key.domain != new_key.domain
                    || old_key.generation != new_key.generation =>
                {
                    return Err(error(
                        "listener relock changed domain/generation without replacement lifecycle authority",
                    ));
                }
                _ => {}
            }
            let relocked_client = evidence
                .client_sends
                .iter()
                .find(|send| send.probe_id == 23)
                .ok_or_else(|| error("listener relock omitted client B send evidence"))?
                .source
                .to_string();
            let relock_stats = diagnostics
                .stats()
                .find(|record| {
                    record.value["worker_flows"]
                        .as_array()
                        .is_some_and(|flows| {
                            flows.iter().any(|flow| {
                                flow["locked"].as_bool() == Some(true)
                                    && flow["flow_key"].as_str() == Some(relocked_client.as_str())
                            })
                        })
                })
                .ok_or_else(|| {
                    error("listener relock emitted no locked stats evidence for client B")
                })?;
            let locked_flows = relock_stats.value["worker_flows"]
                .as_array()
                .ok_or_else(|| error("listener relock stats omitted worker_flows"))?
                .iter()
                .filter(|flow| flow["locked"].as_bool() == Some(true))
                .collect::<Vec<_>>();
            if locked_flows.is_empty() {
                return Err(error(
                    "listener relock stats contained no locked worker flow",
                ));
            }
            let connected_owner_count = locked_flows
                .iter()
                .filter(|flow| flow["listener_connected"].as_bool() == Some(true))
                .count();
            let expected_connected = !requested.connection_scenario.debug_force_unconnected()
                && policy
                    .listener_lifecycle
                    .is_some_and(pkthere_socket_policy::ListenerLockLifecycle::connects_after_lock);
            let expected_connected_owner_count = usize::from(expected_connected);
            if connected_owner_count != expected_connected_owner_count {
                return Err(error(format!(
                    "listener relock had {connected_owner_count} connected owners, expected {expected_connected_owner_count}"
                )));
            }
        }
        _ => unreachable!("matched lifecycle operation"),
    }
    let mut observed_probe_ids = evidence
        .endpoint_observations
        .iter()
        .map(|observation| observation.probe_id)
        .collect::<Vec<_>>();
    observed_probe_ids.sort_unstable();
    observed_probe_ids.dedup();
    Ok(DerivedFacts::Lifecycle {
        operation: requested.operation,
        old_key,
        new_key,
        observed_probe_ids,
    })
}

pub(super) fn listener_relock_transition_keys(
    diagnostics: &DiagnosticLogIndex,
    lifecycle: Option<ListenerLockLifecycle>,
    role: &str,
) -> Result<(SocketEvidenceKey, SocketEvidenceKey, Option<String>), VerificationError> {
    if matches!(
        lifecycle,
        Some(ListenerLockLifecycle::StayUnconnectedReplaceOnClear)
            | Some(ListenerLockLifecycle::Connected {
                clear: ListenerClearStrategy::ReplaceOwnerSameBind,
            })
    ) {
        let (old, new) = listener_replacement_keys(diagnostics)?;
        return Ok((old, new, Some("replaced".to_string())));
    }
    let keys = packet_socket_keys(diagnostics, role)?;
    let first = *keys
        .first()
        .ok_or_else(|| error("listener relock packet dumps contained no socket key"))?;
    let last = *keys
        .last()
        .ok_or_else(|| error("listener relock packet dumps contained no final key"))?;
    Ok((first, last, None))
}

fn listener_replacement_keys(
    diagnostics: &DiagnosticLogIndex,
) -> Result<(SocketEvidenceKey, SocketEvidenceKey), VerificationError> {
    let replacement = diagnostics
        .socket_evidence()
        .find(|record| {
            record.value.get("action").and_then(Value::as_str) == Some("replace-listener-on-clear")
        })
        .ok_or_else(|| error("listener relock emitted no listener-replacement evidence"))?;
    let new_key = replacement
        .value
        .get("key")
        .ok_or_else(|| error("listener replacement evidence omitted its key"))
        .and_then(parse_evidence_key)?;
    let old_generation = new_key
        .generation
        .checked_sub(1)
        .ok_or_else(|| error("listener replacement generation cannot precede generation one"))?;
    let old_key = SocketEvidenceKey {
        generation: old_generation,
        ..new_key
    };
    Ok((old_key, new_key))
}

fn require_witnessed_probe(
    evidence: &ForwarderLifecycleEvidence,
    probe_id: u64,
) -> Result<(), VerificationError> {
    let send = evidence
        .client_sends
        .iter()
        .find(|send| send.probe_id == probe_id)
        .ok_or_else(|| error(format!("missing client send for probe {probe_id}")))?;
    let observation = evidence
        .endpoint_observations
        .iter()
        .find(|observation| observation.probe_id == probe_id)
        .ok_or_else(|| error(format!("missing endpoint witness for probe {probe_id}")))?;
    if send.payload_digest != observation.payload_digest {
        return Err(error(format!(
            "probe {probe_id} client and endpoint digests differ"
        )));
    }
    Ok(())
}

fn resolver_transition_keys(
    diagnostics: &DiagnosticLogIndex,
    operation: RealityOperation,
) -> Result<(SocketEvidenceKey, SocketEvidenceKey, String), VerificationError> {
    let record = diagnostics
        .resolver_events()
        .find(|record| {
            record
                .value
                .pointer("/resolver/revision")
                .and_then(Value::as_u64)
                == Some(2)
                && record
                    .value
                    .pointer("/resolver/application_result")
                    .and_then(Value::as_str)
                    == Some("applied")
        })
        .ok_or_else(|| error("missing applied resolver revision 2"))?;
    let prefix = if operation == RealityOperation::UpstreamReconnect {
        "upstream"
    } else {
        "listener"
    };
    let old = record
        .value
        .pointer(&format!("/resolver/old_{prefix}_key"))
        .ok_or_else(|| error("resolver evidence omitted old key"))?;
    let new = record
        .value
        .pointer(&format!("/resolver/new_{prefix}_key"))
        .ok_or_else(|| error("resolver evidence omitted new key"))?;
    let update = record
        .value
        .pointer(&format!("/resolver/{prefix}_update"))
        .and_then(Value::as_str)
        .ok_or_else(|| error("resolver evidence omitted update kind"))?;
    Ok((
        parse_evidence_key(old)?,
        parse_evidence_key(new)?,
        update.to_owned(),
    ))
}

fn require_cross_family_replacement(
    diagnostics: &DiagnosticLogIndex,
    requested: RealityCase,
    old_key: SocketEvidenceKey,
    new_key: SocketEvidenceKey,
    update_kind: Option<&str>,
    role: &str,
) -> Result<(), VerificationError> {
    if update_kind != Some("replaced-cross-family") {
        return Err(error(
            "cross-family update was not classified as replacement",
        ));
    }
    if old_key.socket_slot != new_key.socket_slot
        || new_key.generation != old_key.generation.saturating_add(1)
        || new_key.domain == old_key.domain
        || requested.target_domain != Some(new_key.domain)
    {
        return Err(error(
            "cross-family replacement did not atomically preserve slot and update generation/domain",
        ));
    }
    let observed = diagnostics.packets().any(|record| {
        record
            .value
            .pointer("/socket/evidence_key")
            .is_some_and(|value| parse_evidence_key(value).ok() == Some(new_key))
            && record
                .value
                .get("parser_kernel")
                .and_then(Value::as_str)
                .is_some()
            && record
                .value
                .pointer("/socket/receive_header")
                .and_then(Value::as_str)
                .is_some()
            && record
                .value
                .pointer("/socket/evidence_key/role")
                .and_then(Value::as_str)
                == Some(role)
    });
    if !observed {
        let packet_evidence = diagnostics
            .packets()
            .map(|record| {
                format!(
                    "stage={:?} key={:?} parser={:?}",
                    record.value.get("stage"),
                    record.value.pointer("/socket/evidence_key"),
                    (
                        record.value.get("parser_kernel"),
                        record.value.pointer("/parse/headers/src_ip"),
                        record.value.pointer("/receive/socket_source")
                    )
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(error(format!(
            "cross-family replacement has no packet observation for its new parser/socket generation: {packet_evidence}"
        )));
    }
    Ok(())
}

fn packet_socket_keys(
    diagnostics: &DiagnosticLogIndex,
    role: &str,
) -> Result<Vec<SocketEvidenceKey>, VerificationError> {
    diagnostics
        .packets()
        .filter_map(|record| record.value.pointer("/socket/evidence_key"))
        .filter(|key| key.get("role").and_then(Value::as_str) == Some(role))
        .map(parse_evidence_key)
        .collect()
}

fn require_key_has_getsockname(
    diagnostics: &DiagnosticLogIndex,
    key: SocketEvidenceKey,
) -> Result<(), VerificationError> {
    let found = diagnostics.socket_evidence().any(|record| {
        record
            .value
            .get("key")
            .and_then(|value| parse_evidence_key(value).ok())
            == Some(key)
            && record
                .value
                .get("getsockname")
                .and_then(Value::as_str)
                .is_some()
    });
    if found {
        Ok(())
    } else {
        Err(error(format!(
            "socket evidence key {key:?} has no verbatim getsockname sample"
        )))
    }
}
