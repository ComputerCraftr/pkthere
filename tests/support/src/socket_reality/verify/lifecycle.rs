use super::implementation::{error, parse_evidence_key};
use super::model::{DerivedFacts, VerificationError};
use crate::packet_diagnostics::DiagnosticLogIndex;
use crate::socket_reality::case::{RealityCase, RealityOperation};
use crate::socket_reality::evidence::ForwarderLifecycleEvidence;
use pkthere_socket_policy::{ResolvedSocketPolicy, SocketEvidenceKey};
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
        let keys = packet_socket_keys(&diagnostics, expected.2)?;
        let first = *keys
            .first()
            .ok_or_else(|| error("listener relock packet dumps contained no socket key"))?;
        if keys.iter().any(|key| *key != first) {
            return Err(error("listener relock changed socket slot or generation"));
        }
        (first, first, None)
    } else {
        let (old, new, update) = resolver_transition_keys(&diagnostics, requested.operation)?;
        (old, new, Some(update))
    };
    require_key_has_getsockname(&diagnostics, old_key)?;
    require_key_has_getsockname(&diagnostics, new_key)?;
    if old_key.socket_slot != new_key.socket_slot {
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
            } else if requested.connected {
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
            if old_key != new_key {
                return Err(error("listener relock replaced the socket"));
            }
            let final_stats = diagnostics
                .stats()
                .next_back()
                .ok_or_else(|| error("listener relock emitted no stats evidence"))?;
            let listener_connected = final_stats.value["worker_flows"]
                .as_array()
                .and_then(|flows| flows.first())
                .and_then(|flow| flow["listener_connected"].as_bool())
                .ok_or_else(|| error("listener relock stats omitted listener_connected"))?;
            let expected_connected = requested.connected && policy.reuse.connects_after_lock();
            if listener_connected != expected_connected {
                return Err(error(format!(
                    "listener relock connected state was {listener_connected}, expected {expected_connected}"
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
