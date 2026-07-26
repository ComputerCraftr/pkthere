use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TraceKey {
    pub worker: u64,
    pub direction: String,
    pub packet_id: u64,
}

#[derive(Debug, Default)]
pub struct TraceStages<'a> {
    pub received: Vec<&'a DiagnosticRecord>,
    pub admission: Vec<&'a DiagnosticRecord>,
    pub disposition: Vec<&'a DiagnosticRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticKind {
    Packet,
    SocketEvidence,
    Handshake,
    Resolver,
    Runtime,
    Stats,
}

#[derive(Debug)]
pub struct DiagnosticRecord {
    pub stream: DiagnosticStream,
    pub physical_line: usize,
    pub sequence: u64,
    pub kind: DiagnosticKind,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SocketEvidenceIndexKey {
    pub process_id: u64,
    pub role: String,
    pub domain: String,
    pub socket_slot: u64,
    pub generation: u64,
}

#[derive(Debug, Default)]
pub struct DiagnosticLogIndex {
    records: Vec<DiagnosticRecord>,
    packet_records: HashMap<TraceKey, Vec<usize>>,
    socket_records: HashMap<SocketEvidenceIndexKey, Vec<usize>>,
    handshake_records: Vec<usize>,
    resolver_records: Vec<usize>,
    stats_records: Vec<usize>,
}

impl DiagnosticLogIndex {
    pub fn parse(stdout: &str, stderr: &str) -> Result<Self, String> {
        let mut index = Self::default();
        index.parse_stream(DiagnosticStream::Stdout, stdout)?;
        index.parse_stream(DiagnosticStream::Stderr, stderr)?;
        index.records.sort_by_key(|record| record.sequence);
        for pair in index.records.windows(2) {
            if pair[0].sequence == pair[1].sequence {
                return Err(format!(
                    "duplicate diagnostic_sequence {}",
                    pair[0].sequence
                ));
            }
        }
        index.rebuild_indexes()?;
        Ok(index)
    }

    pub fn records(&self) -> &[DiagnosticRecord] {
        &self.records
    }

    pub fn packet_records(&self, key: &TraceKey) -> impl Iterator<Item = &DiagnosticRecord> {
        self.packet_records
            .get(key)
            .into_iter()
            .flatten()
            .map(|index| &self.records[*index])
    }

    pub fn packets(&self) -> impl Iterator<Item = &DiagnosticRecord> {
        self.records
            .iter()
            .filter(|record| record.kind == DiagnosticKind::Packet)
    }

    pub fn socket_evidence(&self) -> impl Iterator<Item = &DiagnosticRecord> {
        self.records
            .iter()
            .filter(|record| record.kind == DiagnosticKind::SocketEvidence)
    }

    pub fn socket_records(
        &self,
        key: &SocketEvidenceIndexKey,
    ) -> impl Iterator<Item = &DiagnosticRecord> {
        self.socket_records
            .get(key)
            .into_iter()
            .flatten()
            .map(|index| &self.records[*index])
    }

    pub fn handshakes(&self) -> impl Iterator<Item = &DiagnosticRecord> {
        self.handshake_records
            .iter()
            .map(|index| &self.records[*index])
    }

    pub fn require_single_completed_handshake(&self, buffered_len: usize) -> Result<(), String> {
        let transitions = self.handshakes().collect::<Vec<_>>();
        let begin = transitions
            .iter()
            .filter(|record| record.value["transition"] == "begin")
            .copied()
            .collect::<Vec<_>>();
        let matched = transitions
            .iter()
            .filter(|record| record.value["transition"] == "ack-matched")
            .copied()
            .collect::<Vec<_>>();
        if begin.len() != 1 || matched.len() != 1 {
            return Err(format!(
                "expected one begin and one ack-matched handshake transition, observed begin={} ack-matched={} transitions={}",
                begin.len(),
                matched.len(),
                transitions
                    .iter()
                    .filter_map(|record| record.value["transition"].as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }

        let begin = begin[0];
        let matched = matched[0];
        if begin.sequence >= matched.sequence {
            return Err("handshake ACK was not observed after negotiation began".to_string());
        }
        if begin.value["expected_ack_destination_id"]
            != matched.value["expected_ack_destination_id"]
        {
            return Err("handshake begin and ACK used different destination IDs".to_string());
        }
        if begin.value["buffered_len"].as_u64() != Some(buffered_len as u64)
            || matched.value["buffered_len"].as_u64() != Some(buffered_len as u64)
        {
            return Err(format!(
                "handshake did not preserve the first payload length {buffered_len}"
            ));
        }
        if transitions.iter().any(|record| {
            matches!(
                record.value["transition"].as_str(),
                Some("timeout" | "reset")
            )
        }) {
            return Err("completed handshake also emitted timeout/reset".to_string());
        }
        Ok(())
    }

    pub fn resolver_events(&self) -> impl Iterator<Item = &DiagnosticRecord> {
        self.resolver_records
            .iter()
            .map(|index| &self.records[*index])
    }

    pub fn stats(&self) -> impl DoubleEndedIterator<Item = &DiagnosticRecord> {
        self.stats_records.iter().map(|index| &self.records[*index])
    }

    pub fn trace_stages(&self) -> HashMap<TraceKey, TraceStages<'_>> {
        let mut grouped = HashMap::new();
        for record in self.packets() {
            let Some(key) = trace_key(&record.value) else {
                continue;
            };
            let Some(stage) = record.value.get("stage").and_then(Value::as_str) else {
                continue;
            };
            let stages = grouped.entry(key).or_insert_with(TraceStages::default);
            match stage {
                "received" => stages.received.push(record),
                "admission" => stages.admission.push(record),
                "disposition" => stages.disposition.push(record),
                _ => {}
            }
        }
        grouped
    }

    pub fn has_complete_accepted_forwarded_trace(&self, direction: &str) -> bool {
        self.trace_stages().iter().any(|(key, stages)| {
            key.direction == direction
                && stages.received.len() == 1
                && stages.admission.len() == 1
                && stages.disposition.len() == 1
                && stages.admission[0].value["admission"]["result"] == "accepted"
                && stages.disposition[0].value["disposition"] == "forwarded"
                && stages.received[0].sequence < stages.admission[0].sequence
                && stages.admission[0].sequence < stages.disposition[0].sequence
        })
    }

    pub fn received_trace_keys(&self) -> Vec<TraceKey> {
        self.packets()
            .filter(|record| record.value.get("stage").and_then(Value::as_str) == Some("received"))
            .filter_map(|record| trace_key(&record.value))
            .collect()
    }

    fn parse_stream(&mut self, stream: DiagnosticStream, text: &str) -> Result<(), String> {
        for (physical_line, source_line) in text.split_inclusive('\n').enumerate() {
            let terminated = source_line.ends_with('\n');
            let line = source_line.trim_end_matches(['\r', '\n']);
            let (kind, value) = match parse_diagnostic_line(line) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(_) if !terminated => break,
                Err(error) => {
                    return Err(format!(
                        "malformed known diagnostic on {:?} line {}: {error}",
                        stream,
                        physical_line + 1
                    ));
                }
            };

            let sequence = value
                .get("diagnostic_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    format!(
                        "schema-3 diagnostic lacks diagnostic_sequence on {:?} line {}",
                        stream,
                        physical_line + 1
                    )
                })?;
            if value.get("diagnostic_schema").and_then(Value::as_u64) != Some(3) {
                return Err(format!(
                    "unsupported diagnostic schema on {:?} line {}",
                    stream,
                    physical_line + 1
                ));
            }

            self.records.push(DiagnosticRecord {
                stream,
                physical_line: physical_line + 1,
                sequence,
                kind,
                value,
            });
        }
        Ok(())
    }

    fn rebuild_indexes(&mut self) -> Result<(), String> {
        self.packet_records.clear();
        self.socket_records.clear();
        self.handshake_records.clear();
        self.resolver_records.clear();
        self.stats_records.clear();
        for (record_index, record) in self.records.iter().enumerate() {
            match record.kind {
                DiagnosticKind::Packet => {
                    let key = trace_key(&record.value).ok_or_else(|| {
                        format!(
                            "packet diagnostic lacks trace key at sequence {}",
                            record.sequence
                        )
                    })?;
                    self.packet_records
                        .entry(key)
                        .or_default()
                        .push(record_index);
                }
                DiagnosticKind::SocketEvidence => {
                    let key = socket_evidence_key(&record.value).ok_or_else(|| {
                        format!(
                            "socket diagnostic lacks evidence key at sequence {}",
                            record.sequence
                        )
                    })?;
                    self.socket_records
                        .entry(key)
                        .or_default()
                        .push(record_index);
                }
                DiagnosticKind::Handshake => self.handshake_records.push(record_index),
                DiagnosticKind::Resolver => self.resolver_records.push(record_index),
                DiagnosticKind::Runtime => {}
                DiagnosticKind::Stats => self.stats_records.push(record_index),
            }
        }
        Ok(())
    }
}

pub fn parse_diagnostic_line(line: &str) -> Result<Option<(DiagnosticKind, Value)>, String> {
    let known = [
        ("packet-dump ", DiagnosticKind::Packet),
        ("socket-evidence ", DiagnosticKind::SocketEvidence),
        ("handshake-trace ", DiagnosticKind::Handshake),
        ("resolver-evidence ", DiagnosticKind::Resolver),
        ("runtime-trace ", DiagnosticKind::Runtime),
    ];
    if let Some((kind, json)) = known
        .into_iter()
        .find_map(|(marker, kind)| line.split_once(marker).map(|(_, json)| (kind, json)))
    {
        return serde_json::from_str(json)
            .map(|value| Some((kind, value)))
            .map_err(|error| error.to_string());
    }

    let Some(start) = line.find('{') else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_str::<Value>(&line[start..]) else {
        return Ok(None);
    };
    Ok(value
        .get("worker_flows")
        .is_some()
        .then_some((DiagnosticKind::Stats, value)))
}

fn socket_evidence_key(record: &Value) -> Option<SocketEvidenceIndexKey> {
    let key = record.get("key").or_else(|| {
        record
            .get("socket")
            .and_then(|socket| socket.get("evidence_key"))
    })?;
    Some(SocketEvidenceIndexKey {
        process_id: key.get("process_id")?.as_u64()?,
        role: key.get("role")?.as_str()?.to_owned(),
        domain: key.get("domain")?.as_str()?.to_owned(),
        socket_slot: key.get("socket_slot")?.as_u64()?,
        generation: key.get("generation")?.as_u64()?,
    })
}

pub fn trace_key(record: &Value) -> Option<TraceKey> {
    Some(TraceKey {
        worker: record.get("worker")?.as_u64()?,
        direction: record.get("direction")?.as_str()?.to_string(),
        packet_id: record.get("packet_id")?.as_u64()?,
    })
}

#[cfg(test)]
mod tests;
