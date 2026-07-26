use std::collections::BTreeMap;

const EVIDENCE_PREFIX: &str = "authority-worker-evidence ";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuditDirection {
    ClientToUpstream,
    UpstreamToClient,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerAuthorityEvidence {
    pub worker: usize,
    pub direction: AuditDirection,
    pub receive: u64,
    pub send: u64,
    pub completed: u64,
    pub allocations: u64,
    pub allocation_authority_mask: u64,
    pub payload_copies: u64,
    pub endpoint_normalizations: u64,
    pub forbidden_authorities: u64,
    pub forbidden_rmws: u64,
    pub refcount_rmws: u64,
    pub violation: u64,
}

pub fn require_complete_worker_authority_evidence(
    stderr: &str,
    worker_pairs: usize,
    maximum_load_ratio: u64,
) -> Result<Vec<WorkerAuthorityEvidence>, String> {
    let mut records = BTreeMap::new();
    for line in stderr.lines() {
        let Some(fields) = line.strip_prefix(EVIDENCE_PREFIX) else {
            continue;
        };
        let record = parse_record(fields)?;
        let key = (record.worker, record.direction);
        if records.insert(key, record).is_some() {
            return Err(format!("duplicate authority evidence for {key:?}"));
        }
    }
    let expected_records = worker_pairs
        .checked_mul(2)
        .ok_or_else(|| "worker evidence count overflowed".to_string())?;
    if records.len() != expected_records {
        return Err(format!(
            "expected {expected_records} forwarding-worker records, found {}",
            records.len()
        ));
    }
    for worker in 0..worker_pairs {
        for direction in [
            AuditDirection::ClientToUpstream,
            AuditDirection::UpstreamToClient,
        ] {
            let record = records.get(&(worker, direction)).ok_or_else(|| {
                format!("missing authority evidence for worker {worker} {direction:?}")
            })?;
            validate_record(record)?;
        }
    }
    for direction in [
        AuditDirection::ClientToUpstream,
        AuditDirection::UpstreamToClient,
    ] {
        let mut counts = records
            .values()
            .filter(|record| record.direction == direction)
            .map(|record| record.completed);
        let first = counts
            .next()
            .ok_or_else(|| format!("missing {direction:?} completion evidence"))?;
        let (minimum, maximum) = counts.fold((first, first), |(minimum, maximum), count| {
            (minimum.min(count), maximum.max(count))
        });
        if maximum > minimum.saturating_mul(maximum_load_ratio) {
            return Err(format!(
                "{direction:?} worker completion load exceeded {maximum_load_ratio}:1: min={minimum}, max={maximum}"
            ));
        }
    }
    Ok(records.into_values().collect())
}

fn parse_record(fields: &str) -> Result<WorkerAuthorityEvidence, String> {
    let fields = fields
        .split_ascii_whitespace()
        .map(|field| {
            field
                .split_once('=')
                .ok_or_else(|| format!("malformed authority evidence field {field:?}"))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if fields.len() != 13 {
        return Err(format!(
            "authority evidence had {} fields instead of 13",
            fields.len()
        ));
    }
    Ok(WorkerAuthorityEvidence {
        worker: parse_number(&fields, "worker")?,
        direction: match required(&fields, "direction")? {
            "ClientToUpstream" => AuditDirection::ClientToUpstream,
            "UpstreamToClient" => AuditDirection::UpstreamToClient,
            value => return Err(format!("unknown authority evidence direction {value:?}")),
        },
        receive: parse_number(&fields, "receive")?,
        send: parse_number(&fields, "send")?,
        completed: parse_number(&fields, "completed")?,
        allocations: parse_number(&fields, "allocations")?,
        allocation_authority_mask: parse_hex_number(&fields, "allocation_authority_mask")?,
        payload_copies: parse_number(&fields, "payload_copies")?,
        endpoint_normalizations: parse_number(&fields, "endpoint_normalizations")?,
        forbidden_authorities: parse_number(&fields, "forbidden_authorities")?,
        forbidden_rmws: parse_number(&fields, "forbidden_rmws")?,
        refcount_rmws: parse_number(&fields, "refcount_rmws")?,
        violation: parse_number(&fields, "violation")?,
    })
}

fn required<'a>(fields: &'a BTreeMap<&str, &str>, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .copied()
        .ok_or_else(|| format!("authority evidence omitted {name}"))
}

fn parse_number<T>(fields: &BTreeMap<&str, &str>, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    required(fields, name)?
        .parse()
        .map_err(|_| format!("authority evidence {name} was not an integer"))
}

fn parse_hex_number(fields: &BTreeMap<&str, &str>, name: &str) -> Result<u64, String> {
    let value = required(fields, name)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("authority evidence {name} omitted its hexadecimal prefix"))?;
    u64::from_str_radix(digits, 16)
        .map_err(|_| format!("authority evidence {name} was not a hexadecimal integer"))
}

fn validate_record(record: &WorkerAuthorityEvidence) -> Result<(), String> {
    if record.receive == 0 || record.send == 0 || record.completed == 0 {
        return Err(format!(
            "worker {} {:?} did not traverse every forwarding stage: {record:?}",
            record.worker, record.direction
        ));
    }
    if record.completed > record.send || record.send > record.receive {
        return Err(format!(
            "worker {} {:?} published inconsistent pipeline counts: {record:?}",
            record.worker, record.direction
        ));
    }
    if record.allocations != 0
        || record.allocation_authority_mask != 0
        || record.payload_copies != 0
        || record.endpoint_normalizations != 0
        || record.forbidden_authorities != 0
        || record.forbidden_rmws != 0
        || record.refcount_rmws != 0
        || record.violation != 0
    {
        return Err(format!(
            "worker {} {:?} violated stable-path authority requirements: {record:?}",
            record.worker, record.direction
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
