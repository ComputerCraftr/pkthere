use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const DIAGNOSTIC_SCHEMA: u64 = 3;

static NEXT_DIAGNOSTIC_SEQUENCE: crate::authority::AuthorityAtomic<
    crate::authority::tags::DiagnosticCounter,
    AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    1,
    crate::authority::AtomicProtocolId::DiagnosticCounter,
);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct PacketTraceId {
    pub(crate) worker_id: usize,
    pub(crate) c2u: bool,
    pub(crate) packet_id: u64,
}

#[inline]
pub(crate) fn stamp(mut value: Value) -> Value {
    let sequence =
        match NEXT_DIAGNOSTIC_SEQUENCE.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        }) {
            Ok(sequence) => sequence,
            Err(sequence) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "diagnostic sequence exhausted at {sequence}"
                ));
                sequence
            }
        };
    value["diagnostic_schema"] = DIAGNOSTIC_SCHEMA.into();
    value["diagnostic_sequence"] = sequence.into();
    value
}

#[cfg(test)]
mod tests;
