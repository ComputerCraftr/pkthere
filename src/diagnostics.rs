use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const DIAGNOSTIC_SCHEMA: u64 = 2;

static NEXT_DIAGNOSTIC_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[inline]
pub(crate) fn stamp(mut value: Value) -> Value {
    let sequence = NEXT_DIAGNOSTIC_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    value["diagnostic_schema"] = DIAGNOSTIC_SCHEMA.into();
    value["diagnostic_sequence"] = sequence.into();
    value
}

#[cfg(test)]
mod tests {
    #[test]
    fn stamps_schema_and_monotonic_sequence() {
        let first = super::stamp(serde_json::json!({}));
        let second = super::stamp(serde_json::json!({}));
        assert_eq!(first["diagnostic_schema"], 2);
        assert_eq!(
            second["diagnostic_sequence"].as_u64(),
            first["diagnostic_sequence"].as_u64().map(|value| value + 1)
        );
    }
}
