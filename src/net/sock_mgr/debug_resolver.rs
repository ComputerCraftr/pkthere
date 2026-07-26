use serde_json::Value;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DebugAddressRevision {
    pub(crate) revision: u64,
    pub(crate) listen_addr: Option<SocketAddr>,
    pub(crate) upstream_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DebugResolverDecision {
    Apply(DebugAddressRevision),
    AlreadyApplied {
        revision: u64,
    },
    Rejected {
        revision: Option<u64>,
        reason: String,
    },
}

pub(crate) struct DebugAddressResolver {
    path: PathBuf,
    last_applied_revision: Option<u64>,
}

impl DebugAddressResolver {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            last_applied_revision: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub(crate) fn read(
        &self,
        require_listen: bool,
        require_upstream: bool,
    ) -> DebugResolverDecision {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) => {
                return DebugResolverDecision::Rejected {
                    revision: None,
                    reason: format!("read-failed: {error}"),
                };
            }
        };
        let value = match serde_json::from_str::<Value>(&text) {
            Ok(value) => value,
            Err(error) => {
                return DebugResolverDecision::Rejected {
                    revision: None,
                    reason: format!("malformed-json: {error}"),
                };
            }
        };
        let Some(revision) = value.get("revision").and_then(Value::as_u64) else {
            return DebugResolverDecision::Rejected {
                revision: None,
                reason: "missing-or-invalid-revision".to_owned(),
            };
        };
        if self.last_applied_revision == Some(revision) {
            return DebugResolverDecision::AlreadyApplied { revision };
        }
        if self
            .last_applied_revision
            .is_some_and(|last| revision < last)
        {
            return DebugResolverDecision::Rejected {
                revision: Some(revision),
                reason: "revision-rollback".to_owned(),
            };
        }
        let listen_addr = match parse_addr_field(&value, "listen_addr", require_listen) {
            Ok(addr) => addr,
            Err(reason) => {
                return DebugResolverDecision::Rejected {
                    revision: Some(revision),
                    reason,
                };
            }
        };
        let upstream_addr = match parse_addr_field(&value, "upstream_addr", require_upstream) {
            Ok(addr) => addr,
            Err(reason) => {
                return DebugResolverDecision::Rejected {
                    revision: Some(revision),
                    reason,
                };
            }
        };
        DebugResolverDecision::Apply(DebugAddressRevision {
            revision,
            listen_addr,
            upstream_addr,
        })
    }

    pub(crate) fn mark_applied(&mut self, revision: u64) {
        self.last_applied_revision = Some(revision);
    }
}

fn parse_addr_field(
    value: &Value,
    field: &'static str,
    required: bool,
) -> Result<Option<SocketAddr>, String> {
    let Some(raw) = value.get(field) else {
        return if required {
            Err(format!("missing-{field}"))
        } else {
            Ok(None)
        };
    };
    let Some(raw) = raw.as_str() else {
        return Err(format!("invalid-{field}"));
    };
    raw.parse::<SocketAddr>()
        .map(Some)
        .map_err(|error| format!("invalid-{field}: {error}"))
}
