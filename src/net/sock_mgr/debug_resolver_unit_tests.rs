use super::{DebugAddressResolver, DebugResolverDecision};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn resolver(contents: &str) -> DebugAddressResolver {
    let path = std::env::temp_dir().join(format!(
        "pkthere-debug-resolver-{}-{}.json",
        std::process::id(),
        FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, contents).expect("write resolver fixture");
    DebugAddressResolver::new(path)
}

#[test]
fn revisions_apply_once_and_reject_rollback() {
    let mut resolver = resolver(
        r#"{"revision":2,"listen_addr":"127.0.0.1:12002","upstream_addr":"127.0.0.1:12003"}"#,
    );
    let DebugResolverDecision::Apply(update) = resolver.read(true, true) else {
        panic!("first complete revision must apply");
    };
    assert_eq!(update.revision, 2);
    assert_eq!(
        update.upstream_addr,
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12003))
    );
    resolver.mark_applied(update.revision);
    assert_eq!(
        resolver.read(true, true),
        DebugResolverDecision::AlreadyApplied { revision: 2 }
    );
    fs::write(
        resolver.path(),
        r#"{"revision":1,"listen_addr":"127.0.0.1:12002","upstream_addr":"127.0.0.1:12003"}"#,
    )
    .expect("write rollback");
    assert!(matches!(
        resolver.read(true, true),
        DebugResolverDecision::Rejected {
            revision: Some(1),
            ..
        }
    ));
}

#[test]
fn enabled_sides_require_complete_valid_addresses() {
    let invalid = resolver(r#"{"revision":1,"listen_addr":"not-an-address"}"#);
    assert_eq!(
        invalid.read(true, false),
        DebugResolverDecision::Rejected {
            revision: Some(1),
            reason: "invalid-listen_addr: invalid socket address syntax".to_owned(),
        }
    );

    let missing = resolver(r#"{"revision":1,"listen_addr":"127.0.0.1:12002"}"#);
    assert_eq!(
        missing.read(true, true),
        DebugResolverDecision::Rejected {
            revision: Some(1),
            reason: "missing-upstream_addr".to_owned(),
        }
    );
}

#[test]
fn malformed_or_partial_json_is_never_applied() {
    for contents in ["{", r#"{"listen_addr":"127.0.0.1:12002"}"#] {
        let resolver = resolver(contents);
        assert!(matches!(
            resolver.read(true, false),
            DebugResolverDecision::Rejected { revision: None, .. }
        ));
    }
}
