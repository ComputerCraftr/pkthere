//! Target socket policy resolved independently from runtime kernel evidence.
//!
//! ```
//! use pkthere_socket_policy::{
//!     SocketPlatform, current_icmp_platform_capabilities, icmp_platform_capabilities,
//! };
//!
//! let current = current_icmp_platform_capabilities();
//! assert_eq!(current, icmp_platform_capabilities(SocketPlatform::current()));
//! ```

#![cfg_attr(
    not(test),
    deny(
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::undocumented_unsafe_blocks,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used
    )
)]

mod listener_lifecycle;
mod platform;
mod resolution_api;
mod upstream_worker;

pub use listener_lifecycle::{
    ListenerRelockCapability, SameBindReplacementRealityKey, listener_lock_lifecycle,
    listener_relock_capability, listener_relock_capability_with_worker_policy,
    listener_reresolve_mode, listener_same_bind_replacement_lifecycle_eligible,
    same_bind_replacement_lifecycle_supported,
};
pub use platform::{
    IcmpPlatformCapabilities, SocketPlatform, UnsupportedSocketDomain,
    current_icmp_platform_capabilities, icmp_platform_capabilities, ip_version_for_domain,
};
pub use resolution_api::{
    resolve_listener_socket_policy_for_creation_path_with_lifecycle,
    resolve_listener_socket_policy_for_creation_path_with_protocol_intent,
    resolve_listener_socket_policy_with_protocol_intent,
    resolve_socket_policy_for_creation_path_with_lifecycle,
    resolve_socket_policy_for_creation_path_with_protocol_intent,
    resolve_socket_policy_with_protocol_intent, upstream_reresolve_capability,
};
pub use upstream_worker::{
    SharedIcmpIdentityRealityKey, UpstreamWorkerDistribution, UpstreamWorkerSocketPolicy,
    shared_icmp_identity_supported, upstream_worker_socket_policy,
};

mod creation;
mod disconnect;
mod resolution;
mod types;

pub(crate) use creation::raw_icmp_creation_path;
pub use creation::{
    ListenerSocketBindPolicy, ListenerWorkerDistribution, ListenerWorkerSocketPolicy,
    ReusePortAction, UpstreamBindAddress, UpstreamSocketBindPolicy, listener_socket_bind_policy,
    listener_socket_creation_policy, listener_socket_setup_policy, listener_worker_socket_policy,
    reuse_port_action, reuse_port_action_for, socket_create_spec, socket_post_bind_policy,
    upstream_socket_bind_policy, upstream_socket_creation_policy,
};
pub use disconnect::{
    CapabilityEvidence, CapabilityEvidenceId, CapabilityUnsupportedReason,
    CapabilityUnverifiedReason, DatagramBindPreservation, DatagramDisconnectCapability,
    DatagramDisconnectEvidence, DatagramPortBindCapability, DisconnectBindShape,
    DisconnectRealityKey, InterfaceBindingKind, ResolvedDisconnectContract,
    SocketDisconnectCapability, SocketDisconnectEvidence, UpstreamReresolveCapability,
    datagram_disconnect_evidence, datagram_disconnect_evidence_for, socket_disconnect_evidence,
};
pub(crate) use pkthere_wire::SupportedProtocol;
pub use resolution::{
    IcmpPolicyIntent, ProtocolPolicyIntent, SocketLifecycleContext, SocketPathContext,
    SocketPolicyContext, SocketReuseCapability, resolve_icmp_socket_policy_with_intent,
};
pub(crate) use resolution::{
    SocketPolicyRequest, inferred_socket_creation_path, resolve_receive_header_mode,
    resolve_receive_header_mode_for_platform, resolve_socket_policy,
};
pub(crate) use types::resolve_peer_verification;
pub use types::{
    EvidenceGenerationExhausted, IcmpChecksumMode, IcmpKernelIdPolicy, IcmpSocketIdCapability,
    IcmpWildcardIdPolicy, IpHeaderMode, Ipv4HeaderAction, Ipv6DestinationScopeEvidence,
    ListenerClearStrategy, ListenerLockLifecycle, ListenerSocketSetupPolicy, PeerSourceRequirement,
    PeerVerification, ProtocolIdRequirement, ReceiveCaptureScope, ReceiveEvidencePolicy,
    ReceiveSyscall, ResolvedIcmpSocketPolicy, ResolvedReceiveEvidence, ResolvedReceiveSyscall,
    ResolvedSocketPolicy, SocketCaptureAction, SocketCreateSpec, SocketCreationFailureClass,
    SocketCreationPath, SocketCreationPlan, SocketEvidenceKey, SocketFallbackPolicy,
    SocketPostBindPolicy, SocketReresolveMode, SocketRole, SocketSendPolicy, StartupPeerMode,
    TimeoutAction,
};

#[cfg(test)]
mod tests;
