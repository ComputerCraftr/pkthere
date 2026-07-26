//! Wire-format parsing and Internet-checksum primitives shared by the
//! forwarder, socket-policy resolver, test harness, and external consumers.
//!
//! ```
//! use pkthere_wire::checksum::checksum16_bytes;
//!
//! assert_eq!(checksum16_bytes(b"abc"), 0x3b9d);
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

pub mod checksum;
pub mod packet_headers;
mod wire_types;
pub use wire_types::{MAX_WIRE_PAYLOAD, SupportedProtocol, be16_16};
