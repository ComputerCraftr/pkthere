//! Socket-reality evidence collectors.

mod direct;
mod dispatch;
mod forwarder;

pub use dispatch::collect;

#[cfg(test)]
pub(crate) use direct::{collect_udp_connected_filter, collect_udp_datagram};
