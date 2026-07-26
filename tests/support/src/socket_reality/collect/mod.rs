//! Socket-reality evidence collectors.

mod direct;
mod direct_icmp;
#[cfg(test)]
mod direct_tests;
mod disconnect_platform;
mod dispatch;
mod forwarder;
mod icmp_dgram;
mod icmp_dgram_shared;
mod receive_buffer;

pub use dispatch::{
    collect, configure_protocol_zero_capture, independent_disconnect,
    route_probe_bind_before_connect_required,
};

#[cfg(test)]
pub(crate) use direct::{collect_udp_connected_filter, collect_udp_datagram};
#[cfg(test)]
mod dispatch_tests;
#[cfg(test)]
mod forwarder_tests;
#[cfg(test)]
mod icmp_dgram_tests;
#[cfg(test)]
mod receive_buffer_tests;
