use super::{
    MAX_IPV4_PACKET_CAPTURE, MAX_IPV6_PACKET_CAPTURE, MAX_RECEIVE_CAPTURE, MAX_WIRE_PAYLOAD,
};

#[test]
fn receive_capacity_covers_every_selectable_header_layout() {
    assert_eq!(MAX_IPV4_PACKET_CAPTURE, MAX_WIRE_PAYLOAD);
    assert_eq!(MAX_IPV6_PACKET_CAPTURE, 40 + MAX_WIRE_PAYLOAD);
    assert_eq!(MAX_RECEIVE_CAPTURE, MAX_IPV6_PACKET_CAPTURE);
}
