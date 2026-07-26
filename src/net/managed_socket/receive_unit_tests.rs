use super::receive::ReceiveBuffer;
use std::io::ErrorKind;

#[test]
fn initialized_receive_prefix_handles_zero_capacity_and_reuse() {
    let mut buffer = ReceiveBuffer::<8>::new();
    assert!(
        buffer
            .initialized_prefix(0)
            .expect("zero prefix")
            .is_empty()
    );

    for (slot, byte) in buffer.bytes.iter_mut().zip(*b"12345678") {
        slot.write(byte);
    }
    assert_eq!(
        buffer.initialized_prefix(8).expect("capacity prefix"),
        b"12345678"
    );

    for (slot, byte) in buffer.bytes.iter_mut().zip(*b"new") {
        slot.write(byte);
    }
    assert_eq!(buffer.initialized_prefix(3).expect("reused prefix"), b"new");
    assert_eq!(
        buffer
            .initialized_prefix(9)
            .expect_err("oversize prefix")
            .kind(),
        ErrorKind::InvalidData
    );
}
