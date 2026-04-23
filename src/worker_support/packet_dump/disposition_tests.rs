use super::PacketDisposition;
use std::collections::HashSet;

const fn coverage_owner(disposition: PacketDisposition) -> &'static str {
    match disposition {
        PacketDisposition::Forwarded | PacketDisposition::Filtered => "loopback integration",
        PacketDisposition::ReceiveNoise => "admission and privileged injection",
        PacketDisposition::ConsumeCadence => "ICMP DGRAM integration",
        PacketDisposition::ConsumeSessionControl | PacketDisposition::ReplySessionControl => {
            "handshake integration"
        }
        PacketDisposition::ReplyFailed | PacketDisposition::SendFailed => {
            "injected sender component"
        }
        PacketDisposition::DropDuplicate => "sequence component and privileged replay",
        PacketDisposition::DropHandshakePending => "handshake integration",
        PacketDisposition::DropSyncReplaced => "sync buffer component",
        PacketDisposition::DropFlowConflict => "flow admission component",
        PacketDisposition::DropSyncInvalid => "sync sequence component",
        PacketDisposition::DropNoActiveFlow => "worker routing component",
        PacketDisposition::HandshakeTimeoutDrop => "timeout topology",
        PacketDisposition::HandshakeResetDrop => "reset and activity integration",
    }
}

#[test]
fn every_disposition_has_a_unique_wire_name_and_coverage_owner() {
    let mut names = HashSet::new();
    for disposition in PacketDisposition::ALL {
        assert!(
            names.insert(disposition.as_str()),
            "duplicate packet disposition wire name: {}",
            disposition.as_str()
        );
        assert!(
            !coverage_owner(disposition).is_empty(),
            "{disposition:?} has no declared coverage owner"
        );
    }
    assert_eq!(names.len(), PacketDisposition::ALL.len());
}
