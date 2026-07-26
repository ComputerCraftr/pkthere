#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketRejectionCategory {
    IpMissingHeader,
    IpInvalidVersion,
    IpTruncatedHeader,
    IpDeclaredLengthInvalid,
    IpCaptureTruncated,
    IpFragmented,
    IpReservedFlag,
    IpExtensionChain,
    IpRoutingUnsupported,
    IpJumbogramUnsupported,
    IpSourceMismatch,
    IpDestinationMismatch,
    UnrelatedIpProtocol,
    IcmpMalformed,
}

#[derive(Clone, Copy)]
pub(super) enum ErrorCategory {
    Receive,
    UserSend,
    ControlSend,
    Admission,
    Topology,
    MalformedPacket,
    WrongPeer,
    WrongSource,
    HandshakeInvalid,
    Replay,
    IcmpAbuseBudget,
    StaleSession,
    StaleAuthority,
    InvariantFailure,
}
