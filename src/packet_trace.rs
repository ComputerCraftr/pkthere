#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketTraceId {
    pub(crate) worker_id: usize,
    pub(crate) c2u: bool,
    pub(crate) packet_id: u64,
}
