use crate::cli::{Config, SupportedProtocol};
use crate::net::params::MAX_WIRE_PAYLOAD;
use crate::net::payload::{PayloadEvent, WirePayload, send_payload};
use crate::net::session::handle_send_result;
use crate::net::sock_mgr::{SocketHandles, SocketManager};
use crate::net::sync_icmp::{
    C2uKeepaliveDecision, SharedSyncIcmpState, SyncIcmpCache, classify_c2u_keepalive,
    remember_request_seq, reset_session,
};
use crate::stats::StatsSink;
use socket2::{SockAddr, Socket, Type};

use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, SOCKET_ERROR, WSAEINTR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};

pub(crate) const SYNC_BEST_EFFORT_POLL_CAP: Duration = Duration::from_millis(5);

#[inline]
pub(crate) fn as_uninit_mut(buf: &mut [u8]) -> &mut [std::mem::MaybeUninit<u8>] {
    unsafe {
        std::slice::from_raw_parts_mut(
            buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
            buf.len(),
        )
    }
}

#[cfg(unix)]
#[inline]
pub(crate) fn wait_socket_until_readable(sock: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pfd.revents & libc::POLLIN) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

#[cfg(windows)]
#[inline]
pub(crate) fn wait_socket_until_readable(sock: &Socket, timeout: Duration) -> io::Result<bool> {
    loop {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = WSAPOLLFD {
            fd: sock.as_raw_socket() as usize,
            events: POLLRDNORM as i16,
            revents: 0,
        };
        let rc = unsafe { WSAPoll(&mut pfd, 1, timeout_ms) };
        if rc > 0 {
            return Ok((pfd.revents & (POLLRDNORM as i16)) != 0);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = unsafe { WSAGetLastError() };
        if err == WSAEINTR {
            continue;
        }
        if rc == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(err));
        }
        return Err(io::Error::other("unexpected WSAPoll return value"));
    }
}

#[cfg(not(any(unix, windows)))]
#[inline]
pub(crate) fn wait_socket_until_readable(_sock: &Socket, _timeout: Duration) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket readiness waiting is not implemented on this platform",
    ))
}

pub(crate) struct BestEffortPacer {
    interval: Duration,
    last_send_at: Option<Instant>,
}

impl BestEffortPacer {
    #[inline]
    pub(crate) fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_send_at: None,
        }
    }

    #[inline]
    pub(crate) fn reset(&mut self) {
        self.last_send_at = None;
    }

    #[inline]
    pub(crate) fn send_due(&self, now: Instant) -> bool {
        match self.last_send_at {
            None => true,
            Some(last_send_at) => now.saturating_duration_since(last_send_at) >= self.interval,
        }
    }

    #[inline]
    pub(crate) fn mark_sent(&mut self, now: Instant) {
        self.last_send_at = Some(now);
    }

    #[inline]
    pub(crate) fn poll_wait(&self) -> Duration {
        self.interval.min(SYNC_BEST_EFFORT_POLL_CAP)
    }
}

pub(crate) struct BufferedSyncPayload {
    src_is_icmp: bool,
    src_seq: u16,
    dst_proto: SupportedProtocol,
    payload: Vec<u8>,
}

impl BufferedSyncPayload {
    #[inline]
    pub(crate) fn from_wire(wire: &WirePayload<'_>) -> Self {
        Self {
            src_is_icmp: wire.src_is_icmp,
            src_seq: wire.src_seq,
            dst_proto: wire.dst_proto,
            payload: wire.payload.to_vec(),
        }
    }

    #[inline]
    pub(crate) fn as_event(&self) -> PayloadEvent<'_> {
        PayloadEvent::UserData(WirePayload {
            src_is_icmp: self.src_is_icmp,
            src_seq: self.src_seq,
            dst_proto: self.dst_proto,
            payload: &self.payload,
            pub_len: self.payload.len(),
        })
    }
}

#[inline]
pub(crate) fn normalize_client_sockaddr(
    src_sa: &SockAddr,
    listen_proto: SupportedProtocol,
    listen_port_id: u16,
) -> Option<SocketAddr> {
    let src = src_sa.as_socket()?;
    if listen_proto == SupportedProtocol::ICMP {
        let normalized = match src {
            SocketAddr::V4(addr) => {
                SocketAddr::V4(std::net::SocketAddrV4::new(*addr.ip(), listen_port_id))
            }
            SocketAddr::V6(addr) => SocketAddr::V6(std::net::SocketAddrV6::new(
                *addr.ip(),
                listen_port_id,
                addr.flowinfo(),
                addr.scope_id(),
            )),
        };
        Some(normalized)
    } else {
        Some(src)
    }
}

#[inline]
pub(crate) fn locked_client_matches(
    normalized_src: Option<SocketAddr>,
    locked_client_addr: Option<SocketAddr>,
) -> bool {
    locked_client_addr.is_some() && normalized_src == locked_client_addr
}

#[inline]
fn empty_icmp_reply_event(seq: u16) -> PayloadEvent<'static> {
    PayloadEvent::SyncKeepalive(WirePayload {
        src_is_icmp: true,
        src_seq: seq,
        dst_proto: SupportedProtocol::ICMP,
        payload: &[],
        pub_len: 0,
    })
}

#[inline]
fn send_local_keepalive_reply(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &Config,
    stats: &dyn StatsSink,
    last_seen_s: &AtomicU64,
    handles: &mut SocketHandles,
    dest_sa: &SockAddr,
    dest_port_id: u16,
    wire: &WirePayload<'_>,
) {
    let reply_event = empty_icmp_reply_event(wire.src_seq);
    let send_res = send_payload(
        &handles.client_sock,
        handles.client_connected,
        handles.client_sock.r#type().unwrap_or(Type::RAW),
        dest_sa,
        dest_port_id,
        &reply_event,
        false,
        Some(wire.src_seq),
    );
    handle_send_result(
        false,
        worker_id,
        t_start,
        t_recv,
        cfg,
        stats,
        last_seen_s,
        0,
        false,
        &send_res,
        handles.client_connected,
        dest_sa,
        None,
    );
}

#[inline]
pub(crate) fn handle_c2u_keepalive(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &Config,
    stats: &dyn StatsSink,
    last_seen_s: &AtomicU64,
    handles: &mut SocketHandles,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
    default_dest: Option<(SockAddr, u16)>,
    wire: &WirePayload<'_>,
) {
    match classify_c2u_keepalive(cfg, wire, sync_state, sync_cache) {
        Ok(C2uKeepaliveDecision::Consume) => {}
        Ok(C2uKeepaliveDecision::ReplyLocally) => {
            let dest = default_dest.or_else(|| {
                handles
                    .client_addr
                    .map(|addr| (SockAddr::from(addr), addr.port()))
            });
            if let Some((dest_sa, dest_port_id)) = dest {
                send_local_keepalive_reply(
                    worker_id,
                    t_start,
                    t_recv,
                    cfg,
                    stats,
                    last_seen_s,
                    handles,
                    &dest_sa,
                    dest_port_id,
                    wire,
                );
            } else {
                log_debug_dir!(
                    cfg.debug_log_drops,
                    worker_id,
                    true,
                    "dropping keepalive reply with no locked client address"
                );
            }
        }
        Err(e) => log_debug_dir!(
            cfg.debug_log_drops,
            worker_id,
            true,
            "classify_c2u_keepalive error: {}",
            e
        ),
    }
}

#[inline]
pub(crate) fn buffer_sync_event(
    worker_id: usize,
    t_start: Instant,
    t_recv: Instant,
    cfg: &Config,
    stats: &dyn StatsSink,
    last_seen_s: &AtomicU64,
    handles: &mut SocketHandles,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
    default_dest: Option<(SockAddr, u16)>,
    event: PayloadEvent<'_>,
) -> Option<BufferedSyncPayload> {
    match event {
        PayloadEvent::UserData(wire) => {
            if wire.src_is_icmp {
                remember_request_seq(sync_state, sync_cache, &wire);
            }
            Some(BufferedSyncPayload::from_wire(&wire))
        }
        PayloadEvent::SyncKeepalive(wire) => {
            handle_c2u_keepalive(
                worker_id,
                t_start,
                t_recv,
                cfg,
                stats,
                last_seen_s,
                handles,
                sync_state,
                sync_cache,
                default_dest,
                &wire,
            );
            None
        }
    }
}

#[inline]
pub(crate) fn sync_session_on_lock_transition(
    was_locked: &mut bool,
    locked: bool,
    sync_state: &SharedSyncIcmpState,
    sync_cache: &mut SyncIcmpCache,
) {
    if *was_locked && !locked {
        reset_session(sync_state, sync_cache);
    }
    *was_locked = locked;
}

#[repr(align(64))]
pub(crate) struct AlignedBuf {
    pub(crate) data: [u8; MAX_WIRE_PAYLOAD],
}

impl AlignedBuf {
    pub(crate) const fn new() -> Self {
        Self {
            data: [0u8; MAX_WIRE_PAYLOAD],
        }
    }
}

pub(crate) struct CachedClientState {
    c2u: bool,
    worker_id: usize,
    pub(crate) dest_sock_type: Type,
    pub(crate) dest_sa: SockAddr,
    pub(crate) dest_port_id: u16,
    pub(crate) recv_port_id: u16,
    log_handles: bool,
}

impl CachedClientState {
    pub(crate) fn new(
        c2u: bool,
        worker_id: usize,
        handles: &SocketHandles,
        recv_port_id: u16,
        log_handles: bool,
    ) -> Self {
        if c2u {
            Self {
                c2u,
                worker_id,
                dest_sock_type: handles.upstream_sock.r#type().unwrap_or(Type::RAW),
                dest_sa: SockAddr::from(handles.upstream_addr),
                dest_port_id: handles.upstream_addr.port(),
                recv_port_id,
                log_handles,
            }
        } else {
            let (dest_sa, dest_port_id) = handles
                .client_addr
                .map(|addr| (SockAddr::from(addr), addr.port()))
                .unwrap_or_else(|| {
                    (
                        SockAddr::from(SocketAddr::new([0, 0, 0, 0].into(), 0)),
                        0u16,
                    )
                });
            Self {
                c2u,
                worker_id,
                dest_sock_type: handles.client_sock.r#type().unwrap_or(Type::RAW),
                dest_sa,
                dest_port_id,
                recv_port_id,
                log_handles,
            }
        }
    }

    pub(crate) fn refresh_from_handles(&mut self, handles: &SocketHandles) {
        if self.c2u {
            self.dest_sock_type = handles.upstream_sock.r#type().unwrap_or(Type::RAW);
            self.dest_sa = SockAddr::from(handles.upstream_addr);
            self.dest_port_id = handles.upstream_addr.port();
        } else {
            self.dest_sock_type = handles.client_sock.r#type().unwrap_or(Type::RAW);
            (self.dest_sa, self.dest_port_id) = handles
                .client_addr
                .map(|addr| (SockAddr::from(addr), addr.port()))
                .unwrap_or_else(|| (self.dest_sa.clone(), self.dest_port_id));
            self.recv_port_id = handles.upstream_addr.port();
        }
    }

    #[inline]
    pub(crate) fn refresh_handles_and_cache(
        &mut self,
        sock_mgr: &SocketManager,
        handles: &mut SocketHandles,
    ) {
        if handles.version != sock_mgr.get_version() {
            let prev_ver = handles.version;
            *handles = sock_mgr.refresh_handles();
            self.refresh_from_handles(handles);
            log_debug_dir!(
                self.log_handles,
                self.worker_id,
                self.c2u,
                "refresh_handles_and_cache: stale={}, new_ver={}, client_addr={:?}, client_connected={}, upstream_addr={}, upstream_connected={}",
                prev_ver,
                handles.version,
                handles.client_addr,
                handles.client_connected,
                handles.upstream_addr,
                handles.upstream_connected
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BestEffortPacer, BufferedSyncPayload, SYNC_BEST_EFFORT_POLL_CAP, locked_client_matches,
    };
    use crate::cli::SupportedProtocol;
    use crate::net::payload::{PayloadEvent, WirePayload};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::{Duration, Instant};

    #[test]
    fn best_effort_pacer_is_immediately_due_without_prior_send() {
        let now = Instant::now();
        let pacer = BestEffortPacer::new(Duration::from_millis(10));
        assert!(pacer.send_due(now));
    }

    #[test]
    fn best_effort_pacer_waits_for_interval_and_never_catches_up_more_than_once() {
        let now = Instant::now();
        let mut pacer = BestEffortPacer::new(Duration::from_millis(100));
        assert!(pacer.send_due(now));
        pacer.mark_sent(now);
        assert!(!pacer.send_due(now));
        assert!(!pacer.send_due(now + Duration::from_millis(99)));
        assert!(pacer.send_due(now + Duration::from_millis(100)));
    }

    #[test]
    fn best_effort_pacer_poll_wait_is_bounded_and_resettable() {
        let mut pacer = BestEffortPacer::new(Duration::from_secs(1));
        assert_eq!(pacer.poll_wait(), SYNC_BEST_EFFORT_POLL_CAP);
        let now = Instant::now();
        pacer.mark_sent(now);
        assert!(!pacer.send_due(now));
        pacer.reset();
        assert!(pacer.send_due(now));

        let short = BestEffortPacer::new(Duration::from_millis(2));
        assert_eq!(short.poll_wait(), Duration::from_millis(2));
    }

    #[test]
    fn buffered_sync_payload_round_trips_validated_user_data() {
        let event = PayloadEvent::UserData(WirePayload {
            src_is_icmp: true,
            src_seq: 77,
            dst_proto: SupportedProtocol::ICMP,
            payload: b"payload",
            pub_len: 7,
        });

        let buffered = BufferedSyncPayload::from_wire(event.wire());
        let replay = buffered.as_event();
        let wire = replay.wire();
        assert!(replay.is_user_data());
        assert!(wire.src_is_icmp);
        assert_eq!(wire.src_seq, 77);
        assert_eq!(wire.dst_proto, SupportedProtocol::ICMP);
        assert_eq!(wire.payload, b"payload");
        assert_eq!(wire.len(), 7);
    }

    #[test]
    fn locked_client_matches_reuses_single_normalized_result() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2222));
        assert!(locked_client_matches(Some(addr), Some(addr)));
        assert!(!locked_client_matches(None, Some(addr)));
        assert!(!locked_client_matches(Some(addr), None));
    }
}
