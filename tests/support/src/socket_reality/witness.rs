use sha2::{Digest, Sha256};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::timing::{SOCKET_WITNESS_POLL, SOCKET_WITNESS_WAIT};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointObservation {
    pub endpoint: String,
    pub sequence: u64,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub probe_id: u64,
    pub payload_digest: [u8; 32],
    pub received_at_nanos: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSendObservation {
    pub sequence: u64,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub probe_id: u64,
    pub payload_digest: [u8; 32],
    pub sent_at_nanos: u64,
}

pub fn probe_payload(probe_id: u64) -> Vec<u8> {
    let mut payload = b"pkthere-reality-probe:".to_vec();
    payload.extend_from_slice(&probe_id.to_be_bytes());
    payload
}

pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub struct UdpWitness {
    local_addr: SocketAddr,
    observations: Arc<Mutex<Vec<EndpointObservation>>>,
    stop: Arc<AtomicBool>,
    completed: mpsc::Receiver<io::Result<()>>,
    thread: Option<JoinHandle<()>>,
}

impl UdpWitness {
    pub fn spawn(endpoint: &str, bind: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(SOCKET_WITNESS_POLL))?;
        let local_addr = socket.local_addr()?;
        let observations = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let observations_thread = Arc::clone(&observations);
        let stop_thread = Arc::clone(&stop);
        let endpoint = endpoint.to_owned();
        let start = Instant::now();
        let (completion_sender, completed) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = run_witness(
                socket,
                &endpoint,
                local_addr,
                &observations_thread,
                &stop_thread,
                start,
            );
            let _ = completion_sender.send(result);
        });
        Ok(Self {
            local_addr,
            observations,
            stop,
            completed,
            thread: Some(thread),
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn observations(&self) -> Vec<EndpointObservation> {
        self.observations
            .lock()
            .expect("witness observations")
            .clone()
    }

    pub fn shutdown(mut self, deadline: Instant) -> io::Result<()> {
        self.shutdown_inner(deadline)
    }

    fn shutdown_inner(&mut self, deadline: Instant) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        let completion = self
            .completed
            .recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match completion {
            Ok(result) => {
                let join = self.thread.take().map(|thread| {
                    thread
                        .join()
                        .map_err(|_| io::Error::other("UDP witness thread panicked"))
                });
                if let Some(join) = join {
                    join?;
                }
                result
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(thread) = self.thread.take() {
                    thread
                        .join()
                        .map_err(|_| io::Error::other("UDP witness thread panicked"))?;
                }
                Err(io::Error::other(
                    "UDP witness completion channel disconnected",
                ))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "UDP witness {} did not stop by its deadline",
                    self.local_addr
                ),
            )),
        }
    }
}

fn run_witness(
    socket: UdpSocket,
    endpoint: &str,
    local_addr: SocketAddr,
    observations: &Mutex<Vec<EndpointObservation>>,
    stop: &AtomicBool,
    start: Instant,
) -> io::Result<()> {
    let mut sequence = 1u64;
    let mut buffer = [0u8; 2048];
    while !stop.load(Ordering::Acquire) {
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                let payload = &buffer[..length];
                let Some(probe_id) = parse_probe_id(payload) else {
                    continue;
                };
                observations
                    .lock()
                    .expect("witness observations")
                    .push(EndpointObservation {
                        endpoint: endpoint.to_owned(),
                        sequence,
                        source,
                        destination: local_addr,
                        probe_id,
                        payload_digest: payload_digest(payload),
                        received_at_nanos: nanos(start.elapsed()),
                    });
                sequence = sequence.saturating_add(1);
                socket.send_to(payload, source)?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl Drop for UdpWitness {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.shutdown_inner(Instant::now() + SOCKET_WITNESS_WAIT);
        }
    }
}

pub fn client_send_observation(
    sequence: u64,
    source: SocketAddr,
    destination: SocketAddr,
    probe_id: u64,
    payload: &[u8],
    elapsed: Duration,
) -> ClientSendObservation {
    ClientSendObservation {
        sequence,
        source,
        destination,
        probe_id,
        payload_digest: payload_digest(payload),
        sent_at_nanos: nanos(elapsed),
    }
}

fn parse_probe_id(payload: &[u8]) -> Option<u64> {
    let suffix = payload.get(payload.len().checked_sub(8)?..)?;
    Some(u64::from_be_bytes(suffix.try_into().ok()?))
}

fn nanos(duration: Duration) -> u64 {
    duration
        .as_nanos()
        .try_into()
        .expect("test witness elapsed duration must fit in u64 nanoseconds")
}

#[cfg(test)]
mod tests {
    use super::{UdpWitness, payload_digest, probe_payload};
    use crate::timing::{SOCKET_WITNESS_WAIT, TEST_POLL_INTERVAL};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::time::Instant;

    #[test]
    fn witness_records_exact_probe_and_digest() {
        let witness = UdpWitness::spawn(
            "endpoint-a",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("spawn witness");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind client");
        client
            .set_read_timeout(Some(SOCKET_WITNESS_WAIT))
            .expect("timeout");
        let payload = probe_payload(42);
        client
            .send_to(&payload, witness.local_addr())
            .expect("send probe");
        let mut echoed = [0u8; 128];
        let length = client.recv(&mut echoed).expect("echo");
        assert_eq!(&echoed[..length], payload);
        let deadline = Instant::now() + SOCKET_WITNESS_WAIT;
        let observations = loop {
            let observations = witness.observations();
            if !observations.is_empty() {
                break observations;
            }
            assert!(Instant::now() < deadline, "witness did not record probe");
            std::thread::sleep(TEST_POLL_INTERVAL);
        };
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].probe_id, 42);
        assert_eq!(observations[0].payload_digest, payload_digest(&payload));
        let address = witness.local_addr();
        witness
            .shutdown(Instant::now() + SOCKET_WITNESS_WAIT)
            .expect("shutdown witness");
        std::net::UdpSocket::bind(address).expect("witness released UDP port");
    }
}
