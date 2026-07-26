#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::stale_association::{ObservedStaleRetry, StaleRetryError};
use super::{
    StableSendCore,
    context::{StableProtocolReservation, StableSendTransaction},
};
use crate::atomic_core::{
    AtomicU64Authority, AtomicU64Value, PreparedSessionGeneration, acquire_epoch_lane,
    close_epoch_gate, release_epoch_lane, release_writer_epoch_lane, reopen_epoch_gate,
    reserve_epoch_lane_for_writer,
};
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use loom::sync::{Arc, mpsc};
use loom::thread;

const CLOSED_BIT: u64 = 1_u64 << 63;

struct ModeledAuthority {
    active: Arc<AtomicBool>,
}

struct ModeledReservation {
    active: Arc<AtomicBool>,
}

impl StableProtocolReservation for ModeledReservation {
    type Protocol = ModeledAuthority;
    type Error = ();

    fn reserve(self) -> Result<Self::Protocol, Self::Error> {
        Ok(ModeledAuthority {
            active: self.active,
        })
    }
}

struct LoomU64(AtomicU64);

impl AtomicU64Authority for LoomU64 {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.0
            .compare_exchange(current, next, Ordering::Release, Ordering::Acquire)
    }

    fn cross_atomic_fence(&self) {
        loom::sync::atomic::fence(Ordering::SeqCst);
    }
}

impl AtomicU64Value for LoomU64 {
    fn load_acquire(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn store_release(&self, value: u64) {
        self.0.store(value, Ordering::Release);
    }
}

struct PreparedGenerationReservation {
    generation: PreparedSessionGeneration,
    published: Arc<LoomU64>,
    active: Arc<AtomicBool>,
}

impl StableProtocolReservation for PreparedGenerationReservation {
    type Protocol = ModeledAuthority;
    type Error = ();

    fn reserve(self) -> Result<Self::Protocol, Self::Error> {
        if !self.generation.is_current(self.published.as_ref()) {
            return Err(());
        }
        Ok(ModeledAuthority {
            active: self.active,
        })
    }
}

struct LoomFlowAuthority {
    lane: Arc<LoomU64>,
    epoch: u64,
}

struct LoomStableSend {
    sent: Arc<AtomicBool>,
    identity: Arc<AtomicU64>,
}

impl StableSendTransaction<LoomFlowAuthority, ModeledAuthority, ModeledAuthority>
    for LoomStableSend
{
    type SendResult = ();
    type Output = ();

    fn send(
        &mut self,
        _flow: &mut LoomFlowAuthority,
        socket: &ModeledAuthority,
        protocol: &mut ModeledAuthority,
    ) {
        assert!(socket.active.load(Ordering::Acquire));
        assert!(protocol.active.load(Ordering::Acquire));
        assert_eq!(self.identity.load(Ordering::Acquire), 1);
    }

    fn complete(
        self,
        _flow: &mut LoomFlowAuthority,
        _socket: &ModeledAuthority,
        _protocol: &mut ModeledAuthority,
        _send_result: (),
    ) {
        self.sent.store(true, Ordering::Release);
    }
}

impl Drop for LoomFlowAuthority {
    fn drop(&mut self) {
        release_epoch_lane(&*self.lane, self.epoch).expect("release stable flow lane");
    }
}

impl Drop for ModeledAuthority {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[test]
fn production_stable_send_core_releases_protocol_socket_then_flow() {
    loom::model(|| {
        let gate = Arc::new(LoomU64(AtomicU64::new(1)));
        let lane = Arc::new(LoomU64(AtomicU64::new(0)));
        let socket_active = Arc::new(AtomicBool::new(true));
        let protocol_active = Arc::new(AtomicBool::new(true));
        let sent = Arc::new(AtomicBool::new(false));
        let reset_identity = Arc::new(AtomicU64::new(1));
        let (admitted_tx, admitted_rx) = mpsc::channel();

        let sender_gate = Arc::clone(&gate);
        let sender_lane = Arc::clone(&lane);
        let sender_socket = Arc::clone(&socket_active);
        let sender_protocol = Arc::clone(&protocol_active);
        let sender_sent = Arc::clone(&sent);
        let sender_identity = Arc::clone(&reset_identity);
        let sender = thread::spawn(move || {
            let epoch = acquire_epoch_lane(&*sender_gate, &*sender_lane, CLOSED_BIT)
                .expect("acquire stable flow lane");
            admitted_tx.send(()).expect("publish stable admission");
            StableSendCore::new(LoomFlowAuthority {
                lane: sender_lane,
                epoch,
            })
            .acquire_socket(ModeledAuthority {
                active: sender_socket,
            })
            .reserve_protocol(ModeledReservation {
                active: sender_protocol,
            })
            .expect("reserve modeled protocol")
            .perform(LoomStableSend {
                sent: sender_sent,
                identity: sender_identity,
            });
        });

        let reset_gate = Arc::clone(&gate);
        let reset_lane = Arc::clone(&lane);
        let reset_value = Arc::clone(&reset_identity);
        let reset = thread::spawn(move || {
            admitted_rx.recv().expect("stable sender admission");
            let transition = close_epoch_gate(&*reset_gate, CLOSED_BIT).expect("close flow gate");
            while !reserve_epoch_lane_for_writer(&*reset_lane).expect("drain stable sender") {
                thread::yield_now();
            }
            reset_value.store(2, Ordering::Release);
            release_writer_epoch_lane(&*reset_lane).expect("release writer lane");
            reopen_epoch_gate(&*reset_gate, transition, CLOSED_BIT).expect("reopen flow gate");
        });

        sender.join().expect("sender");
        reset.join().expect("reset");
        assert!(!socket_active.load(Ordering::Acquire));
        assert!(!protocol_active.load(Ordering::Acquire));
        assert!(sent.load(Ordering::Acquire));
        assert_eq!(reset_identity.load(Ordering::Acquire), 2);
    });
}

#[test]
fn production_prepared_session_reservation_cannot_cross_flow_publication() {
    loom::model(|| {
        let gate = Arc::new(LoomU64(AtomicU64::new(1)));
        let lane = Arc::new(LoomU64(AtomicU64::new(0)));
        let generation = Arc::new(LoomU64(AtomicU64::new(7)));
        let socket_active = Arc::new(AtomicBool::new(true));
        let protocol_active = Arc::new(AtomicBool::new(true));
        let sent = Arc::new(AtomicBool::new(false));
        let (admitted_tx, admitted_rx) = mpsc::channel();

        let sender_gate = Arc::clone(&gate);
        let sender_lane = Arc::clone(&lane);
        let sender_generation = Arc::clone(&generation);
        let sender_socket = Arc::clone(&socket_active);
        let sender_protocol = Arc::clone(&protocol_active);
        let sender_sent = Arc::clone(&sent);
        let sender = thread::spawn(move || {
            let epoch = acquire_epoch_lane(sender_gate.as_ref(), sender_lane.as_ref(), CLOSED_BIT)
                .expect("acquire stable flow lane");
            let prepared = PreparedSessionGeneration::claim(sender_generation.as_ref(), 7, true)
                .expect("claim exact prepared generation");
            admitted_tx.send(()).expect("publish stable admission");
            StableSendCore::new(LoomFlowAuthority {
                lane: sender_lane,
                epoch,
            })
            .acquire_socket(ModeledAuthority {
                active: sender_socket,
            })
            .reserve_protocol(PreparedGenerationReservation {
                generation: prepared,
                published: sender_generation,
                active: sender_protocol,
            })
            .expect("reserve before publication")
            .perform(LoomStableSend {
                sent: sender_sent,
                identity: Arc::new(AtomicU64::new(1)),
            });
        });

        let writer_gate = Arc::clone(&gate);
        let writer_lane = Arc::clone(&lane);
        let writer_generation = Arc::clone(&generation);
        let writer = thread::spawn(move || {
            admitted_rx.recv().expect("stable sender admission");
            let transition =
                close_epoch_gate(writer_gate.as_ref(), CLOSED_BIT).expect("close flow gate");
            while !reserve_epoch_lane_for_writer(writer_lane.as_ref()).expect("drain stable sender")
            {
                thread::yield_now();
            }
            writer_generation.store_release(8);
            release_writer_epoch_lane(writer_lane.as_ref()).expect("release writer lane");
            reopen_epoch_gate(writer_gate.as_ref(), transition, CLOSED_BIT)
                .expect("publish changed generation");
        });

        sender.join().expect("sender");
        writer.join().expect("writer");
        assert!(sent.load(Ordering::Acquire));
        assert_eq!(AtomicU64Value::load_acquire(generation.as_ref()), 8);
        assert!(!socket_active.load(Ordering::Acquire));
        assert!(!protocol_active.load(Ordering::Acquire));
    });
}

#[test]
fn production_stale_retry_core_holds_flow_lane_through_retry_or_loses_to_reset() {
    loom::model(|| {
        let gate = Arc::new(LoomU64(AtomicU64::new(1)));
        let lane = Arc::new(LoomU64(AtomicU64::new(0)));
        let identity = Arc::new(AtomicU64::new(1));
        let sends = Arc::new(AtomicUsize::new(0));

        let reset_gate = Arc::clone(&gate);
        let reset_lane = Arc::clone(&lane);
        let reset_identity = Arc::clone(&identity);
        let reset = thread::spawn(move || {
            let transition = close_epoch_gate(&*reset_gate, CLOSED_BIT).expect("close flow gate");
            while !reserve_epoch_lane_for_writer(&*reset_lane).expect("reserve flow lane") {
                thread::yield_now();
            }
            reset_identity.store(2, Ordering::Release);
            release_writer_epoch_lane(&*reset_lane).expect("release writer lane");
            reopen_epoch_gate(&*reset_gate, transition, CLOSED_BIT).expect("reopen flow gate");
        });

        let retry_gate = Arc::clone(&gate);
        let retry_lane = Arc::clone(&lane);
        let retry_identity = Arc::clone(&identity);
        let retry_sends = Arc::clone(&sends);
        let retry = thread::spawn(move || {
            let retry = ObservedStaleRetry::new(7, 1_u64, 91_u8)
                .authorize_transition(1)
                .expect("authorize transition")
                .reconciled(7)
                .expect("reconcile");
            let epoch = loop {
                match acquire_epoch_lane(&*retry_gate, &*retry_lane, CLOSED_BIT) {
                    Ok(epoch) => break epoch,
                    Err(crate::atomic_core::LaneAdmissionError::Closed) => thread::yield_now(),
                    Err(error) => panic!("retry lane admission failed: {error:?}"),
                }
            };
            let current = retry_identity.load(Ordering::Acquire);
            let result = retry.authorize(current);
            if let Ok(authorized) = result {
                assert_eq!(*authorized.payload(), 91);
                retry_sends.fetch_add(1, Ordering::AcqRel);
                authorized.complete(false).expect("complete one retry");
            }
            release_epoch_lane(&*retry_lane, epoch).expect("release retry lane");
            current
        });

        let observed_identity = retry.join().expect("retry actor");
        reset.join().expect("reset actor");
        if observed_identity == 1 {
            assert_eq!(sends.load(Ordering::Acquire), 1);
        } else {
            assert_eq!(observed_identity, 2);
            assert_eq!(sends.load(Ordering::Acquire), 0);
        }
        assert_eq!(identity.load(Ordering::Acquire), 2);
    });
}

#[test]
fn production_stale_retry_core_is_one_shot_epoch_bound_and_payload_exact() {
    loom::model(|| {
        assert!(matches!(
            ObservedStaleRetry::new(11, 3_u64, 41_u8)
                .authorize_transition(3)
                .expect("authorize transition")
                .reconciled(10),
            Err(StaleRetryError::AssociationChanged)
        ));
        let authorized = ObservedStaleRetry::new(11, 3_u64, 42_u8)
            .authorize_transition(3)
            .expect("authorize transition")
            .reconciled(11)
            .expect("matching reconciliation")
            .authorize(3)
            .expect("matching flow identity");
        assert_eq!(*authorized.payload(), 42);
        let completion = authorized.complete(true);
        assert_eq!(completion, Err(StaleRetryError::RetryRepeated));
    });
}

#[test]
fn production_stale_retry_core_rejects_foreign_flow_before_exposing_payload() {
    loom::model(|| {
        let mutations = AtomicUsize::new(0);
        let result = ObservedStaleRetry::new(5, 9_u64, 77_u8).authorize_transition(10);
        if result.is_ok() {
            mutations.fetch_add(1, Ordering::AcqRel);
        }
        assert!(matches!(result, Err(StaleRetryError::FlowChanged)));
        assert_eq!(mutations.load(Ordering::Acquire), 0);
    });
}
