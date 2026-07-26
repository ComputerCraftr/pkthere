use crate::net::managed_socket::{
    ManagedReadiness, ManagedReceiver, ManagedSocket, WorkerDescriptorCache,
};
use crate::net::sock_mgr::receiver_transfer::{
    ReceiverGenerationView, ReceiverTransferCore, ReceiverTransferError,
};
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiverRole {
    Listener,
    Upstream,
}

type PublishedReceiverGeneration =
    crate::authority::AuthorityAtomic<crate::authority::tags::ReceiverClaim, AtomicU64>;
type ReceiverGeneration =
    ReceiverGenerationView<PublishedReceiverGeneration, Arc<PublishedReceiverGeneration>>;
type ManagedReceiverTransfer = ReceiverTransferCore<
    ManagedReceiver,
    PublishedReceiverGeneration,
    Arc<PublishedReceiverGeneration>,
>;

struct ReceiverSlot {
    transfer: ManagedReceiverTransfer,
    socket: ManagedSocket,
}

pub(crate) struct ReceiverRegistry {
    role: ReceiverRole,
    published_generation: ReceiverGeneration,
    slot: crate::authority::AuthorityMutex<crate::authority::tags::ReceiverClaim, ReceiverSlot>,
}

/// Unique, generation-checked receive ownership for one worker direction.
///
/// The registry mutex is used only to claim or replace ownership. Polling and
/// packet receive use the contained `ManagedReceiver` directly and therefore
/// do not serialize the data path.
pub(crate) struct ReceiverClaim {
    registry: Arc<ReceiverRegistry>,
    owner: usize,
    generation: u64,
    receiver: ManagedReceiver,
    descriptor_cache: WorkerDescriptorCache,
}

impl ReceiverRegistry {
    pub(crate) fn new(role: ReceiverRole, socket_slot: u32, socket: &ManagedSocket) -> Arc<Self> {
        let published = Arc::new(PublishedReceiverGeneration::new_u64(
            1,
            crate::authority::AtomicProtocolId::ReceiverGeneration,
        ));
        let (transfer, published_generation) =
            ReceiverTransferCore::new(ManagedReceiver::new(socket), published);
        let registry = Self {
            role,
            published_generation,
            slot: crate::authority::AuthorityMutex::new(
                ReceiverSlot {
                    transfer,
                    socket: socket.clone(),
                },
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::ReceiverClaim,
                    flow: 0,
                    direction: match role {
                        ReceiverRole::Listener => 0,
                        ReceiverRole::Upstream => 1,
                    },
                    kind: 0,
                    session: u64::from(socket_slot) + 1,
                },
            ),
        };
        registry.slot.prewarm().unwrap_or_else(|error| {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "{role:?} receiver registry authority prewarm failed: {error}"
            ))
        });
        Arc::new(registry)
    }

    pub(crate) fn claim(self: &Arc<Self>, owner: usize) -> io::Result<ReceiverClaim> {
        let mut slot = self.lock_slot()?;
        let (generation, receiver) = slot
            .transfer
            .claim(owner)
            .map_err(receiver_transfer_error)?;
        Ok(ReceiverClaim {
            registry: Arc::clone(self),
            owner,
            generation,
            receiver,
            descriptor_cache: WorkerDescriptorCache::for_worker(owner),
        })
    }

    pub(crate) fn publish_socket(&self, socket: &ManagedSocket) -> io::Result<u64> {
        self.publish_staged(socket, ManagedReceiver::new(socket))
    }

    pub(crate) fn publish_staged(
        &self,
        socket: &ManagedSocket,
        receiver: ManagedReceiver,
    ) -> io::Result<u64> {
        let mut slot = self.lock_slot()?;
        if slot.socket.same_descriptor(socket) {
            return Ok(slot.transfer.generation());
        }
        let generation = slot
            .transfer
            .publish_replacement(receiver)
            .map_err(receiver_transfer_error)?;
        slot.socket = socket.clone();
        Ok(generation)
    }

    pub(crate) fn precheck_publication(&self) -> io::Result<()> {
        let slot = self.lock_slot()?;
        slot.transfer
            .precheck_publication()
            .map_err(receiver_transfer_error)
    }

    pub(crate) fn generation(&self) -> io::Result<u64> {
        Ok(self.published_generation.generation())
    }

    fn lock_slot(
        &self,
    ) -> io::Result<
        crate::authority::AuthorityMutexGuard<
            '_,
            crate::authority::tags::ReceiverClaim,
            ReceiverSlot,
        >,
    > {
        self.slot.lock().map_err(|error| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "{:?} receiver registry authority acquisition failed: {error}",
                self.role,
            ));
            io::Error::other(format!(
                "{:?} receiver registry authority acquisition failed",
                self.role,
            ))
        })
    }

    #[cfg(all(test, not(miri)))]
    pub(crate) fn snapshot(&self) -> (u64, Option<usize>, bool, bool) {
        let slot = self.lock_slot().expect("receiver registry test snapshot");
        let snapshot = slot.transfer.snapshot();
        (
            snapshot.generation,
            snapshot.owner,
            snapshot.receiver_available,
            snapshot.owner_exited,
        )
    }
}

impl ReceiverClaim {
    pub(crate) fn prepare_for_receive(&mut self) -> io::Result<()> {
        if self
            .registry
            .published_generation
            .changed(self.generation)
            .is_some()
        {
            let mut slot = self.registry.lock_slot()?;
            if let Some((generation, receiver)) = slot
                .transfer
                .transfer_replacement_to_owner(self.owner, self.generation)
                .map_err(receiver_transfer_error)?
            {
                self.receiver = receiver;
                self.generation = generation;
            }
            drop(slot);
        }
        self.receiver
            .reconcile_descriptor_cache(&mut self.descriptor_cache)
    }

    pub(crate) fn topology_epoch(&self) -> u64 {
        self.receiver.topology_epoch()
    }

    pub(crate) fn wait_until_readable_or_wake(
        &mut self,
        wake: &std::net::UdpSocket,
        timeout: Duration,
    ) -> io::Result<ManagedReadiness<'_>> {
        self.receiver
            .wait_until_readable_or_wake(&mut self.descriptor_cache, wake, timeout)
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for ReceiverClaim {
    fn drop(&mut self) {
        let Ok(mut slot) = self.registry.lock_slot() else {
            return;
        };
        if let Err(error) = slot.transfer.owner_exit(self.owner) {
            crate::runtime_support::publish_process_fatal(format_args!(
                "receiver owner exit violated transfer state: {error:?}"
            ));
        }
    }
}

fn receiver_transfer_error(error: ReceiverTransferError) -> io::Error {
    io::Error::other(match error {
        ReceiverTransferError::AlreadyOwned => "receiver is already owned",
        ReceiverTransferError::GenerationExhausted => "receiver generation exhausted",
        ReceiverTransferError::GenerationMovedBackwards => "receiver generation moved backwards",
        ReceiverTransferError::OwnerExited => "receiver owner already exited",
        ReceiverTransferError::OwnershipLost => "receiver ownership is no longer authoritative",
        ReceiverTransferError::ReceiverUnavailable => "receiver generation is not available",
    })
}
