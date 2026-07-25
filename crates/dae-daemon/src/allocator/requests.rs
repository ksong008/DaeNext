use super::*;

const RECLAIM_REASON_COUNT: usize = 9;
const RECLAIM_REQUEST_COUNT_SHIFT: u32 = RECLAIM_REASON_COUNT as u32;
const RECLAIM_REASON_MASK: u64 = (1_u64 << RECLAIM_REQUEST_COUNT_SHIFT) - 1;
const RECLAIM_REQUEST_COUNT_MAX: u64 = u64::MAX >> RECLAIM_REQUEST_COUNT_SHIFT;

// Keep the reason bits and coalesced request count in one atomic word so a
// consumer can never take a reason from one request and the count from the
// next request racing with it.
static PENDING_RECLAIM_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_DEFERRED_RECLAIM_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_DEFERRED_RECLAIM_BATCHES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AllocatorReclaimRequestBatch {
    reason_bits: u64,
    request_count: u64,
}

impl AllocatorReclaimReason {
    const fn request_index(self) -> usize {
        match self {
            Self::StartupControlBuilt => 0,
            Self::ReloadCompleted => 1,
            Self::ReloadFailedAfterCleanup => 2,
            Self::StopRuntime => 3,
            Self::IdleMemoryPressure => 4,
            Self::ManualLatencyProbe => 5,
            Self::GroupHealthProbe => 6,
            Self::GeodataUpdate => 7,
            Self::RetiredGenerationReleased => 8,
        }
    }

    const fn request_bit(self) -> u64 {
        1_u64 << self.request_index()
    }

    fn from_request_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::StartupControlBuilt),
            1 => Some(Self::ReloadCompleted),
            2 => Some(Self::ReloadFailedAfterCleanup),
            3 => Some(Self::StopRuntime),
            4 => Some(Self::IdleMemoryPressure),
            5 => Some(Self::ManualLatencyProbe),
            6 => Some(Self::GroupHealthProbe),
            7 => Some(Self::GeodataUpdate),
            8 => Some(Self::RetiredGenerationReleased),
            _ => None,
        }
    }
}

impl AllocatorReclaimRequestBatch {
    pub(crate) fn is_empty(self) -> bool {
        self.reason_bits == 0 || self.request_count == 0
    }

    pub(crate) fn request_count(self) -> u64 {
        self.request_count
    }

    pub(crate) fn reasons(self) -> impl Iterator<Item = AllocatorReclaimReason> {
        (0..RECLAIM_REASON_COUNT).filter_map(move |index| {
            let reason = AllocatorReclaimReason::from_request_index(index)?;
            (self.reason_bits & reason.request_bit() != 0).then_some(reason)
        })
    }

    pub(crate) fn primary_reason(self) -> Option<AllocatorReclaimReason> {
        [
            AllocatorReclaimReason::GeodataUpdate,
            AllocatorReclaimReason::ManualLatencyProbe,
            AllocatorReclaimReason::GroupHealthProbe,
            AllocatorReclaimReason::RetiredGenerationReleased,
            AllocatorReclaimReason::ReloadCompleted,
            AllocatorReclaimReason::StartupControlBuilt,
            AllocatorReclaimReason::ReloadFailedAfterCleanup,
            AllocatorReclaimReason::StopRuntime,
            AllocatorReclaimReason::IdleMemoryPressure,
        ]
        .into_iter()
        .find(|reason| self.reason_bits & reason.request_bit() != 0)
    }

    pub(crate) fn json(self) -> Value {
        json!({
            "requestCount": self.request_count(),
            "reasons": self.reasons().map(AllocatorReclaimReason::as_str).collect::<Vec<_>>(),
        })
    }
}

pub(crate) fn allocator_request_reclaim(reason: AllocatorReclaimReason) {
    let _ =
        PENDING_RECLAIM_REQUESTS.fetch_update(Ordering::Release, Ordering::Relaxed, |current| {
            Some(pending_reclaim_state_with_request(current, reason))
        });
    TOTAL_DEFERRED_RECLAIM_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn allocator_pending_reclaim_requests() -> bool {
    PENDING_RECLAIM_REQUESTS.load(Ordering::Acquire) & RECLAIM_REASON_MASK != 0
}

pub(crate) fn allocator_pending_reclaim_reason(reason: AllocatorReclaimReason) -> bool {
    PENDING_RECLAIM_REQUESTS.load(Ordering::Acquire) & reason.request_bit() != 0
}

pub(crate) fn allocator_take_reclaim_requests() -> AllocatorReclaimRequestBatch {
    let batch =
        reclaim_request_batch_from_state(PENDING_RECLAIM_REQUESTS.swap(0, Ordering::AcqRel));
    if !batch.is_empty() {
        TOTAL_DEFERRED_RECLAIM_BATCHES.fetch_add(1, Ordering::Relaxed);
    }
    batch
}

pub(super) fn allocator_reclaim_request_snapshot_json() -> Value {
    let pending =
        reclaim_request_batch_from_state(PENDING_RECLAIM_REQUESTS.load(Ordering::Acquire));
    json!({
        "requestedTotal": TOTAL_DEFERRED_RECLAIM_REQUESTS.load(Ordering::Relaxed),
        "batchTotal": TOTAL_DEFERRED_RECLAIM_BATCHES.load(Ordering::Relaxed),
        "pending": pending.json(),
    })
}

fn pending_reclaim_state_with_request(current: u64, reason: AllocatorReclaimReason) -> u64 {
    let request_count = (current >> RECLAIM_REQUEST_COUNT_SHIFT)
        .saturating_add(1)
        .min(RECLAIM_REQUEST_COUNT_MAX);
    (current & RECLAIM_REASON_MASK)
        | reason.request_bit()
        | (request_count << RECLAIM_REQUEST_COUNT_SHIFT)
}

fn reclaim_request_batch_from_state(state: u64) -> AllocatorReclaimRequestBatch {
    AllocatorReclaimRequestBatch {
        reason_bits: state & RECLAIM_REASON_MASK,
        request_count: state >> RECLAIM_REQUEST_COUNT_SHIFT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static REQUEST_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn deferred_reclaim_requests_coalesce_reasons_and_count_requests() {
        let _guard = REQUEST_TEST_LOCK.lock().unwrap();
        let _ = allocator_take_reclaim_requests();

        allocator_request_reclaim(AllocatorReclaimReason::GroupHealthProbe);
        allocator_request_reclaim(AllocatorReclaimReason::GroupHealthProbe);
        allocator_request_reclaim(AllocatorReclaimReason::ManualLatencyProbe);

        assert!(allocator_pending_reclaim_reason(
            AllocatorReclaimReason::ManualLatencyProbe
        ));
        assert!(!allocator_pending_reclaim_reason(
            AllocatorReclaimReason::RetiredGenerationReleased
        ));

        let batch = allocator_take_reclaim_requests();
        assert_eq!(batch.request_count(), 3);
        assert_eq!(
            batch.reasons().collect::<Vec<_>>(),
            vec![
                AllocatorReclaimReason::ManualLatencyProbe,
                AllocatorReclaimReason::GroupHealthProbe,
            ]
        );
        assert_eq!(
            batch.primary_reason(),
            Some(AllocatorReclaimReason::ManualLatencyProbe)
        );
        assert!(!allocator_pending_reclaim_requests());
    }

    #[test]
    fn packed_reclaim_state_keeps_reason_and_count_in_one_update() {
        let first = pending_reclaim_state_with_request(0, AllocatorReclaimReason::GroupHealthProbe);
        let second =
            pending_reclaim_state_with_request(first, AllocatorReclaimReason::ManualLatencyProbe);
        let batch = reclaim_request_batch_from_state(second);

        assert_eq!(batch.request_count(), 2);
        assert_eq!(
            batch.reasons().collect::<Vec<_>>(),
            vec![
                AllocatorReclaimReason::ManualLatencyProbe,
                AllocatorReclaimReason::GroupHealthProbe,
            ]
        );

        let saturated = (RECLAIM_REQUEST_COUNT_MAX << RECLAIM_REQUEST_COUNT_SHIFT)
            | AllocatorReclaimReason::GeodataUpdate.request_bit();
        let saturated =
            pending_reclaim_state_with_request(saturated, AllocatorReclaimReason::GroupHealthProbe);
        assert_eq!(
            reclaim_request_batch_from_state(saturated).request_count(),
            RECLAIM_REQUEST_COUNT_MAX
        );
    }
}
