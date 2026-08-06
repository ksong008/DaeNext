use super::*;
use std::collections::VecDeque;
use std::sync::Condvar;
use std::time::Duration;

const RECLAIM_REASON_COUNT: usize = 12;
const MAX_PENDING_PUBLICATION_IDS: usize = 64;
const MAX_PUBLICATION_PURGE_HISTORY: usize = 128;

static RECLAIM_REQUEST_REGISTRY: OnceLock<Mutex<AllocatorReclaimRequestRegistry>> = OnceLock::new();
static RECLAIM_REQUEST_WAKE: OnceLock<(Mutex<u64>, Condvar)> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AllocatorReclaimScope {
    ControlPlane,
    #[default]
    Global,
}

impl AllocatorReclaimScope {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlane => "control-plane",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AllocatorReclaimUrgency {
    #[default]
    Ordinary,
    Lifecycle,
    Pressure,
}

impl AllocatorReclaimUrgency {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Lifecycle => "lifecycle",
            Self::Pressure => "pressure",
        }
    }
}

#[derive(Clone, Debug)]
struct PendingAllocatorReclaimRequests {
    reason_bits: u64,
    request_count: u64,
    scope: AllocatorReclaimScope,
    urgency: AllocatorReclaimUrgency,
    publication_ids: Vec<u64>,
    publication_overflow: u64,
    requested_at: Option<Instant>,
}

impl Default for PendingAllocatorReclaimRequests {
    fn default() -> Self {
        Self {
            reason_bits: 0,
            request_count: 0,
            scope: AllocatorReclaimScope::ControlPlane,
            urgency: AllocatorReclaimUrgency::Ordinary,
            publication_ids: Vec::new(),
            publication_overflow: 0,
            requested_at: None,
        }
    }
}

impl PendingAllocatorReclaimRequests {
    fn is_empty(&self) -> bool {
        self.reason_bits == 0 || self.request_count == 0
    }

    fn merge_request(
        &mut self,
        reason: AllocatorReclaimReason,
        scope: AllocatorReclaimScope,
        urgency: AllocatorReclaimUrgency,
        publication_id: Option<u64>,
        requested_at: Instant,
    ) {
        self.reason_bits |= reason.request_bit();
        self.request_count = self.request_count.saturating_add(1);
        self.scope = self.scope.max(scope);
        self.urgency = self.urgency.max(urgency);
        if self.requested_at.is_none() {
            self.requested_at = Some(requested_at);
        }
        if let Some(publication_id) = publication_id
            && !self.publication_ids.contains(&publication_id)
        {
            if self.publication_ids.len() < MAX_PENDING_PUBLICATION_IDS {
                self.publication_ids.push(publication_id);
            } else {
                self.publication_overflow = self.publication_overflow.saturating_add(1);
            }
        }
    }

    fn merge_batch(&mut self, batch: &AllocatorReclaimRequestBatch) {
        self.reason_bits |= batch.reason_bits;
        self.request_count = self.request_count.saturating_add(batch.request_count);
        self.scope = self.scope.max(batch.scope);
        self.urgency = self.urgency.max(batch.urgency);
        self.requested_at = match (self.requested_at, batch.requested_at) {
            (Some(current), Some(restored)) => Some(current.min(restored)),
            (current @ Some(_), None) => current,
            (None, restored) => restored,
        };
        for publication_id in &batch.publication_ids {
            if self.publication_ids.contains(publication_id) {
                continue;
            }
            if self.publication_ids.len() < MAX_PENDING_PUBLICATION_IDS {
                self.publication_ids.push(*publication_id);
            } else {
                self.publication_overflow = self.publication_overflow.saturating_add(1);
            }
        }
        self.publication_overflow = self
            .publication_overflow
            .saturating_add(batch.publication_overflow);
    }

    fn take(&mut self) -> AllocatorReclaimRequestBatch {
        let pending = std::mem::take(self);
        AllocatorReclaimRequestBatch {
            reason_bits: pending.reason_bits,
            request_count: pending.request_count,
            scope: pending.scope,
            urgency: pending.urgency,
            publication_ids: pending.publication_ids,
            publication_overflow: pending.publication_overflow,
            requested_at: pending.requested_at,
        }
    }
}

#[derive(Debug, Default)]
struct AllocatorReclaimRequestRegistry {
    pending: PendingAllocatorReclaimRequests,
    requested_total: u64,
    global_requested_total: u64,
    control_plane_requested_total: u64,
    publication_requested_total: u64,
    merged_total: u64,
    batch_total: u64,
    trailing_evaluation_total: u64,
    publication_deduplicated_total: u64,
    publication_overflow_total: u64,
    publication_purges: VecDeque<(u64, u64)>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AllocatorReclaimRequestBatch {
    reason_bits: u64,
    request_count: u64,
    scope: AllocatorReclaimScope,
    urgency: AllocatorReclaimUrgency,
    publication_ids: Vec<u64>,
    publication_overflow: u64,
    requested_at: Option<Instant>,
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
            Self::ControlPlaneIdle => 9,
            Self::SubscriptionRefresh => 10,
            Self::LargeControlCompleted => 11,
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
            9 => Some(Self::ControlPlaneIdle),
            10 => Some(Self::SubscriptionRefresh),
            11 => Some(Self::LargeControlCompleted),
            _ => None,
        }
    }

    const fn default_urgency(self) -> AllocatorReclaimUrgency {
        match self {
            Self::StartupControlBuilt
            | Self::ReloadCompleted
            | Self::ReloadFailedAfterCleanup
            | Self::StopRuntime
            | Self::RetiredGenerationReleased => AllocatorReclaimUrgency::Lifecycle,
            Self::IdleMemoryPressure => AllocatorReclaimUrgency::Pressure,
            Self::ManualLatencyProbe
            | Self::GroupHealthProbe
            | Self::GeodataUpdate
            | Self::SubscriptionRefresh
            | Self::LargeControlCompleted
            | Self::ControlPlaneIdle => AllocatorReclaimUrgency::Ordinary,
        }
    }
}

impl AllocatorReclaimRequestBatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.reason_bits == 0 || self.request_count == 0
    }

    pub(crate) fn request_count(&self) -> u64 {
        self.request_count
    }

    pub(crate) fn scope(&self) -> AllocatorReclaimScope {
        self.scope
    }

    #[cfg(test)]
    pub(crate) fn urgency(&self) -> AllocatorReclaimUrgency {
        self.urgency
    }

    #[cfg(test)]
    pub(crate) fn publication_ids(&self) -> &[u64] {
        &self.publication_ids
    }

    pub(crate) fn reasons(&self) -> impl Iterator<Item = AllocatorReclaimReason> + '_ {
        (0..RECLAIM_REASON_COUNT).filter_map(move |index| {
            let reason = AllocatorReclaimReason::from_request_index(index)?;
            (self.reason_bits & reason.request_bit() != 0).then_some(reason)
        })
    }

    pub(crate) fn primary_reason(&self) -> Option<AllocatorReclaimReason> {
        [
            AllocatorReclaimReason::GeodataUpdate,
            AllocatorReclaimReason::SubscriptionRefresh,
            AllocatorReclaimReason::LargeControlCompleted,
            AllocatorReclaimReason::ManualLatencyProbe,
            AllocatorReclaimReason::GroupHealthProbe,
            AllocatorReclaimReason::RetiredGenerationReleased,
            AllocatorReclaimReason::ReloadCompleted,
            AllocatorReclaimReason::StartupControlBuilt,
            AllocatorReclaimReason::ReloadFailedAfterCleanup,
            AllocatorReclaimReason::StopRuntime,
            AllocatorReclaimReason::ControlPlaneIdle,
            AllocatorReclaimReason::IdleMemoryPressure,
        ]
        .into_iter()
        .find(|reason| self.reason_bits & reason.request_bit() != 0)
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "requestCount": self.request_count(),
            "reasons": self.reasons().map(AllocatorReclaimReason::as_str).collect::<Vec<_>>(),
            "scope": self.scope.as_str(),
            "urgency": self.urgency.as_str(),
            "publicationIds": self.publication_ids,
            "publicationOverflow": self.publication_overflow,
            "oldestRequestAgeMillis": self.requested_at.map(|at| at.elapsed().as_millis().to_string()),
        })
    }
}

pub(crate) fn allocator_request_reclaim(reason: AllocatorReclaimReason) {
    let _ = allocator_request_reclaim_with(
        reason,
        AllocatorReclaimScope::Global,
        reason.default_urgency(),
        None,
    );
}

pub(crate) fn allocator_request_reclaim_for_publication(
    reason: AllocatorReclaimReason,
    publication_id: u64,
) -> Value {
    allocator_request_reclaim_with(
        reason,
        AllocatorReclaimScope::Global,
        reason.default_urgency(),
        Some(publication_id),
    )
}

pub(crate) fn allocator_request_control_plane_reclaim() -> Value {
    allocator_request_reclaim_with(
        AllocatorReclaimReason::ControlPlaneIdle,
        AllocatorReclaimScope::ControlPlane,
        AllocatorReclaimUrgency::Ordinary,
        None,
    )
}

fn allocator_request_reclaim_with(
    reason: AllocatorReclaimReason,
    scope: AllocatorReclaimScope,
    urgency: AllocatorReclaimUrgency,
    publication_id: Option<u64>,
) -> Value {
    let requested_at = Instant::now();
    let Ok(mut registry) = RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
    else {
        return json!({
            "status": "unavailable",
            "reason": reason.as_str(),
            "scope": scope.as_str(),
            "publicationId": publication_id,
        });
    };
    registry.requested_total = registry.requested_total.saturating_add(1);
    match scope {
        AllocatorReclaimScope::Global => {
            registry.global_requested_total = registry.global_requested_total.saturating_add(1);
        }
        AllocatorReclaimScope::ControlPlane => {
            registry.control_plane_requested_total =
                registry.control_plane_requested_total.saturating_add(1);
        }
    }
    if let Some(publication_id) = publication_id {
        registry.publication_requested_total =
            registry.publication_requested_total.saturating_add(1);
        let already_purged = registry
            .publication_purges
            .iter()
            .any(|(known, _)| *known == publication_id);
        let already_pending = registry.pending.publication_ids.contains(&publication_id);
        if already_purged || already_pending {
            registry.publication_deduplicated_total =
                registry.publication_deduplicated_total.saturating_add(1);
            return json!({
                "status": "deduplicated",
                "reason": reason.as_str(),
                "scope": scope.as_str(),
                "urgency": urgency.as_str(),
                "publicationId": publication_id,
                "alreadyPurged": already_purged,
                "alreadyPending": already_pending,
            });
        }
    }
    if !registry.pending.is_empty() {
        registry.merged_total = registry.merged_total.saturating_add(1);
    }
    registry
        .pending
        .merge_request(reason, scope, urgency, publication_id, requested_at);
    if registry.pending.publication_overflow > registry.publication_overflow_total {
        registry.publication_overflow_total = registry.pending.publication_overflow;
    }
    let receipt = json!({
        "status": "requested",
        "reason": reason.as_str(),
        "scope": scope.as_str(),
        "urgency": urgency.as_str(),
        "publicationId": publication_id,
        "execution": "deferred-coordinator-evaluation",
    });
    drop(registry);
    allocator_notify_reclaim_monitor();
    receipt
}

pub(crate) fn allocator_notify_reclaim_monitor() {
    let (epoch, wake) = RECLAIM_REQUEST_WAKE.get_or_init(|| (Mutex::new(0), Condvar::new()));
    if let Ok(mut epoch) = epoch.lock() {
        *epoch = epoch.wrapping_add(1);
        wake.notify_one();
    }
}

pub(crate) fn allocator_reclaim_request_wake_epoch() -> u64 {
    RECLAIM_REQUEST_WAKE
        .get_or_init(|| (Mutex::new(0), Condvar::new()))
        .0
        .lock()
        .map(|epoch| *epoch)
        .unwrap_or(0)
}

pub(crate) fn allocator_wait_for_reclaim_request_since(epoch: u64, timeout: Duration) {
    let (state, wake) = RECLAIM_REQUEST_WAKE.get_or_init(|| (Mutex::new(0), Condvar::new()));
    let Ok(current) = state.lock() else {
        return;
    };
    if *current != epoch || timeout.is_zero() {
        return;
    }
    let _ = wake.wait_timeout_while(current, timeout, |current| *current == epoch);
}

pub(crate) fn allocator_pending_reclaim_requests() -> bool {
    RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
        .map(|registry| !registry.pending.is_empty())
        .unwrap_or(false)
}

pub(crate) fn allocator_pending_publication_reclaim() -> bool {
    RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
        .map(|registry| {
            !registry.pending.is_empty() && !registry.pending.publication_ids.is_empty()
        })
        .unwrap_or(false)
}

#[cfg(test)]
fn allocator_pending_reclaim_reason(reason: AllocatorReclaimReason) -> bool {
    RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
        .map(|registry| registry.pending.reason_bits & reason.request_bit() != 0)
        .unwrap_or(false)
}

pub(crate) fn allocator_pending_reclaim_is_only(reason: AllocatorReclaimReason) -> bool {
    RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
        .map(|registry| {
            !registry.pending.is_empty() && registry.pending.reason_bits == reason.request_bit()
        })
        .unwrap_or(false)
}

pub(crate) fn allocator_pending_reclaim_scope() -> Option<AllocatorReclaimScope> {
    RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
        .ok()
        .and_then(|registry| (!registry.pending.is_empty()).then_some(registry.pending.scope))
}

pub(crate) fn allocator_take_reclaim_requests() -> AllocatorReclaimRequestBatch {
    let Ok(mut registry) = RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
    else {
        return AllocatorReclaimRequestBatch::default();
    };
    let batch = registry.pending.take();
    if !batch.is_empty() {
        registry.batch_total = registry.batch_total.saturating_add(1);
    }
    batch
}

pub(crate) fn allocator_restore_reclaim_requests(batch: &AllocatorReclaimRequestBatch) {
    if batch.is_empty() {
        return;
    }
    if let Ok(mut registry) = RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
    {
        registry.pending.merge_batch(batch);
    }
}

pub(crate) fn allocator_record_trailing_reclaim_evaluation() {
    if let Ok(mut registry) = RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
    {
        registry.trailing_evaluation_total = registry.trailing_evaluation_total.saturating_add(1);
    }
}

pub(crate) fn allocator_record_publication_reclaim(batch: &AllocatorReclaimRequestBatch) {
    if batch.scope != AllocatorReclaimScope::Global || batch.publication_ids.is_empty() {
        return;
    }
    if let Ok(mut registry) = RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
    {
        for publication_id in &batch.publication_ids {
            if let Some((_, count)) = registry
                .publication_purges
                .iter_mut()
                .find(|(known, _)| known == publication_id)
            {
                *count = count.saturating_add(1);
            } else {
                registry.publication_purges.push_back((*publication_id, 1));
                while registry.publication_purges.len() > MAX_PUBLICATION_PURGE_HISTORY {
                    registry.publication_purges.pop_front();
                }
            }
        }
    }
}

pub(super) fn allocator_reclaim_request_snapshot_json() -> Value {
    let Ok(registry) = RECLAIM_REQUEST_REGISTRY
        .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
        .lock()
    else {
        return json!({"status": "unavailable"});
    };
    json!({
        "requestedTotal": registry.requested_total,
        "globalRequestedTotal": registry.global_requested_total,
        "controlPlaneRequestedTotal": registry.control_plane_requested_total,
        "publicationRequestedTotal": registry.publication_requested_total,
        "mergedTotal": registry.merged_total,
        "batchTotal": registry.batch_total,
        "trailingEvaluationTotal": registry.trailing_evaluation_total,
        "publicationDeduplicatedTotal": registry.publication_deduplicated_total,
        "publicationOverflowTotal": registry.publication_overflow_total,
        "pending": AllocatorReclaimRequestBatch {
            reason_bits: registry.pending.reason_bits,
            request_count: registry.pending.request_count,
            scope: registry.pending.scope,
            urgency: registry.pending.urgency,
            publication_ids: registry.pending.publication_ids.clone(),
            publication_overflow: registry.pending.publication_overflow,
            requested_at: registry.pending.requested_at,
        }.json(),
        "publicationPurges": registry.publication_purges.iter().map(|(publication_id, count)| {
            json!({"publicationId": publication_id, "purgeCount": count})
        }).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static REQUEST_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_requests() {
        let mut registry = RECLAIM_REQUEST_REGISTRY
            .get_or_init(|| Mutex::new(AllocatorReclaimRequestRegistry::default()))
            .lock()
            .unwrap();
        *registry = AllocatorReclaimRequestRegistry::default();
    }

    #[test]
    fn deferred_reclaim_requests_merge_scope_urgency_reasons_and_count() {
        let _guard = REQUEST_TEST_LOCK.lock().unwrap();
        reset_requests();

        let _ = allocator_request_control_plane_reclaim();
        allocator_request_reclaim(AllocatorReclaimReason::GroupHealthProbe);
        allocator_request_reclaim(AllocatorReclaimReason::ManualLatencyProbe);

        assert!(allocator_pending_reclaim_reason(
            AllocatorReclaimReason::ManualLatencyProbe
        ));
        assert_eq!(
            allocator_pending_reclaim_scope(),
            Some(AllocatorReclaimScope::Global)
        );

        let batch = allocator_take_reclaim_requests();
        assert_eq!(batch.request_count(), 3);
        assert_eq!(batch.scope(), AllocatorReclaimScope::Global);
        assert_eq!(
            batch.reasons().collect::<Vec<_>>(),
            vec![
                AllocatorReclaimReason::ManualLatencyProbe,
                AllocatorReclaimReason::GroupHealthProbe,
                AllocatorReclaimReason::ControlPlaneIdle,
            ]
        );
        assert!(!allocator_pending_reclaim_requests());
    }

    #[test]
    fn same_publication_is_pending_once_and_purged_at_most_once() {
        let _guard = REQUEST_TEST_LOCK.lock().unwrap();
        reset_requests();

        let first =
            allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 42);
        let duplicate =
            allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 42);
        assert_eq!(first["status"], json!("requested"));
        assert_eq!(duplicate["status"], json!("deduplicated"));
        assert!(allocator_pending_publication_reclaim());

        let batch = allocator_take_reclaim_requests();
        assert_eq!(batch.publication_ids(), &[42]);
        assert!(!allocator_pending_publication_reclaim());
        allocator_record_publication_reclaim(&batch);

        let after_purge =
            allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 42);
        assert_eq!(after_purge["status"], json!("deduplicated"));
        assert_eq!(
            allocator_reclaim_request_snapshot_json()["publicationPurges"][0]["purgeCount"],
            json!(1)
        );
    }

    #[test]
    fn retired_generation_only_detection_does_not_hide_a_merged_reload() {
        let _guard = REQUEST_TEST_LOCK.lock().unwrap();
        reset_requests();

        allocator_request_reclaim(AllocatorReclaimReason::RetiredGenerationReleased);
        assert!(allocator_pending_reclaim_is_only(
            AllocatorReclaimReason::RetiredGenerationReleased
        ));

        allocator_request_reclaim(AllocatorReclaimReason::ReloadCompleted);
        assert!(!allocator_pending_reclaim_is_only(
            AllocatorReclaimReason::RetiredGenerationReleased
        ));
        let _ = allocator_take_reclaim_requests();
    }

    #[test]
    fn a_taken_batch_can_be_restored_without_losing_metadata() {
        let _guard = REQUEST_TEST_LOCK.lock().unwrap();
        reset_requests();
        let _ =
            allocator_request_reclaim_for_publication(AllocatorReclaimReason::ReloadCompleted, 7);
        let batch = allocator_take_reclaim_requests();
        allocator_restore_reclaim_requests(&batch);
        let restored = allocator_take_reclaim_requests();
        assert_eq!(restored.publication_ids(), &[7]);
        assert_eq!(restored.scope(), AllocatorReclaimScope::Global);
        assert_eq!(restored.urgency(), AllocatorReclaimUrgency::Lifecycle);
    }

    #[test]
    fn a_new_request_wakes_the_event_driven_coordinator_wait() {
        let _guard = REQUEST_TEST_LOCK.lock().unwrap();
        reset_requests();
        let epoch = allocator_reclaim_request_wake_epoch();
        let requested = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(10));
            allocator_request_reclaim(AllocatorReclaimReason::GeodataUpdate);
        });
        let started_at = Instant::now();
        allocator_wait_for_reclaim_request_since(epoch, Duration::from_secs(1));
        requested.join().unwrap();

        assert!(started_at.elapsed() < Duration::from_millis(500));
        assert!(allocator_pending_reclaim_requests());
        let _ = allocator_take_reclaim_requests();
    }
}
