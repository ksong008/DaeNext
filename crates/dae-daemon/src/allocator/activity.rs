use super::*;

const RECLAIM_BUSY_KIND_COUNT: usize = 7;

static ACTIVE_RECLAIM_BUSY_LEASES: [AtomicU64; RECLAIM_BUSY_KIND_COUNT] =
    [const { AtomicU64::new(0) }; RECLAIM_BUSY_KIND_COUNT];
static TOTAL_RECLAIM_BUSY_LEASES: [AtomicU64; RECLAIM_BUSY_KIND_COUNT] =
    [const { AtomicU64::new(0) }; RECLAIM_BUSY_KIND_COUNT];
static COMPLETED_RECLAIM_BUSY_LEASES: [AtomicU64; RECLAIM_BUSY_KIND_COUNT] =
    [const { AtomicU64::new(0) }; RECLAIM_BUSY_KIND_COUNT];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AllocatorReclaimBusyKind {
    Publication,
    Geodata,
    Subscription,
    ManualLatency,
    GroupHealth,
    Auth,
    LargeControl,
}

impl AllocatorReclaimBusyKind {
    const ALL: [Self; RECLAIM_BUSY_KIND_COUNT] = [
        Self::Publication,
        Self::Geodata,
        Self::Subscription,
        Self::ManualLatency,
        Self::GroupHealth,
        Self::Auth,
        Self::LargeControl,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Publication => 0,
            Self::Geodata => 1,
            Self::Subscription => 2,
            Self::ManualLatency => 3,
            Self::GroupHealth => 4,
            Self::Auth => 5,
            Self::LargeControl => 6,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Publication => "publication",
            Self::Geodata => "geodata",
            Self::Subscription => "subscription",
            Self::ManualLatency => "manual-latency",
            Self::GroupHealth => "group-health",
            Self::Auth => "auth",
            Self::LargeControl => "large-control",
        }
    }
}

#[derive(Debug)]
pub(crate) struct AllocatorReclaimBusyLease {
    kind: AllocatorReclaimBusyKind,
}

impl Drop for AllocatorReclaimBusyLease {
    fn drop(&mut self) {
        let _ = ACTIVE_RECLAIM_BUSY_LEASES[self.kind.index()].fetch_update(
            Ordering::Release,
            Ordering::Relaxed,
            |active| Some(active.saturating_sub(1)),
        );
        COMPLETED_RECLAIM_BUSY_LEASES[self.kind.index()].fetch_add(1, Ordering::Release);
    }
}

pub(crate) fn allocator_reclaim_busy(kind: AllocatorReclaimBusyKind) -> AllocatorReclaimBusyLease {
    ACTIVE_RECLAIM_BUSY_LEASES[kind.index()].fetch_add(1, Ordering::AcqRel);
    TOTAL_RECLAIM_BUSY_LEASES[kind.index()].fetch_add(1, Ordering::Relaxed);
    AllocatorReclaimBusyLease { kind }
}

pub(crate) fn allocator_reclaim_busy_count() -> u64 {
    ACTIVE_RECLAIM_BUSY_LEASES
        .iter()
        .map(|value| value.load(Ordering::Acquire))
        .sum()
}

pub(crate) fn allocator_reclaim_busy_completion_count() -> u64 {
    COMPLETED_RECLAIM_BUSY_LEASES
        .iter()
        .map(|value| value.load(Ordering::Acquire))
        .sum()
}

pub(super) fn allocator_reclaim_busy_snapshot_json() -> Value {
    let active = AllocatorReclaimBusyKind::ALL
        .into_iter()
        .map(|kind| {
            (
                kind.as_str(),
                ACTIVE_RECLAIM_BUSY_LEASES[kind.index()].load(Ordering::Relaxed),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let total = AllocatorReclaimBusyKind::ALL
        .into_iter()
        .map(|kind| {
            (
                kind.as_str(),
                TOTAL_RECLAIM_BUSY_LEASES[kind.index()].load(Ordering::Relaxed),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let completed = AllocatorReclaimBusyKind::ALL
        .into_iter()
        .map(|kind| {
            (
                kind.as_str(),
                COMPLETED_RECLAIM_BUSY_LEASES[kind.index()].load(Ordering::Relaxed),
            )
        })
        .collect::<BTreeMap<_, _>>();
    json!({
        "activeTotal": active.values().sum::<u64>(),
        "activeByClass": active,
        "acquiredByClass": total,
        "completedByClass": completed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_lease_is_released_by_raii() {
        let before = allocator_reclaim_busy_count();
        {
            let _lease = allocator_reclaim_busy(AllocatorReclaimBusyKind::Geodata);
            assert_eq!(allocator_reclaim_busy_count(), before + 1);
        }
        assert_eq!(allocator_reclaim_busy_count(), before);
    }
}
