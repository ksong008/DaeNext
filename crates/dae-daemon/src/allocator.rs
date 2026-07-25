use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use serde_json::{Value, json};

mod reclaim;
use self::reclaim::allocator_reclaim_impl;
mod control_plane;
mod mallctl;
pub(crate) use self::control_plane::{
    allocator_bind_control_plane_thread, allocator_flush_current_thread_cache,
    allocator_purge_control_plane_arena,
};
mod requests;
pub(crate) use self::requests::{
    AllocatorReclaimRequestBatch, allocator_pending_reclaim_reason,
    allocator_pending_reclaim_requests, allocator_request_reclaim, allocator_take_reclaim_requests,
};

#[cfg(not(feature = "allocator-jemalloc"))]
const ALLOCATOR_SYSTEM_TRIM_ENV: &str = "ALLOCATOR_SYSTEM_TRIM";
#[cfg(not(feature = "allocator-jemalloc"))]
const ALLOCATOR_SYSTEM_TRIM_LEGACY_ENV: &str = "DAED_ALLOCATOR_SYSTEM_TRIM";

#[cfg(all(feature = "allocator-system", feature = "allocator-jemalloc"))]
compile_error!("allocator-system cannot be combined with allocator-jemalloc");

#[cfg(all(test, feature = "allocator-jemalloc"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocatorReclaimReason {
    StartupControlBuilt,
    ReloadCompleted,
    ReloadFailedAfterCleanup,
    StopRuntime,
    IdleMemoryPressure,
    ManualLatencyProbe,
    GroupHealthProbe,
    GeodataUpdate,
    RetiredGenerationReleased,
}

impl AllocatorReclaimReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::StartupControlBuilt => "startup_control_built",
            Self::ReloadCompleted => "reload_completed",
            Self::ReloadFailedAfterCleanup => "reload_failed_after_cleanup",
            Self::StopRuntime => "stop_runtime",
            Self::IdleMemoryPressure => "idle_memory_pressure",
            Self::ManualLatencyProbe => "manual_latency_probe",
            Self::GroupHealthProbe => "group_health_probe",
            Self::GeodataUpdate => "geodata_update",
            Self::RetiredGenerationReleased => "retired_generation_released",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AllocatorStatsSnapshot {
    pub allocated: u64,
    pub active: u64,
    pub metadata: u64,
    pub resident: u64,
    pub mapped: u64,
    pub retained: u64,
}

impl AllocatorStatsSnapshot {
    pub fn active_minus_allocated(self) -> u64 {
        self.active.saturating_sub(self.allocated)
    }

    pub fn resident_minus_active(self) -> u64 {
        self.resident.saturating_sub(self.active)
    }

    pub fn rss_anon_minus_allocated(self, anonymous_rss_bytes: u64) -> u64 {
        anonymous_rss_bytes.saturating_sub(self.allocated)
    }

    pub fn idle_reclaim_pressure_bytes(self) -> u64 {
        self.resident_minus_active()
    }

    fn from_bytes(stats: BTreeMap<&'static str, u64>) -> Option<Self> {
        Some(Self {
            allocated: *stats.get("allocated")?,
            active: *stats.get("active")?,
            metadata: *stats.get("metadata")?,
            resident: *stats.get("resident")?,
            mapped: *stats.get("mapped")?,
            retained: *stats.get("retained")?,
        })
    }

    fn bytes_json(self) -> BTreeMap<&'static str, Value> {
        [
            ("allocated", self.allocated),
            ("active", self.active),
            ("metadata", self.metadata),
            ("resident", self.resident),
            ("mapped", self.mapped),
            ("retained", self.retained),
        ]
        .into_iter()
        .map(|(key, value)| (key, json!(value.to_string())))
        .collect()
    }
}

#[derive(Clone, Debug)]
struct LastAllocatorReclaim {
    reason: &'static str,
    profile: &'static str,
    status: String,
    detail: Value,
}

static STARTUP_CONTROL_BUILT_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static RELOAD_COMPLETED_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static RELOAD_FAILED_AFTER_CLEANUP_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static STOP_RUNTIME_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static IDLE_MEMORY_PRESSURE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static MANUAL_LATENCY_PROBE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static GROUP_HEALTH_PROBE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static GEODATA_UPDATE_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static RETIRED_GENERATION_RELEASED_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static TOTAL_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static EXECUTED_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static COALESCED_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static LAST_RECLAIM: OnceLock<Mutex<Option<LastAllocatorReclaim>>> = OnceLock::new();

pub fn allocator_profile() -> &'static str {
    if cfg!(feature = "allocator-jemalloc") {
        "jemalloc"
    } else {
        "system"
    }
}

pub fn allocator_stats_json_from(snapshot: Option<&AllocatorStatsSnapshot>) -> Value {
    match snapshot {
        Some(stats) => json!({
            "available": true,
            "profile": allocator_profile(),
            "bytes": stats.bytes_json(),
        }),
        None => json!({
            "available": false,
            "profile": allocator_profile(),
        }),
    }
}

pub fn allocator_stats_snapshot() -> Option<AllocatorStatsSnapshot> {
    allocator_stats_bytes().and_then(AllocatorStatsSnapshot::from_bytes)
}

pub fn allocator_derived_stats_json_from(
    snapshot: Option<&AllocatorStatsSnapshot>,
    anonymous_rss_bytes: u64,
) -> Value {
    match snapshot {
        Some(stats) => json!({
            "available": true,
            "profile": allocator_profile(),
            "idleReclaimPressureSource": "jemalloc-resident-minus-active",
            "retainedSemantics": "virtual-address-space-not-physical-rss",
            "bytes": {
                "activeMinusAllocated": stats.active_minus_allocated().to_string(),
                "residentMinusActive": stats.resident_minus_active().to_string(),
                "retained": stats.retained.to_string(),
                "rssAnonMinusAllocated": stats.rss_anon_minus_allocated(anonymous_rss_bytes).to_string(),
                "idleReclaimPressure": stats.idle_reclaim_pressure_bytes().to_string(),
            },
        }),
        None => json!({
            "available": false,
            "profile": allocator_profile(),
        }),
    }
}

pub fn allocator_reclaim(reason: AllocatorReclaimReason) -> Value {
    increment_reason_counter(reason);
    TOTAL_RECLAIMS.fetch_add(1, Ordering::Relaxed);

    let stats_before = allocator_stats_snapshot();
    let started_at = Instant::now();
    let (status, detail) = allocator_reclaim_impl();
    if status == "coalesced" {
        COALESCED_RECLAIMS.fetch_add(1, Ordering::Relaxed);
    } else {
        EXECUTED_RECLAIMS.fetch_add(1, Ordering::Relaxed);
    }
    let elapsed = started_at.elapsed();
    let stats_after = allocator_stats_snapshot();
    let detail = allocator_reclaim_detail(detail, stats_before, stats_after, elapsed);
    let report = LastAllocatorReclaim {
        reason: reason.as_str(),
        profile: allocator_profile(),
        status: status.to_owned(),
        detail,
    };
    if let Ok(mut guard) = LAST_RECLAIM.get_or_init(|| Mutex::new(None)).lock() {
        *guard = Some(report.clone());
    }
    last_allocator_reclaim_json(&report)
}

fn allocator_reclaim_detail(
    detail: Value,
    stats_before: Option<AllocatorStatsSnapshot>,
    stats_after: Option<AllocatorStatsSnapshot>,
    elapsed: std::time::Duration,
) -> Value {
    let mut detail = match detail {
        Value::Object(detail) => detail,
        detail => serde_json::Map::from_iter([("backendDetail".to_owned(), detail)]),
    };
    detail.insert(
        "elapsedMicros".to_owned(),
        json!(elapsed.as_micros().to_string()),
    );
    detail.insert(
        "statsBefore".to_owned(),
        stats_before
            .map(|stats| json!(stats.bytes_json()))
            .unwrap_or(Value::Null),
    );
    detail.insert(
        "statsAfter".to_owned(),
        stats_after
            .map(|stats| json!(stats.bytes_json()))
            .unwrap_or(Value::Null),
    );
    detail.insert(
        "physicalResidentReleasedBytes".to_owned(),
        json!(
            stats_before
                .zip(stats_after)
                .map(|(before, after)| before.resident.saturating_sub(after.resident).to_string())
        ),
    );
    Value::Object(detail)
}

pub fn allocator_reclaim_snapshot_json() -> Value {
    let last = LAST_RECLAIM
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|guard| guard.clone());
    json!({
        "profile": allocator_profile(),
        "total": TOTAL_RECLAIMS.load(Ordering::Relaxed),
        "requestedTotal": TOTAL_RECLAIMS.load(Ordering::Relaxed),
        "executedTotal": EXECUTED_RECLAIMS.load(Ordering::Relaxed),
        "coalescedTotal": COALESCED_RECLAIMS.load(Ordering::Relaxed),
        "deferred": requests::allocator_reclaim_request_snapshot_json(),
        "reasons": {
            "startup_control_built": STARTUP_CONTROL_BUILT_RECLAIMS.load(Ordering::Relaxed),
            "reload_completed": RELOAD_COMPLETED_RECLAIMS.load(Ordering::Relaxed),
            "reload_failed_after_cleanup": RELOAD_FAILED_AFTER_CLEANUP_RECLAIMS.load(Ordering::Relaxed),
            "stop_runtime": STOP_RUNTIME_RECLAIMS.load(Ordering::Relaxed),
            "idle_memory_pressure": IDLE_MEMORY_PRESSURE_RECLAIMS.load(Ordering::Relaxed),
            "manual_latency_probe": MANUAL_LATENCY_PROBE_RECLAIMS.load(Ordering::Relaxed),
            "group_health_probe": GROUP_HEALTH_PROBE_RECLAIMS.load(Ordering::Relaxed),
            "geodata_update": GEODATA_UPDATE_RECLAIMS.load(Ordering::Relaxed),
            "retired_generation_released": RETIRED_GENERATION_RELEASED_RECLAIMS.load(Ordering::Relaxed),
        },
        "last": last.as_ref().map(last_allocator_reclaim_json),
    })
}

fn increment_reason_counter(reason: AllocatorReclaimReason) {
    match reason {
        AllocatorReclaimReason::StartupControlBuilt => {
            STARTUP_CONTROL_BUILT_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::ReloadCompleted => {
            RELOAD_COMPLETED_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::ReloadFailedAfterCleanup => {
            RELOAD_FAILED_AFTER_CLEANUP_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::StopRuntime => {
            STOP_RUNTIME_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::IdleMemoryPressure => {
            IDLE_MEMORY_PRESSURE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::ManualLatencyProbe => {
            MANUAL_LATENCY_PROBE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::GroupHealthProbe => {
            GROUP_HEALTH_PROBE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::GeodataUpdate => {
            GEODATA_UPDATE_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
        AllocatorReclaimReason::RetiredGenerationReleased => {
            RETIRED_GENERATION_RELEASED_RECLAIMS.fetch_add(1, Ordering::Relaxed);
        }
    };
}

fn last_allocator_reclaim_json(reclaim: &LastAllocatorReclaim) -> Value {
    json!({
        "reason": reclaim.reason,
        "profile": reclaim.profile,
        "status": reclaim.status,
        "detail": reclaim.detail,
    })
}

#[cfg(feature = "allocator-jemalloc")]
fn allocator_stats_bytes() -> Option<BTreeMap<&'static str, u64>> {
    use tikv_jemalloc_ctl::{epoch, stats};

    let _ = epoch::advance();
    let mut values = BTreeMap::new();
    values.insert("allocated", stats::allocated::read().ok()? as u64);
    values.insert("active", stats::active::read().ok()? as u64);
    values.insert("metadata", stats::metadata::read().ok()? as u64);
    values.insert("resident", stats::resident::read().ok()? as u64);
    values.insert("mapped", stats::mapped::read().ok()? as u64);
    values.insert("retained", stats::retained::read().ok()? as u64);
    Some(values)
}

#[cfg(not(feature = "allocator-jemalloc"))]
fn allocator_stats_bytes() -> Option<BTreeMap<&'static str, u64>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_reclaim_pressure_tracks_physical_resident_slack_not_virtual_retained_extents() {
        let stats = AllocatorStatsSnapshot {
            allocated: 36 * 1024 * 1024,
            active: 40 * 1024 * 1024,
            metadata: 8 * 1024 * 1024,
            resident: 52 * 1024 * 1024,
            mapped: 72 * 1024 * 1024,
            retained: 220 * 1024 * 1024,
        };

        assert_eq!(stats.idle_reclaim_pressure_bytes(), 12 * 1024 * 1024);
    }
}
