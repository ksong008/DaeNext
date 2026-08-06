use super::*;

pub(super) struct ProductGeodataUpdateMetrics {
    configured_workers: u64,
    queue_capacity: u64,
    queue_depth: AtomicU64,
    active_workers: AtomicU64,
    active_geosite: AtomicU64,
    active_geoip: AtomicU64,
    next_generation: AtomicU64,
    geosite_generation: AtomicU64,
    geoip_generation: AtomicU64,
    geosite_phase: AtomicU64,
    geoip_phase: AtomicU64,
    submitted_total: AtomicU64,
    completed_total: AtomicU64,
    rejected_same_kind_total: AtomicU64,
    rejected_capacity_total: AtomicU64,
    rejected_unavailable_total: AtomicU64,
    worker_panic_total: AtomicU64,
    workers_joined_total: AtomicU64,
    workers_detached_total: AtomicU64,
}

impl ProductGeodataUpdateMetrics {
    pub(super) fn new(config: ProductGeodataUpdateRuntimeConfig) -> Self {
        Self {
            configured_workers: config.worker_count as u64,
            queue_capacity: config.queue_capacity as u64,
            queue_depth: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            active_geosite: AtomicU64::new(0),
            active_geoip: AtomicU64::new(0),
            next_generation: AtomicU64::new(0),
            geosite_generation: AtomicU64::new(0),
            geoip_generation: AtomicU64::new(0),
            geosite_phase: AtomicU64::new(0),
            geoip_phase: AtomicU64::new(0),
            submitted_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            rejected_same_kind_total: AtomicU64::new(0),
            rejected_capacity_total: AtomicU64::new(0),
            rejected_unavailable_total: AtomicU64::new(0),
            worker_panic_total: AtomicU64::new(0),
            workers_joined_total: AtomicU64::new(0),
            workers_detached_total: AtomicU64::new(0),
        }
    }

    pub(super) fn submitted(&self, kind: GeodataKind) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.generation(kind).store(generation, Ordering::Relaxed);
        self.phase(kind).store(1, Ordering::Relaxed);
        self.submitted_total.fetch_add(1, Ordering::Relaxed);
        generation
    }

    pub(super) fn enqueued(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn dequeued(&self, kind: GeodataKind, generation: u64) {
        decrement_saturating(&self.queue_depth);
        self.active_workers.fetch_add(1, Ordering::Relaxed);
        self.active_kind(kind).store(1, Ordering::Relaxed);
        self.generation(kind).store(generation, Ordering::Relaxed);
        self.phase(kind).store(2, Ordering::Relaxed);
    }

    pub(super) fn dequeue_rollback(&self, kind: GeodataKind, generation: u64) {
        decrement_saturating(&self.queue_depth);
        if self.generation(kind).load(Ordering::Relaxed) == generation {
            self.phase(kind).store(0, Ordering::Relaxed);
        }
    }

    pub(super) fn completed(&self, kind: GeodataKind, generation: u64) {
        decrement_saturating(&self.active_workers);
        self.active_kind(kind).store(0, Ordering::Relaxed);
        if self.generation(kind).load(Ordering::Relaxed) == generation {
            self.phase(kind).store(0, Ordering::Relaxed);
        }
        self.completed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn rejected_same_kind(&self) {
        self.rejected_same_kind_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn rejected_capacity(&self) {
        self.rejected_capacity_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn rejected_unavailable(&self) {
        self.rejected_unavailable_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn worker_panicked(&self) {
        self.worker_panic_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn worker_joined(&self) {
        self.workers_joined_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn worker_detached(&self) {
        self.workers_detached_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self, config: ProductGeodataUpdateRuntimeConfig) -> Value {
        json!({
            "profile": config.profile.name(),
            "configuredWorkers": self.configured_workers,
            "queueCapacity": self.queue_capacity,
            "workerStackBytes": config.worker_stack_bytes,
            "preparationMode": config.preparation_mode.name(),
            "queueDepth": self.queue_depth.load(Ordering::Relaxed),
            "activeWorkers": self.active_workers.load(Ordering::Relaxed),
            "active": {
                "geosite": self.active_geosite.load(Ordering::Relaxed) != 0,
                "geoip": self.active_geoip.load(Ordering::Relaxed) != 0,
            },
            "jobs": {
                "geosite": {
                    "generation": self.geosite_generation.load(Ordering::Relaxed),
                    "phase": phase_name(self.geosite_phase.load(Ordering::Relaxed)),
                },
                "geoip": {
                    "generation": self.geoip_generation.load(Ordering::Relaxed),
                    "phase": phase_name(self.geoip_phase.load(Ordering::Relaxed)),
                },
            },
            "submittedTotal": self.submitted_total.load(Ordering::Relaxed),
            "completedTotal": self.completed_total.load(Ordering::Relaxed),
            "rejectedSameKindTotal": self.rejected_same_kind_total.load(Ordering::Relaxed),
            "rejectedCapacityTotal": self.rejected_capacity_total.load(Ordering::Relaxed),
            "rejectedUnavailableTotal": self.rejected_unavailable_total.load(Ordering::Relaxed),
            "workerPanicTotal": self.worker_panic_total.load(Ordering::Relaxed),
            "workersJoinedTotal": self.workers_joined_total.load(Ordering::Relaxed),
            "workersDetachedTotal": self.workers_detached_total.load(Ordering::Relaxed),
        })
    }

    fn active_kind(&self, kind: GeodataKind) -> &AtomicU64 {
        match kind {
            GeodataKind::Geosite => &self.active_geosite,
            GeodataKind::Geoip => &self.active_geoip,
        }
    }

    fn generation(&self, kind: GeodataKind) -> &AtomicU64 {
        match kind {
            GeodataKind::Geosite => &self.geosite_generation,
            GeodataKind::Geoip => &self.geoip_generation,
        }
    }

    fn phase(&self, kind: GeodataKind) -> &AtomicU64 {
        match kind {
            GeodataKind::Geosite => &self.geosite_phase,
            GeodataKind::Geoip => &self.geoip_phase,
        }
    }
}

fn decrement_saturating(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

fn phase_name(phase: u64) -> &'static str {
    match phase {
        1 => "queued",
        2 => "running",
        _ => "idle",
    }
}
