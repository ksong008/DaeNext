use super::*;

static RESIDENT_DATAPLANE_GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn next_resident_dataplane_generation_id() -> u64 {
    RESIDENT_DATAPLANE_GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug)]
struct ActiveGenerationSlotInner<T> {
    generation: RwLock<Arc<T>>,
    publication: AtomicU64,
    publication_signal: tokio::sync::watch::Sender<u64>,
}

#[derive(Debug)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ActiveGenerationSlot<T> {
    inner: Arc<ActiveGenerationSlotInner<T>>,
}

impl<T> Clone for ActiveGenerationSlot<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> ActiveGenerationSlot<T> {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(generation: Arc<T>) -> Self {
        let (publication_signal, _) = tokio::sync::watch::channel(1);
        Self {
            inner: Arc::new(ActiveGenerationSlotInner {
                generation: RwLock::new(generation),
                publication: AtomicU64::new(1),
                publication_signal,
            }),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn load(&self) -> Arc<T> {
        Arc::clone(
            &self
                .inner
                .generation
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn load_versioned(
        &self,
    ) -> (u64, Arc<T>) {
        let active = self
            .inner
            .generation
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = Arc::clone(&active);
        let publication = self.inner.publication.load(Ordering::Acquire);
        (publication, generation)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn subscribe_publication(
        &self,
    ) -> tokio::sync::watch::Receiver<u64> {
        self.inner.publication_signal.subscribe()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn publish(
        &self,
        generation: Arc<T>,
    ) -> Arc<T> {
        {
            let mut active = self
                .inner
                .generation
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = std::mem::replace(&mut *active, generation);
            let publication = self
                .inner
                .publication
                .fetch_add(1, Ordering::Release)
                .wrapping_add(1);
            self.inner.publication_signal.send_replace(publication);
            previous
        }
    }
}

pub(crate) struct ResidentDataplaneGeneration {
    pub(in crate::production_runtime_owner::resident_dataplane) id: u64,
    pub(in crate::production_runtime_owner::resident_dataplane) reload_generation: u64,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_router: Arc<ResidentTcpRouter>,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_admission:
        tcp::ResidentTcpAdmission,
    pub(in crate::production_runtime_owner::resident_dataplane) tcp_runtime_config:
        ResidentTcpRuntimeConfig,
    pub(in crate::production_runtime_owner::resident_dataplane) dns: Arc<dns::ResidentDnsPlan>,
    pub(in crate::production_runtime_owner::resident_dataplane) udp: udp::ResidentUdpGenerationPlan,
    pub(super) lifecycle: ResidentGenerationLifecycle,
    pub(in crate::production_runtime_owner::resident_dataplane) stop: SharedResidentStopSignal,
    pub(in crate::production_runtime_owner::resident_dataplane) metrics:
        Arc<ResidentDataplaneMetrics>,
    pub(in crate::production_runtime_owner::resident_dataplane) groups:
        Vec<Arc<plan::ResidentProxyGroupPlan>>,
    pub(in crate::production_runtime_owner::resident_dataplane) manual_probe_handle:
        ResidentManualProbeHandle,
    pub(in crate::production_runtime_owner::resident_dataplane) dns_reload_handle:
        dns::ResidentDnsReloadHandle,
    pub(in crate::production_runtime_owner::resident_dataplane) domain_routing_maintenance:
        Option<dns::ResidentDnsDomainRoutingMaintenanceHandle>,
}

impl std::fmt::Debug for ResidentDataplaneGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentDataplaneGeneration")
            .field("id", &self.id)
            .field("reload_generation", &self.reload_generation)
            .field("tcp_runtime_config", &self.tcp_runtime_config)
            .field("group_count", &self.groups.len())
            .finish_non_exhaustive()
    }
}

impl ResidentDataplaneGeneration {
    pub(super) fn admission_is_open(&self) -> bool {
        self.lifecycle.admission_is_open()
    }

    pub(super) fn close_admission(&self) {
        self.lifecycle.close_admission();
    }

    pub(super) fn reopen_admission(&self) -> Result<(), String> {
        self.lifecycle.reopen_admission().map_err(str::to_owned)
    }

    pub(super) fn stop_is_requested(&self) -> bool {
        self.lifecycle.stop_is_requested()
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn request_stop(&self) {
        self.lifecycle.request_stop();
        self.stop.store(true, Ordering::Release);
        if let Some(maintenance) = self.domain_routing_maintenance.as_ref() {
            maintenance.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_generation_slot_pins_loaded_arc_across_publication() {
        let first = Arc::new(String::from("first"));
        let slot = ActiveGenerationSlot::new(Arc::clone(&first));
        let (first_publication, pinned) = slot.load_versioned();
        let retired = slot.publish(Arc::new(String::from("second")));
        let (second_publication, active) = slot.load_versioned();

        assert_eq!(pinned.as_str(), "first");
        assert!(Arc::ptr_eq(&pinned, &first));
        assert!(Arc::ptr_eq(&retired, &first));
        assert_eq!(active.as_str(), "second");
        assert!(second_publication > first_publication);
    }

    #[tokio::test]
    async fn active_generation_slot_notifies_waiters_after_publication() {
        let first = Arc::new(String::from("first"));
        let slot = ActiveGenerationSlot::new(Arc::clone(&first));
        let mut publication = slot.subscribe_publication();
        assert_eq!(*publication.borrow_and_update(), 1);

        let previous = slot.publish(Arc::new(String::from("second")));

        tokio::time::timeout(Duration::from_secs(1), publication.changed())
            .await
            .expect("generation publication must wake waiters")
            .expect("active generation slot must retain its publication sender");
        assert_eq!(*publication.borrow_and_update(), 2);
        assert!(Arc::ptr_eq(&previous, &first));
    }
}
