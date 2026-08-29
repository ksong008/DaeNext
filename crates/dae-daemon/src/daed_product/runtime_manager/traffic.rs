use super::*;

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn resident_traffic_read(&self) -> RuntimeTrafficRead {
        let Ok(inner) = self.inner().lock() else {
            return RuntimeTrafficRead {
                epoch: u64::MAX,
                counters: ResidentTrafficCounters::default(),
                availability: RuntimeTrafficAvailability::TemporarilyUnavailable,
            };
        };
        let epoch = inner.allocator_publication_id;
        let Some(runtime) = inner.runtime.as_ref() else {
            return RuntimeTrafficRead {
                epoch,
                counters: ResidentTrafficCounters::default(),
                availability: if inner.cleanup.running || inner.config.is_some() {
                    RuntimeTrafficAvailability::TemporarilyUnavailable
                } else {
                    RuntimeTrafficAvailability::RuntimeStopped
                },
            };
        };
        let Some(counters) = runtime_traffic_counters(runtime) else {
            return RuntimeTrafficRead {
                epoch,
                counters: ResidentTrafficCounters::default(),
                availability: RuntimeTrafficAvailability::TemporarilyUnavailable,
            };
        };
        RuntimeTrafficRead {
            epoch,
            counters: inner.traffic_carry.apply_to_counters(counters),
            availability: RuntimeTrafficAvailability::Active,
        }
    }

    pub(in crate::daed_product) fn resident_traffic_counters(
        &self,
    ) -> Option<ResidentTrafficCounters> {
        let read = self.resident_traffic_read();
        (read.availability == RuntimeTrafficAvailability::Active).then_some(read.counters)
    }
}

pub(super) fn runtime_traffic_counters(
    runtime: &ProductRuntimeInstance,
) -> Option<ResidentTrafficCounters> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.resident_dataplane_traffic_counters(),
        ProductRuntimeInstance::Fake(_) => None,
    }
}
