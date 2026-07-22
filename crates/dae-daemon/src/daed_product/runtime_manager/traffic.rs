use super::summary::apply_runtime_traffic_metric_carry;
use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::daed_product) struct RuntimeTrafficCarry {
    pub(in crate::daed_product) upload_total: u64,
    pub(in crate::daed_product) download_total: u64,
}

impl RuntimeTrafficCarry {
    pub(in crate::daed_product) fn absorb_runtime(self, runtime: &ProductRuntimeInstance) -> Self {
        let Some(counters) = runtime_traffic_counters(runtime) else {
            return self;
        };
        self.absorb_counters(counters)
    }

    pub(in crate::daed_product) fn absorb_counters(
        self,
        counters: ResidentTrafficCounters,
    ) -> Self {
        Self {
            upload_total: self.upload_total.saturating_add(counters.upload_total),
            download_total: self.download_total.saturating_add(counters.download_total),
        }
    }

    pub(in crate::daed_product) fn apply_to_runtime_summary(self, summary: &mut Value) {
        let Some(metrics) = summary.pointer_mut("/residentDataplane/metrics") else {
            return;
        };
        self.apply_to_metrics(metrics);
    }

    pub(in crate::daed_product) fn apply_to_metrics(self, metrics: &mut Value) {
        if self.upload_total == 0 && self.download_total == 0 {
            return;
        }
        apply_runtime_traffic_metric_carry(metrics, "uploadTotal", self.upload_total);
        apply_runtime_traffic_metric_carry(metrics, "downloadTotal", self.download_total);
    }

    pub(in crate::daed_product) fn apply_to_counters(
        self,
        counters: ResidentTrafficCounters,
    ) -> ResidentTrafficCounters {
        ResidentTrafficCounters {
            upload_total: counters.upload_total.saturating_add(self.upload_total),
            download_total: counters.download_total.saturating_add(self.download_total),
            ..counters
        }
    }
}

impl ProductRuntimeManager {
    pub(in crate::daed_product) fn resident_traffic_counters(
        &self,
    ) -> Option<ResidentTrafficCounters> {
        let inner = self.inner.lock().ok()?;
        let counters = runtime_traffic_counters(inner.runtime.as_ref()?)?;
        Some(inner.traffic_carry.apply_to_counters(counters))
    }
}

fn runtime_traffic_counters(runtime: &ProductRuntimeInstance) -> Option<ResidentTrafficCounters> {
    match runtime {
        ProductRuntimeInstance::Resident(runtime) => runtime.resident_dataplane_traffic_counters(),
        ProductRuntimeInstance::Fake(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carry_applies_only_to_monotonic_totals() {
        let counters = ResidentTrafficCounters {
            upload_total: 25,
            download_total: 50,
            active_tcp_connections: 3,
            active_udp_sessions: 2,
        };
        let carried = RuntimeTrafficCarry {
            upload_total: 500,
            download_total: 700,
        }
        .apply_to_counters(counters);

        assert_eq!(carried.upload_total, 525);
        assert_eq!(carried.download_total, 750);
        assert_eq!(carried.active_tcp_connections, 3);
        assert_eq!(carried.active_udp_sessions, 2);
    }

    #[test]
    fn carry_saturates_without_changing_active_gauges() {
        let counters = ResidentTrafficCounters {
            upload_total: u64::MAX - 1,
            download_total: u64::MAX,
            active_tcp_connections: 7,
            active_udp_sessions: 8,
        };
        let carried = RuntimeTrafficCarry {
            upload_total: 2,
            download_total: 1,
        }
        .apply_to_counters(counters);

        assert_eq!(carried.upload_total, u64::MAX);
        assert_eq!(carried.download_total, u64::MAX);
        assert_eq!(carried.active_tcp_connections, 7);
        assert_eq!(carried.active_udp_sessions, 8);
    }
}
