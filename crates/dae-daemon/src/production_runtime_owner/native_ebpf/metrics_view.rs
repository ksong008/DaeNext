use super::*;

impl NativeEbpfRuntimeReadHandle {
    pub(in crate::production_runtime_owner) fn runtime_metrics(&self) -> Value {
        #[cfg(feature = "native-ebpf")]
        {
            let metrics = self.udp_state_metrics_map_id.map(|map_id| {
                dae_ebpf_support::read_aya_udp_state_metrics_by_id(map_id).map(|metrics| {
                    json!({
                        "stateCreatedTotal": metrics.state_created_total,
                        "stateRefreshTotal": metrics.state_refresh_total,
                        "insertFailureTotal": metrics.insert_failure_total,
                        "postInsertLookupFailureTotal": metrics.post_insert_lookup_failure_total,
                        "timerInitFailureTotal": metrics.timer_init_failure_total,
                        "timerCallbackFailureTotal": metrics.timer_callback_failure_total,
                        "timerStartFailureTotal": metrics.timer_start_failure_total,
                    })
                })
            });
            // tproxy redirect failure counters (sk_assign / skb_store_bytes).
            // Optional: the map exists on the current object, but reading is
            // best-effort so a transient fd failure does not fail the whole
            // metrics report.
            let tproxy_metrics = self.tproxy_metrics_map_id.map(|map_id| {
                match dae_ebpf_support::read_aya_tproxy_metrics_by_id(map_id) {
                    Ok(metrics) => json!({
                        "skAssignFailureTotal": metrics.sk_assign_failure_total,
                        "redirectPrepStoreFailureTotal": metrics.redirect_prep_store_failure_total,
                        "redirectRestoreStoreFailureTotal": metrics.redirect_restore_store_failure_total,
                    }),
                    Err(error) => json!({
                        "status": "error",
                        "error": error,
                    }),
                }
            });
            match metrics {
                Some(Ok(metrics)) => json!({
                    "status": "pass",
                    "mapProfile": self.map_profile.map(RuntimeMapProfile::name),
                    "mapProfileSource": self.map_profile_source,
                    "udpStateCapacity": self.udp_state_capacity,
                    "udpStateIdleTimeoutNs": self.map_profile.map(|profile| profile.udp_state_idle_timeout_ns().to_string()),
                    "udpStateSaturationPolicy": "fail-closed",
                    "redirectTrackAbiVersion": REDIRECT_TRACK_ABI_VERSION,
                    "redirectTrackGeneration": self.redirect_generation.map(|generation| generation.to_string()),
                    "redirectTrackMigration": "fresh-unpinned-map-per-runtime",
                    "udpStateMetrics": metrics,
                    "tproxyMetrics": tproxy_metrics,
                }),
                Some(Err(error)) => json!({
                    "status": "error",
                    "error": error,
                    "mapProfile": self.map_profile.map(RuntimeMapProfile::name),
                    "udpStateCapacity": self.udp_state_capacity,
                    "udpStateSaturationPolicy": "fail-closed",
                    "redirectTrackAbiVersion": REDIRECT_TRACK_ABI_VERSION,
                    "redirectTrackGeneration": self.redirect_generation.map(|generation| generation.to_string()),
                    "tproxyMetrics": tproxy_metrics,
                }),
                None => json!({
                    "status": "unavailable",
                    "mapProfile": self.map_profile.map(RuntimeMapProfile::name),
                    "udpStateSaturationPolicy": "fail-closed",
                    "redirectTrackAbiVersion": REDIRECT_TRACK_ABI_VERSION,
                    "redirectTrackGeneration": self.redirect_generation.map(|generation| generation.to_string()),
                    "tproxyMetrics": tproxy_metrics,
                }),
            }
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            let _ = self;
            json!({
                "status": "unavailable",
                "reason": "native eBPF support is not compiled",
            })
        }
    }
}
