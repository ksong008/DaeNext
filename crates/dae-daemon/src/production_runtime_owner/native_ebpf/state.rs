use super::*;
impl NativeEbpfRuntimeState {
    pub(in crate::production_runtime_owner) fn new() -> Self {
        Self::default()
    }

    pub(in crate::production_runtime_owner) fn peer_attached(&self) -> bool {
        self.peer_attached
    }

    pub(in crate::production_runtime_owner) fn host_attached(&self) -> bool {
        self.host_attached
    }

    pub(in crate::production_runtime_owner) fn cgroup_attached(&self) -> bool {
        self.cgroup_attached
    }

    pub(in crate::production_runtime_owner) fn lan_attached(&self) -> bool {
        self.lan_attached
    }

    pub(in crate::production_runtime_owner) fn loaded_map_id(&self, name: &str) -> Option<u32> {
        #[cfg(feature = "native-ebpf")]
        {
            self.loaded_map_ids.get(name).copied().or_else(|| {
                let truncated = truncated_bpf_name(name);
                (truncated != name)
                    .then(|| self.loaded_map_ids.get(&truncated).copied())
                    .flatten()
            })
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            let _ = name;
            None
        }
    }

    pub(in crate::production_runtime_owner) fn pin_root(&self) -> Option<&Path> {
        #[cfg(feature = "native-ebpf")]
        {
            self.pin_root.as_deref()
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            let _ = self;
            None
        }
    }

    pub(in crate::production_runtime_owner) fn set_load_input(
        &mut self,
        input: Option<NativeEbpfLoadInput>,
    ) {
        #[cfg(feature = "native-ebpf")]
        {
            self.load_input = input;
        }
        #[cfg(not(feature = "native-ebpf"))]
        {
            let _ = input;
        }
    }

    pub(in crate::production_runtime_owner) fn pname_evidence(
        &self,
        pname_rules_required: bool,
        native_param_image: &Value,
    ) -> Value {
        #[cfg(feature = "native-ebpf")]
        let mut value = self
            .pname_report
            .clone()
            .unwrap_or_else(|| current_comm_pname_report("not_loaded"));
        #[cfg(not(feature = "native-ebpf"))]
        let mut value = current_comm_pname_report("native_ebpf_not_compiled");
        if let Value::Object(map) = &mut value {
            map.insert("pnameRulesRequired".to_owned(), json!(pname_rules_required));
            map.insert(
                "paramHasBpfGetCurrentTask".to_owned(),
                native_param_image
                    .pointer("/param/has_bpf_get_current_task")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
        value
    }

    pub(in crate::production_runtime_owner) fn runtime_metrics(&self) -> Value {
        #[cfg(feature = "native-ebpf")]
        {
            let profile = self.load_input.as_ref().map(|input| &input.map_profile);
            let udp_state_capacity = self.loaded.as_ref().and_then(|loaded| {
                loaded
                    .report
                    .loaded_map_specs
                    .iter()
                    .find(|spec| spec.name == "udp_conn_state_map")
                    .map(|spec| spec.max_entries)
            });
            let metrics = self.loaded.as_ref().map(|loaded| {
                dae_ebpf_support::read_aya_udp_state_metrics(loaded).map(|metrics| {
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
            match metrics {
                Some(Ok(metrics)) => json!({
                    "status": "pass",
                    "mapProfile": profile.map(|selection| selection.profile.name()),
                    "mapProfileSource": profile.map(|selection| selection.source),
                    "udpStateCapacity": udp_state_capacity,
                    "udpStateIdleTimeoutNs": profile.map(|selection| selection.profile.udp_state_idle_timeout_ns().to_string()),
                    "udpStateSaturationPolicy": "fail-closed",
                    "udpStateMetrics": metrics,
                }),
                Some(Err(error)) => json!({
                    "status": "error",
                    "error": error,
                    "mapProfile": profile.map(|selection| selection.profile.name()),
                    "udpStateCapacity": udp_state_capacity,
                    "udpStateSaturationPolicy": "fail-closed",
                }),
                None => json!({
                    "status": "unavailable",
                    "mapProfile": profile.map(|selection| selection.profile.name()),
                    "udpStateSaturationPolicy": "fail-closed",
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

    pub(in crate::production_runtime_owner) fn reset(&mut self) {
        #[cfg(feature = "native-ebpf")]
        {
            self.loaded.take();
            self.loaded_map_ids.clear();
            self.load_input.take();
            self.pname_report.take();
            if let Some(pin_root) = self.pin_root.take() {
                let _ = std::fs::remove_dir_all(pin_root);
            }
        }
        self.peer_attached = false;
        self.lan_attached = false;
        self.host_attached = false;
        self.cgroup_attached = false;
    }
}

pub(super) fn current_comm_pname_report(reason: &'static str) -> Value {
    json!({
        "source": "current_comm",
        "fallbackSource": "bpf_get_current_comm",
        "semantics": "non_core_task_comm",
        "coreEnabled": false,
        "nonCoreTaskCommEnabled": true,
        "currentTaskArgvEnabled": false,
        "officialArgvSemanticsImplemented": false,
        "coreStatus": reason,
    })
}
