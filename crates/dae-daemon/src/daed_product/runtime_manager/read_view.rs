use super::*;

enum ProductRuntimeInstanceReadView {
    Resident(Arc<ResidentProductionRuntimeReadHandle>),
    Fake {
        started_at: String,
        tproxy_port: u16,
    },
    Stopped {
        fake_runtime_enabled: bool,
    },
}

pub(super) struct ProductRuntimeReadSnapshot {
    runtime: ProductRuntimeInstanceReadView,
    traffic_carry: RuntimeTrafficCarry,
    last_transition_at: Option<String>,
    runtime_started_at: Option<String>,
    last_error: Option<String>,
    reload_count: u64,
    stop_count: u64,
    last_report: Option<Arc<Value>>,
    cleanup: RuntimeCleanupState,
    apply: RuntimeApplyState,
    coordinator: Value,
    active_generation: Option<String>,
    pending_process_transition: Option<Value>,
}

impl ProductRuntimeReadSnapshot {
    pub(super) fn capture(
        state: &ProductRuntimeState,
        coordinator: Value,
        fake_runtime_enabled: bool,
    ) -> Self {
        let runtime = match state.runtime.as_ref() {
            Some(ProductRuntimeInstance::Resident(runtime)) => {
                ProductRuntimeInstanceReadView::Resident(runtime.read_handle())
            }
            Some(ProductRuntimeInstance::Fake(fake)) => ProductRuntimeInstanceReadView::Fake {
                started_at: fake.started_at.clone(),
                tproxy_port: fake.tproxy_port,
            },
            None => ProductRuntimeInstanceReadView::Stopped {
                fake_runtime_enabled,
            },
        };
        Self {
            runtime,
            traffic_carry: state.traffic_carry,
            last_transition_at: state.last_transition_at.clone(),
            runtime_started_at: state.runtime_started_at.clone(),
            last_error: state.last_error.clone(),
            reload_count: state.reload_count,
            stop_count: state.stop_count,
            last_report: state.last_report.clone(),
            cleanup: state.cleanup.clone(),
            apply: state.apply.clone(),
            coordinator,
            active_generation: state.active_generation.clone(),
            pending_process_transition: state.pending_process_transition.clone(),
        }
    }

    pub(super) fn render(self) -> Value {
        match self.runtime {
            ProductRuntimeInstanceReadView::Resident(runtime) => {
                let mut summary = runtime.product_state_summary();
                self.traffic_carry.apply_to_runtime_summary(&mut summary);
                if let Value::Object(map) = &mut summary {
                    map.insert(
                        "lastTransitionAt".to_owned(),
                        json!(self.last_transition_at),
                    );
                    map.insert("startedAt".to_owned(), json!(self.runtime_started_at));
                    map.insert("lastError".to_owned(), json!(self.last_error));
                    map.insert("reloadCount".to_owned(), json!(self.reload_count));
                    map.insert("stopCount".to_owned(), json!(self.stop_count));
                    map.insert("lastReport".to_owned(), json!(self.last_report.as_deref()));
                    map.insert("cleanup".to_owned(), self.cleanup.summary());
                    map.insert("apply".to_owned(), self.apply.summary());
                    map.insert("applyCoordinator".to_owned(), self.coordinator);
                    map.insert("activeGeneration".to_owned(), json!(self.active_generation));
                    map.insert(
                        "pendingProcessTransition".to_owned(),
                        json!(self.pending_process_transition),
                    );
                }
                summary
            }
            ProductRuntimeInstanceReadView::Fake {
                started_at,
                tproxy_port,
            } => json!({
                "running": true,
                "state": "running",
                "attachBackend": "fake-resident-runtime-test-only",
                "netnsLinkMode": "fake-test-only",
                "fakeRuntime": true,
                "startedAt": self.runtime_started_at.unwrap_or(started_at),
                "tproxyPort": tproxy_port,
                "lastTransitionAt": self.last_transition_at,
                "lastError": self.last_error,
                "reloadCount": self.reload_count,
                "stopCount": self.stop_count,
                "lastReport": self.last_report.as_deref(),
                "cleanup": self.cleanup.summary(),
                "apply": self.apply.summary(),
                "applyCoordinator": self.coordinator,
                "activeGeneration": self.active_generation,
                "pendingProcessTransition": self.pending_process_transition,
            }),
            ProductRuntimeInstanceReadView::Stopped {
                fake_runtime_enabled,
            } => json!({
                "running": false,
                "state": if self.cleanup.running {
                    "stopping"
                } else if self.last_error.is_some() {
                    "error"
                } else {
                    "stopped"
                },
                "attachBackend": Value::Null,
                "netnsLinkMode": Value::Null,
                "fakeRuntime": fake_runtime_enabled,
                "startedAt": Value::Null,
                "lastTransitionAt": self.last_transition_at,
                "lastError": self.last_error,
                "reloadCount": self.reload_count,
                "stopCount": self.stop_count,
                "lastReport": self.last_report.as_deref(),
                "cleanup": self.cleanup.summary(),
                "apply": self.apply.summary(),
                "applyCoordinator": self.coordinator,
                "activeGeneration": self.active_generation,
                "pendingProcessTransition": self.pending_process_transition,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_snapshot_shares_detailed_reports_until_render() {
        let report = Arc::new(json!({
            "status": "pass",
            "details": vec!["entry"; 256],
        }));
        let state = ProductRuntimeState {
            last_report: Some(Arc::clone(&report)),
            ..ProductRuntimeState::default()
        };
        let snapshot = ProductRuntimeReadSnapshot::capture(&state, json!({}), false);
        assert!(Arc::ptr_eq(snapshot.last_report.as_ref().unwrap(), &report));
        assert_eq!(snapshot.render()["lastReport"], report.as_ref().clone());
    }

    #[test]
    fn detailed_summary_render_does_not_hold_manager_state_lock() {
        let manager = Arc::new(ProductRuntimeManager::new());
        manager.inner.lock().unwrap().runtime =
            Some(ProductRuntimeInstance::Fake(FakeProductRuntime {
                started_at: "captured-start".to_owned(),
                tproxy_port: 1234,
            }));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        *manager.summary_render_barrier.lock().unwrap() = Some(Arc::clone(&barrier));

        let summary_manager = Arc::clone(&manager);
        let summary_thread = std::thread::spawn(move || summary_manager.summary());
        barrier.wait();
        assert!(manager.inner.try_lock().is_ok());
        barrier.wait();

        let summary = summary_thread.join().unwrap();
        assert_eq!(summary["running"], json!(true));
        assert_eq!(summary["tproxyPort"], json!(1234));
    }
}
