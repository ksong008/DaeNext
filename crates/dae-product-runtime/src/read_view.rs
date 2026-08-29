use std::sync::Arc;

use serde_json::{Value, json};

use crate::{ProductRuntimeState, RuntimeApplyState, RuntimeCleanupState, RuntimeTrafficCarry};

pub enum RuntimeReadBackend {
    Resident(Box<dyn FnOnce() -> Value + Send>),
    Fake {
        started_at: String,
        tproxy_port: u16,
    },
    Stopped {
        fake_runtime_enabled: bool,
    },
}

enum ProductRuntimeInstanceReadView {
    Resident(Box<dyn FnOnce() -> Value + Send>),
    Fake {
        started_at: String,
        tproxy_port: u16,
    },
    Stopped {
        fake_runtime_enabled: bool,
    },
}

pub struct ProductRuntimeReadSnapshot {
    runtime: ProductRuntimeInstanceReadView,
    traffic_carry: RuntimeTrafficCarry,
    last_transition_at: Option<String>,
    runtime_started_at: Option<String>,
    last_error: Option<String>,
    reload_count: u64,
    allocator_publication_id: u64,
    stop_count: u64,
    last_report: Option<Arc<Value>>,
    cleanup: RuntimeCleanupState,
    apply: RuntimeApplyState,
    coordinator: Value,
    active_generation: Option<String>,
    pending_process_transition: Option<Value>,
}

impl ProductRuntimeReadSnapshot {
    pub fn capture<R>(
        state: &ProductRuntimeState<R>,
        coordinator: Value,
        backend: RuntimeReadBackend,
    ) -> Self {
        let runtime = match backend {
            RuntimeReadBackend::Resident(summary) => {
                ProductRuntimeInstanceReadView::Resident(summary)
            }
            RuntimeReadBackend::Fake {
                started_at,
                tproxy_port,
            } => ProductRuntimeInstanceReadView::Fake {
                started_at,
                tproxy_port,
            },
            RuntimeReadBackend::Stopped {
                fake_runtime_enabled,
            } => ProductRuntimeInstanceReadView::Stopped {
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
            allocator_publication_id: state.allocator_publication_id,
            stop_count: state.stop_count,
            last_report: state.last_report.clone(),
            cleanup: state.cleanup.clone(),
            apply: state.apply.clone(),
            coordinator,
            active_generation: state.active_generation.clone(),
            pending_process_transition: state.pending_process_transition.clone(),
        }
    }

    pub fn render(self) -> Value {
        match self.runtime {
            ProductRuntimeInstanceReadView::Resident(summary_fn) => {
                let mut summary = summary_fn();
                self.traffic_carry.apply_to_runtime_summary(&mut summary);
                if let Value::Object(map) = &mut summary {
                    map.insert(
                        "lastTransitionAt".to_owned(),
                        json!(self.last_transition_at),
                    );
                    map.insert("startedAt".to_owned(), json!(self.runtime_started_at));
                    map.insert("lastError".to_owned(), json!(self.last_error));
                    map.insert("reloadCount".to_owned(), json!(self.reload_count));
                    map.insert(
                        "allocatorPublicationId".to_owned(),
                        json!(self.allocator_publication_id),
                    );
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
                "allocatorPublicationId": self.allocator_publication_id,
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
                "allocatorPublicationId": self.allocator_publication_id,
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
    use serde_json::json;

    #[test]
    fn read_snapshot_keeps_domain_state_until_render() {
        let report = Arc::new(json!({
            "status": "pass",
            "entries": vec!["entry"; 8],
        }));
        let state = ProductRuntimeState::<u8> {
            last_report: Some(Arc::clone(&report)),
            ..ProductRuntimeState::default()
        };
        let snapshot = ProductRuntimeReadSnapshot::capture(
            &state,
            json!({}),
            RuntimeReadBackend::Stopped {
                fake_runtime_enabled: false,
            },
        );
        assert!(Arc::ptr_eq(snapshot.last_report.as_ref().unwrap(), &report));
        assert_eq!(snapshot.render()["lastReport"], report.as_ref().clone());
    }

    #[test]
    fn resident_backend_is_evaluated_after_capture() {
        let snapshot = ProductRuntimeReadSnapshot::capture(
            &ProductRuntimeState::<u8>::default(),
            json!({}),
            RuntimeReadBackend::Resident(Box::new(|| json!({"running": true}))),
        );
        assert_eq!(snapshot.render()["running"], json!(true));
    }
}
