use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub(crate) struct ResidentTcpFlowRegistry {
    state: Arc<Mutex<Registry>>,
}

#[derive(Default)]
struct Registry {
    next: u64,
    closed: bool,
    flows: BTreeMap<u64, Record>,
    registered: u64,
    released: u64,
}

struct Record {
    generation: u64,
    kind: &'static str,
    stop: SharedResidentStopSignal,
}

#[derive(Clone)]
pub(crate) struct ResidentTcpFlowLease {
    inner: Arc<Lease>,
}

struct Lease {
    registry: ResidentTcpFlowRegistry,
    id: u64,
    stop: SharedResidentStopSignal,
    _admission: Option<super::admission::ResidentTcpAdmissionGuard>,
}

impl ResidentTcpFlowRegistry {
    pub(crate) fn register(
        &self,
        generation: u64,
        kind: &'static str,
        admission: Option<super::admission::ResidentTcpAdmissionGuard>,
    ) -> Result<ResidentTcpFlowLease, String> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed {
            return Err("resident TCP flow registry is closed".to_owned());
        }
        loop {
            state.next = state.next.wrapping_add(1).max(1);
            if !state.flows.contains_key(&state.next) {
                break;
            }
        }
        let id = state.next;
        let stop = crate::ResidentStopSignal::shared();
        state.flows.insert(
            id,
            Record {
                generation,
                kind,
                stop: Arc::clone(&stop),
            },
        );
        state.registered += 1;
        Ok(ResidentTcpFlowLease {
            inner: Arc::new(Lease {
                registry: self.clone(),
                id,
                stop,
                _admission: admission,
            }),
        })
    }

    pub(crate) fn stop_all(&self) {
        let stops = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            state
                .flows
                .values()
                .map(|flow| Arc::clone(&flow.stop))
                .collect::<Vec<_>>()
        };
        for stop in stops {
            stop.store(true, Ordering::Release);
        }
    }

    pub(crate) fn snapshot(&self) -> serde_json::Value {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mut generations = BTreeMap::<u64, usize>::new();
        let mut kinds = BTreeMap::<&str, usize>::new();
        for flow in state.flows.values() {
            *generations.entry(flow.generation).or_default() += 1;
            *kinds.entry(flow.kind).or_default() += 1;
        }
        json!({ "active": state.flows.len(), "byGeneration": generations, "byKind": kinds,
            "registeredTotal": state.registered, "releasedTotal": state.released,
            "closed": state.closed, "stopAuthority": "physical-runtime-shutdown" })
    }
}

impl ResidentTcpFlowLease {
    pub(crate) fn stop_handle(&self) -> SharedResidentStopSignal {
        Arc::clone(&self.inner.stop)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.flows.remove(&self.id).is_some() {
            state.released += 1;
        }
    }
}

#[cfg(test)]
#[path = "flow_registry_tests.rs"]
mod tests;
