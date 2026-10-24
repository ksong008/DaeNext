use super::*;
use std::collections::VecDeque;
use tokio::sync::oneshot;

#[derive(Clone, Debug)]
pub(crate) struct ResidentTcpAdmission {
    budget: Arc<Mutex<Budget>>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

#[derive(Debug)]
struct Budget {
    used: usize,
    limit: usize,
    closed: bool,
    next_waiter: u64,
    waiters: VecDeque<(u64, oneshot::Sender<ResidentTcpPermit>)>,
}

#[derive(Debug)]
pub(crate) struct ResidentTcpPermit {
    budget: Option<Arc<Mutex<Budget>>>,
}

type Grants = Vec<(oneshot::Sender<ResidentTcpPermit>, ResidentTcpPermit)>;

pub(crate) struct ResidentTcpAdmissionGuard {
    _permit: ResidentTcpPermit,
    metrics: Arc<ResidentDataplaneMetrics>,
}

struct Waiter {
    id: u64,
    budget: Arc<Mutex<Budget>>,
}

fn grant(budget: &Arc<Mutex<Budget>>, state: &mut Budget) -> Grants {
    let mut grants = Vec::new();
    while !state.closed && state.used < state.limit {
        let Some((_, sender)) = state.waiters.pop_front() else {
            break;
        };
        if sender.is_closed() {
            continue;
        }
        state.used += 1;
        grants.push((
            sender,
            ResidentTcpPermit {
                budget: Some(Arc::clone(budget)),
            },
        ));
    }
    grants
}

fn notify_grants(budget: &Arc<Mutex<Budget>>, mut grants: Grants) {
    // A receiver may disappear between grant and notification. Return all such
    // reservations in batches, outside the lock and without recursive Drop.
    loop {
        let mut cancelled = 0;
        for (sender, permit) in grants {
            if let Err(mut permit) = sender.send(permit) {
                permit.budget.take();
                cancelled += 1;
            }
        }
        if cancelled == 0 {
            break;
        }
        let mut state = budget.lock().unwrap_or_else(|error| error.into_inner());
        state.used -= cancelled;
        grants = grant(budget, &mut state);
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let grants = {
            let mut state = self
                .budget
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.waiters.retain(|(id, _)| *id != self.id);
            grant(&self.budget, &mut state)
        };
        notify_grants(&self.budget, grants);
    }
}

impl Drop for ResidentTcpPermit {
    fn drop(&mut self) {
        let Some(budget) = self.budget.take() else {
            return;
        };
        let grants = {
            let mut state = budget.lock().unwrap_or_else(|error| error.into_inner());
            state.used -= 1;
            grant(&budget, &mut state)
        };
        notify_grants(&budget, grants);
    }
}

impl ResidentTcpAdmission {
    pub(crate) fn new(limit: usize, metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        Self {
            budget: Arc::new(Mutex::new(Budget {
                used: 0,
                limit: limit.max(1),
                closed: false,
                next_waiter: 0,
                waiters: VecDeque::new(),
            })),
            metrics,
        }
    }

    pub(crate) async fn acquire(&self) -> Result<ResidentTcpPermit, String> {
        let (receiver, waiter) = {
            let mut state = self
                .budget
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.closed {
                return Err("resident TCP admission is closed".to_owned());
            }
            if state.used < state.limit && state.waiters.is_empty() {
                state.used += 1;
                return Ok(ResidentTcpPermit {
                    budget: Some(Arc::clone(&self.budget)),
                });
            }
            if state.waiters.len() >= state.limit {
                return Err("resident TCP admission waiter limit reached".to_owned());
            }
            self.metrics.tcp_admission_waited();
            let (sender, receiver) = oneshot::channel();
            state.next_waiter = state.next_waiter.wrapping_add(1);
            let id = state.next_waiter;
            state.waiters.push_back((id, sender));
            (
                receiver,
                Waiter {
                    id,
                    budget: Arc::clone(&self.budget),
                },
            )
        };
        let result = receiver
            .await
            .map_err(|_| "resident TCP admission is closed".to_owned());
        drop(waiter);
        result
    }

    pub(crate) fn set_limit(&self, limit: usize) {
        let grants = {
            let mut state = self
                .budget
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.limit = limit.max(1);
            grant(&self.budget, &mut state)
        };
        notify_grants(&self.budget, grants);
    }

    pub(crate) fn close(&self) {
        let waiters = {
            let mut state = self
                .budget
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            std::mem::take(&mut state.waiters)
        };
        drop(waiters);
    }

    pub(crate) fn snapshot(&self) -> serde_json::Value {
        let state = self
            .budget
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        json!({ "used": state.used, "limit": state.limit, "waiters": state.waiters.len(), "closed": state.closed, "scope": "physical-runtime-client-sockets" })
    }

    pub(crate) fn admitted(&self, permit: ResidentTcpPermit) -> ResidentTcpAdmissionGuard {
        self.metrics.tcp_admitted();
        ResidentTcpAdmissionGuard {
            _permit: permit,
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl Drop for ResidentTcpAdmissionGuard {
    fn drop(&mut self) {
        self.metrics.tcp_admission_released();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_admission_applies_backpressure_until_capacity_is_released() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let admission = ResidentTcpAdmission::new(2, Arc::clone(&metrics));
        let first = admission.admitted(admission.acquire().await.unwrap());
        let second = admission.admitted(admission.acquire().await.unwrap());

        assert!(
            time::timeout(Duration::from_millis(25), admission.acquire())
                .await
                .is_err()
        );
        assert_eq!(metrics.snapshot()["tcpAdmissionActive"], 2);
        assert_eq!(metrics.snapshot()["tcpAdmissionWaitCycles"], 1);

        drop(first);
        let third = time::timeout(Duration::from_secs(1), admission.acquire())
            .await
            .unwrap()
            .unwrap();
        let third = admission.admitted(third);
        assert_eq!(metrics.snapshot()["tcpAdmissionActive"], 2);

        drop((second, third));
        assert_eq!(metrics.snapshot()["tcpAdmissionActive"], 0);
        assert_eq!(metrics.snapshot()["tcpAdmissionMaximumActive"], 2);
        assert_eq!(metrics.snapshot()["tcpAdmissionAcceptedTotal"], 3);
    }

    #[tokio::test]
    async fn tcp_admission_keeps_short_flows_progressing_beside_a_long_flow() {
        let metrics = Arc::new(ResidentDataplaneMetrics::default());
        let admission = ResidentTcpAdmission::new(2, Arc::clone(&metrics));
        let long_flow = admission.admitted(admission.acquire().await.unwrap());
        let mut short_flows = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let admission = admission.clone();
            short_flows.spawn(async move {
                let permit = admission.acquire().await.unwrap();
                drop(admission.admitted(permit));
            });
        }

        time::timeout(Duration::from_secs(1), async {
            while let Some(result) = short_flows.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();

        assert_eq!(metrics.snapshot()["tcpAdmissionMaximumActive"], 2);
        assert_eq!(metrics.snapshot()["tcpAdmissionActive"], 1);
        drop(long_flow);
        assert_eq!(metrics.snapshot()["tcpAdmissionActive"], 0);
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod dynamic_tests;
