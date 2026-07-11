use super::*;

#[derive(Clone, Debug)]
pub(super) struct ResidentTcpAdmission {
    permits: Arc<Semaphore>,
    metrics: Arc<ResidentDataplaneMetrics>,
}

pub(super) struct ResidentTcpAdmissionGuard {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<ResidentDataplaneMetrics>,
}

impl ResidentTcpAdmission {
    pub(super) fn new(limit: usize, metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit.max(1))),
            metrics,
        }
    }

    pub(super) async fn acquire(&self) -> Result<OwnedSemaphorePermit, String> {
        if self.permits.available_permits() == 0 {
            self.metrics.tcp_admission_waited();
        }
        Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| "resident TCP admission semaphore closed".to_owned())
    }

    pub(super) fn admitted(&self, permit: OwnedSemaphorePermit) -> ResidentTcpAdmissionGuard {
        ResidentTcpAdmissionGuard::new(permit, Arc::clone(&self.metrics))
    }
}

impl ResidentTcpAdmissionGuard {
    fn new(permit: OwnedSemaphorePermit, metrics: Arc<ResidentDataplaneMetrics>) -> Self {
        metrics.tcp_admitted();
        Self {
            _permit: permit,
            metrics,
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
