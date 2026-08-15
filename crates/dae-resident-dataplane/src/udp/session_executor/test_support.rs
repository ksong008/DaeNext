use super::*;

#[derive(Clone)]
pub(crate) struct ProxyUdpSessionCheckpoint {
    state: Arc<ProxyUdpSessionCheckpointState>,
}

struct ProxyUdpSessionCheckpointState {
    expected: usize,
    ready: std::sync::atomic::AtomicUsize,
    failed: std::sync::atomic::AtomicUsize,
    released: std::sync::atomic::AtomicBool,
    changed: tokio::sync::Notify,
}

impl ProxyUdpSessionCheckpoint {
    pub(crate) fn new(session_count: usize) -> Self {
        Self {
            state: Arc::new(ProxyUdpSessionCheckpointState {
                expected: session_count,
                ready: std::sync::atomic::AtomicUsize::new(0),
                failed: std::sync::atomic::AtomicUsize::new(0),
                released: std::sync::atomic::AtomicBool::new(false),
                changed: tokio::sync::Notify::new(),
            }),
        }
    }

    pub(crate) async fn hold_session(&self) {
        self.state
            .ready
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.state.changed.notify_waiters();
        while !self
            .state
            .released
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let changed = self.state.changed.notified();
            if self
                .state
                .released
                .load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }
            changed.await;
        }
    }

    fn record_failure(&self) {
        self.state
            .failed
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.state.changed.notify_waiters();
    }

    pub(crate) async fn wait_until_held(&self) -> Result<(), String> {
        loop {
            let failed = self.state.failed.load(std::sync::atomic::Ordering::Acquire);
            if failed != 0 {
                return Err(format!(
                    "{failed} proxy UDP live-test session(s) failed before the hold checkpoint"
                ));
            }
            if self.state.ready.load(std::sync::atomic::Ordering::Acquire) == self.state.expected {
                return Ok(());
            }
            let changed = self.state.changed.notified();
            if self.state.failed.load(std::sync::atomic::Ordering::Acquire) != 0
                || self.state.ready.load(std::sync::atomic::Ordering::Acquire)
                    == self.state.expected
            {
                continue;
            }
            changed.await;
        }
    }

    pub(crate) fn release_sessions(&self) {
        self.state
            .released
            .store(true, std::sync::atomic::Ordering::Release);
        self.state.changed.notify_waiters();
    }
}

pub(crate) async fn exercise_proxy_udp_packet_session(
    binding: ResidentProxyBinding,
    registries: ResidentTransportOwnerRegistries,
    target: SocketAddr,
    payloads: &[Vec<u8>],
    checkpoint: Option<ProxyUdpSessionCheckpoint>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut executor = UdpSessionExecutor::new_proxy_packet_with_optional_transport_owner(
        binding.clone(),
        registries.hysteria2(),
        registries.tuic(),
        registries.juicity(),
        registries.anytls(),
    );
    let outcome = async {
        let mut responses = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let (_, mut response) = executor
                .execute_proxy_packet(&binding, target, payload)
                .await?;
            if !response.reply_forwarded {
                (_, response) = executor
                    .wait_response_with_timeout(
                        RESIDENT_UDP_RESPONSE_TIMEOUT,
                        "receive live-test UDP response",
                    )
                    .await?;
            }
            let expectation = response.fixed_target_expectation(target);
            let payload = response
                .take_fixed_target_payload(expectation)
                .into_payload()
                .map_err(|validation| {
                    format!("live-test UDP response validation failed: {validation:?}")
                })?;
            responses.push(payload);
        }
        Ok(responses)
    }
    .await;
    if let Some(checkpoint) = checkpoint {
        if outcome.is_ok() {
            checkpoint.hold_session().await;
        } else {
            checkpoint.record_failure();
        }
    }
    executor.shutdown().await;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn checkpoint_observes_and_releases_every_session() {
        let checkpoint = ProxyUdpSessionCheckpoint::new(3);
        let mut sessions = tokio::task::JoinSet::new();
        for _ in 0..3 {
            let checkpoint = checkpoint.clone();
            sessions.spawn(async move {
                checkpoint.hold_session().await;
            });
        }
        tokio::time::timeout(Duration::from_secs(1), checkpoint.wait_until_held())
            .await
            .unwrap()
            .unwrap();
        checkpoint.release_sessions();
        while let Some(result) = sessions.join_next().await {
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn checkpoint_reports_a_session_failure_without_waiting_for_timeout() {
        let checkpoint = ProxyUdpSessionCheckpoint::new(2);
        checkpoint.record_failure();
        let error = checkpoint.wait_until_held().await.unwrap_err();
        assert!(error.contains("1 proxy UDP live-test session"));
    }
}
