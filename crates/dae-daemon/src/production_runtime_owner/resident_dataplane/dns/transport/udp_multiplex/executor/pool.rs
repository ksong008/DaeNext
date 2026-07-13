const DNS_UDP_ACTOR_WORKER_THREAD_NAME: &str = "dns-udp";

pub(super) struct ResidentDnsUdpActorPool {
    runtime: std::sync::Mutex<Option<tokio::runtime::Runtime>>,
}

impl ResidentDnsUdpActorPool {
    pub(super) fn new(worker_count: usize, worker_stack_bytes: usize) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_count.max(1))
            .thread_name(DNS_UDP_ACTOR_WORKER_THREAD_NAME)
            .thread_stack_size(worker_stack_bytes)
            .enable_all()
            .build()
            .map_err(|err| format!("build shared DNS UDP actor runtime: {err}"))?;
        Ok(Self {
            runtime: std::sync::Mutex::new(Some(runtime)),
        })
    }

    pub(super) fn runtime_handle(&self) -> Result<tokio::runtime::Handle, String> {
        self.runtime
            .lock()
            .map_err(|_| "shared DNS UDP actor runtime lock poisoned".to_owned())?
            .as_ref()
            .map(tokio::runtime::Runtime::handle)
            .cloned()
            .ok_or_else(|| "shared DNS UDP actor runtime is closed".to_owned())
    }

    pub(super) async fn shutdown(&self, deadline: tokio::time::Instant) -> Result<(), String> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "shared DNS UDP actor runtime lock poisoned".to_owned())?
            .take();
        let Some(runtime) = runtime else {
            return Ok(());
        };
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::task::spawn_blocking(move || runtime.shutdown_timeout(timeout))
            .await
            .map_err(|err| format!("join shared DNS UDP actor runtime shutdown: {err}"))
    }

    #[cfg(test)]
    pub(super) fn worker_count(&self) -> Option<usize> {
        self.runtime.lock().ok().and_then(|runtime| {
            runtime
                .as_ref()
                .map(|runtime| runtime.metrics().num_workers())
        })
    }
}

impl Drop for ResidentDnsUdpActorPool {
    fn drop(&mut self) {
        if let Some(runtime) = self
            .runtime
            .get_mut()
            .ok()
            .and_then(std::option::Option::take)
        {
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_udp_worker_thread_name_stays_functional() {
        assert_eq!(DNS_UDP_ACTOR_WORKER_THREAD_NAME, "dns-udp");
        assert!(!DNS_UDP_ACTOR_WORKER_THREAD_NAME.contains("daed"));
        assert!(!DNS_UDP_ACTOR_WORKER_THREAD_NAME.contains("shard"));
    }
}
