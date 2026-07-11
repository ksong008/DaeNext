use std::sync::Arc;

use super::{
    DNS_UDP_MULTIPLEX_QUEUE_CAPACITY, ResidentDnsUdpMultiplexHandle, dns_udp_forwarder_shard_count,
    open_connected_dns_udp_socket, run_udp_multiplex_actor,
};

const DNS_UDP_ACTOR_WORKER_THREAD_NAME: &str = "daed-dns-udp";
const DNS_UDP_ACTOR_WORKER_STACK_BYTES: usize = 512 * 1024;

pub(in crate::production_runtime_owner::resident_dataplane::dns) struct ResidentDnsUdpActorExecutor
{
    worker_count: usize,
    pool: tokio::sync::Mutex<Option<Arc<ResidentDnsUdpActorPool>>>,
}

impl Default for ResidentDnsUdpActorExecutor {
    fn default() -> Self {
        Self::for_worker_count(dns_udp_forwarder_shard_count())
    }
}

impl ResidentDnsUdpActorExecutor {
    fn for_worker_count(worker_count: usize) -> Self {
        Self {
            worker_count: worker_count.max(1),
            pool: tokio::sync::Mutex::new(None),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::dns) async fn open_handle(
        &self,
        target: std::net::SocketAddr,
        mark: u32,
    ) -> Result<ResidentDnsUdpMultiplexHandle, String> {
        if self.worker_count == 1 {
            return super::open_udp_multiplex_handle(target, mark).await;
        }
        self.pool().await?.open_handle(target, mark).await
    }

    async fn pool(&self) -> Result<Arc<ResidentDnsUdpActorPool>, String> {
        let mut pool = self.pool.lock().await;
        if let Some(pool) = pool.as_ref() {
            return Ok(Arc::clone(pool));
        }
        let opened = Arc::new(ResidentDnsUdpActorPool::new(self.worker_count)?);
        *pool = Some(Arc::clone(&opened));
        Ok(opened)
    }

    #[cfg(test)]
    pub(super) fn for_test_worker_count(worker_count: usize) -> Self {
        Self::for_worker_count(worker_count)
    }

    #[cfg(test)]
    pub(super) async fn pool_worker_count(&self) -> Option<usize> {
        self.pool
            .lock()
            .await
            .as_ref()
            .and_then(|pool| pool.runtime.as_ref())
            .map(|runtime| runtime.metrics().num_workers())
    }

    #[cfg(test)]
    pub(super) async fn pool_identity(&self) -> Option<usize> {
        self.pool
            .lock()
            .await
            .as_ref()
            .map(|pool| Arc::as_ptr(pool) as usize)
    }
}

struct ResidentDnsUdpActorPool {
    runtime: Option<tokio::runtime::Runtime>,
}

impl ResidentDnsUdpActorPool {
    fn new(worker_count: usize) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_count)
            .thread_name(DNS_UDP_ACTOR_WORKER_THREAD_NAME)
            .thread_stack_size(DNS_UDP_ACTOR_WORKER_STACK_BYTES)
            .enable_all()
            .build()
            .map_err(|err| format!("build shared DNS UDP actor runtime: {err}"))?;
        Ok(Self {
            runtime: Some(runtime),
        })
    }

    async fn open_handle(
        &self,
        target: std::net::SocketAddr,
        mark: u32,
    ) -> Result<ResidentDnsUdpMultiplexHandle, String> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| "shared DNS UDP actor runtime is closed".to_owned())?;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        runtime.spawn(async move {
            let socket = match open_connected_dns_udp_socket(target, mark).await {
                Ok(socket) => socket,
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            let (sender, receiver) = tokio::sync::mpsc::channel(DNS_UDP_MULTIPLEX_QUEUE_CAPACITY);
            let handle = ResidentDnsUdpMultiplexHandle { sender };
            if ready_tx.send(Ok(handle)).is_ok() {
                run_udp_multiplex_actor(target, socket, receiver).await;
            }
        });
        ready_rx
            .await
            .map_err(|_| "shared DNS UDP actor exited before initialization".to_owned())?
    }
}

impl Drop for ResidentDnsUdpActorPool {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests;
