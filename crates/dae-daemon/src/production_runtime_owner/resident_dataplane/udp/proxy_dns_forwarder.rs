use super::*;
use crate::production_runtime_owner::resident_dataplane::{
    ResidentDataplaneMetrics, ResidentDnsUdpRuntimeConfig,
    dns::{ResidentDnsUdpActorExecutor, UdpRequestIdAllocator},
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use serde_json::{Value, json};

mod actor;

use self::actor::{ResidentProxyDnsUdpActorHandle, start_proxy_dns_udp_actor};

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxyDnsUdpForwarder {
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    next_actor: std::sync::atomic::AtomicUsize,
    actors: Vec<ResidentProxyDnsUdpActorSlot>,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
    actor_executor: Arc<ResidentDnsUdpActorExecutor>,
    request_scoped_actor_pool: bool,
    closing: AtomicBool,
}

struct ResidentProxyDnsUdpActorSlot {
    handle: tokio::sync::Mutex<Option<ResidentProxyDnsUdpActorHandle>>,
    opened: AtomicBool,
    active: AtomicUsize,
}

struct ResidentProxyDnsUdpActorLoadGuard<'a> {
    active: &'a AtomicUsize,
}

impl Drop for ResidentProxyDnsUdpActorLoadGuard<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ResidentProxyDnsUdpForwarder {
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        proxy: Arc<ResidentProxyPlan>,
        original_dst: SocketAddr,
        runtime_config: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        actor_executor: Arc<ResidentDnsUdpActorExecutor>,
    ) -> Self {
        let request_scoped_actor_pool = proxy.execution_plan().udp.uses_request_scoped_exchange();
        let actor_count = if request_scoped_actor_pool {
            runtime_config.proxy_actor_limit.max(1)
        } else {
            1
        };
        Self {
            proxy,
            original_dst,
            next_actor: std::sync::atomic::AtomicUsize::new(0),
            actors: (0..actor_count)
                .map(|_| ResidentProxyDnsUdpActorSlot {
                    handle: tokio::sync::Mutex::new(None),
                    opened: AtomicBool::new(false),
                    active: AtomicUsize::new(0),
                })
                .collect(),
            runtime_config,
            metrics,
            actor_executor,
            request_scoped_actor_pool,
            closing: AtomicBool::new(false),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn exchange(
        &self,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        if self.closing.load(Ordering::Acquire) {
            return Err("proxied DNS UDP forwarder is closing".to_owned());
        }
        let (actor_index, _load_guard) = self.acquire_actor_slot();
        let attempts = self.runtime_config.attempts;
        let mut failures = Vec::with_capacity(attempts);
        for attempt in 0..attempts {
            if attempt > 0 {
                self.metrics.dns_udp_retry();
            }
            let handle = self.actor_handle(actor_index).await?;
            match handle.exchange_once(payload).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    failures.push(err);
                    if handle.is_closed() {
                        self.clear_closed_actor(actor_index, &handle).await;
                    }
                }
            }
        }
        Err(format!(
            "proxied DNS UDP response failed after {attempts} attempts: {}",
            failures.join("; ")
        ))
    }

    fn acquire_actor_slot(&self) -> (usize, ResidentProxyDnsUdpActorLoadGuard<'_>) {
        if self.actors.len() <= 1 {
            let active = &self.actors[0].active;
            active.fetch_add(1, Ordering::Relaxed);
            return (0, ResidentProxyDnsUdpActorLoadGuard { active });
        }
        let start = self.next_actor.fetch_add(1, Ordering::Relaxed) % self.actors.len();
        let mut unopened_idle = None;
        let mut least_loaded = (usize::MAX, start);
        let mut selected = None;
        for offset in 0..self.actors.len() {
            let index = (start + offset) % self.actors.len();
            let actor = &self.actors[index];
            let active = actor.active.load(Ordering::Relaxed);
            if active == 0 && actor.opened.load(Ordering::Acquire) {
                selected = Some(index);
                break;
            }
            if active == 0 && unopened_idle.is_none() {
                unopened_idle = Some(index);
            }
            if active < least_loaded.0 {
                least_loaded = (active, index);
            }
        }
        let index = selected.or(unopened_idle).unwrap_or(least_loaded.1);
        let active = &self.actors[index].active;
        active.fetch_add(1, Ordering::Relaxed);
        (index, ResidentProxyDnsUdpActorLoadGuard { active })
    }

    async fn actor_handle(
        &self,
        actor_index: usize,
    ) -> Result<ResidentProxyDnsUdpActorHandle, String> {
        if self.closing.load(Ordering::Acquire) {
            return Err("proxied DNS UDP forwarder is closing".to_owned());
        }
        let actor = self
            .actors
            .get(actor_index)
            .ok_or_else(|| format!("proxied DNS UDP actor {actor_index} is missing"))?;
        let mut handle = actor.handle.lock().await;
        if self.closing.load(Ordering::Acquire) {
            return Err("proxied DNS UDP forwarder is closing".to_owned());
        }
        let replacing_closed = handle
            .as_ref()
            .is_some_and(ResidentProxyDnsUdpActorHandle::is_closed);
        if handle
            .as_ref()
            .is_none_or(ResidentProxyDnsUdpActorHandle::is_closed)
        {
            let proxy = Arc::clone(&self.proxy);
            let original_dst = self.original_dst;
            let runtime_config = self
                .runtime_config
                .actor_partition(actor_index, self.actors.len());
            let metrics = Arc::clone(&self.metrics);
            *handle = Some(
                self.actor_executor
                    .spawn_actor(move || async move {
                        Ok(start_proxy_dns_udp_actor(
                            proxy,
                            original_dst,
                            runtime_config,
                            metrics,
                        ))
                    })
                    .await?,
            );
            actor.opened.store(true, Ordering::Release);
            if replacing_closed {
                self.metrics.dns_udp_forwarder_recreated();
            }
        }
        handle
            .as_ref()
            .cloned()
            .ok_or_else(|| "proxied DNS UDP actor was not initialized".to_owned())
    }

    async fn clear_closed_actor(
        &self,
        actor_index: usize,
        failed: &ResidentProxyDnsUdpActorHandle,
    ) {
        if !failed.is_closed() {
            return;
        }
        let Some(actor) = self.actors.get(actor_index) else {
            return;
        };
        let mut handle = actor.handle.lock().await;
        if handle
            .as_ref()
            .is_some_and(ResidentProxyDnsUdpActorHandle::is_closed)
        {
            *handle = None;
            actor.opened.store(false, Ordering::Release);
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn shutdown(
        &self,
        deadline: time::Instant,
    ) -> Value {
        self.closing.store(true, Ordering::Release);
        let mut handles = Vec::with_capacity(self.actors.len());
        for actor in &self.actors {
            if let Some(handle) = actor.handle.lock().await.take() {
                handle.close();
                handles.push(handle);
            }
            actor.opened.store(false, Ordering::Release);
        }
        let opened = handles.len();
        let mut waits = handles
            .into_iter()
            .map(|handle| async move { handle.wait_closed(deadline).await })
            .collect::<FuturesUnordered<_>>();
        let mut closed = 0_usize;
        let mut timed_out = 0_usize;
        while let Some(result) = waits.next().await {
            if result {
                closed = closed.saturating_add(1);
            } else {
                timed_out = timed_out.saturating_add(1);
            }
        }
        json!({
            "status": if timed_out == 0 { "pass" } else { "fail" },
            "generation": self.runtime_config.generation,
            "actors": self.actors.len(),
            "actorMode": if self.request_scoped_actor_pool {
                "request-scoped-pool"
            } else {
                "multiplexed-session"
            },
            "actorsOpened": opened,
            "actorsClosed": closed,
            "timedOut": timed_out,
        })
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn actor_count(&self) -> usize {
        self.actors.len()
    }
}

#[cfg(test)]
mod tests;
