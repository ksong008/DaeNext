use super::*;
use crate::production_runtime_owner::resident_dataplane::{
    ResidentDataplaneMetrics, ResidentDnsUdpRuntimeConfig,
    dns::{
        ProxyDnsRequestContext, ProxyDnsRequestError, ProxyDnsRequestFailure, ProxyDnsRequestStage,
        ResidentDnsTransportOwnerObservation, ResidentDnsUdpActorExecutor, UdpRequestIdAllocator,
    },
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use serde_json::{Value, json};

mod actor;

use self::actor::{ResidentProxyDnsUdpActorHandle, start_proxy_dns_udp_actor};

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxyDnsUdpForwarder {
    owner_observation: Arc<ResidentDnsTransportOwnerObservation>,
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    next_actor: std::sync::atomic::AtomicUsize,
    actors: Vec<ResidentProxyDnsUdpActorSlot>,
    runtime_config: ResidentDnsUdpRuntimeConfig,
    metrics: Arc<ResidentDataplaneMetrics>,
    actor_executor: Arc<ResidentDnsUdpActorExecutor>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
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
    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn new(
        proxy: Arc<ResidentProxyPlan>,
        original_dst: SocketAddr,
        runtime_config: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        actor_executor: Arc<ResidentDnsUdpActorExecutor>,
    ) -> Result<Self, String> {
        let generation = proxy.execution_plan().runtime_generation();
        let binding = if generation.get() == 0 {
            ResidentProxyBinding::control_plane(proxy)
        } else {
            ResidentProxyBinding::resident(proxy, generation)
        }?;
        Self::new_with_optional_transport_owner(
            binding,
            original_dst,
            runtime_config,
            metrics,
            actor_executor,
            ResidentTransportOwnerRegistries::default(),
        )
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn new_with_optional_transport_owner(
        binding: ResidentProxyBinding,
        original_dst: SocketAddr,
        runtime_config: ResidentDnsUdpRuntimeConfig,
        metrics: Arc<ResidentDataplaneMetrics>,
        actor_executor: Arc<ResidentDnsUdpActorExecutor>,
        owners: ResidentTransportOwnerRegistries,
    ) -> Result<Self, String> {
        binding
            .execution()
            .udp
            .agreement()
            .admit_packet_relay("proxied DNS UDP forwarder")?;
        if let Some(reason) = resident_udp_chain_admission(binding.plan()).unsupported_reason() {
            return Err(format!(
                "proxied DNS UDP forwarder rejected by typed chain agreement: {reason}"
            ));
        }
        let request_scoped_actor_pool = binding.execution().udp.uses_request_scoped_exchange();
        let actor_count = if request_scoped_actor_pool {
            runtime_config.proxy_actor_limit.max(1)
        } else {
            1
        };
        let owner_observation = ResidentDnsTransportOwnerObservation::new(
            Arc::clone(&metrics),
            std::mem::size_of::<Self>(),
        );
        Ok(Self {
            owner_observation,
            binding,
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
            hysteria2_owner_registry: owners.hysteria2(),
            tuic_owner_registry: owners.tuic(),
            juicity_owner_registry: owners.juicity(),
            anytls_owner_registry: owners.anytls(),
            request_scoped_actor_pool,
            closing: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) async fn exchange(
        &self,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.exchange_with_context(
            payload,
            ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
        )
        .await
        .map_err(|error| error.to_string())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn exchange_with_context(
        &self,
        payload: &[u8],
        context: ProxyDnsRequestContext,
    ) -> Result<Vec<u8>, ProxyDnsRequestError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::OwnerAcquire,
                ProxyDnsRequestFailure::Network,
                "proxied DNS UDP forwarder is closing",
            ));
        }
        let (actor_index, _load_guard) = self.acquire_actor_slot();
        let attempts = self.runtime_config.attempts;
        let mut failures = Vec::with_capacity(attempts);
        for attempt in 0..attempts {
            context.ensure(ProxyDnsRequestStage::Retry)?;
            if attempt > 0 {
                self.metrics.dns_udp_retry();
            }
            let handle = context
                .run(
                    ProxyDnsRequestStage::OwnerAcquire,
                    ProxyDnsRequestFailure::Network,
                    self.actor_handle(actor_index),
                )
                .await?;
            match handle.exchange_once(payload, context).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    let retryable = err.failure() == ProxyDnsRequestFailure::Network;
                    failures.push(err);
                    if handle.is_closed() {
                        self.clear_closed_actor(actor_index, &handle).await;
                    }
                    if !retryable {
                        break;
                    }
                }
            }
        }
        let Some(last) = failures.last() else {
            return Err(ProxyDnsRequestError::new(
                ProxyDnsRequestStage::Retry,
                ProxyDnsRequestFailure::Capacity,
                "proxied DNS UDP forwarder has no configured attempts",
            ));
        };
        Err(ProxyDnsRequestError::new(
            last.stage(),
            last.failure(),
            format!(
                "proxied DNS UDP response failed after {} attempt(s): {}",
                failures.len(),
                failures
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
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
            let binding = self.binding.clone();
            let original_dst = self.original_dst;
            let runtime_config = self
                .runtime_config
                .actor_partition(actor_index, self.actors.len());
            let metrics = Arc::clone(&self.metrics);
            let hysteria2_owner_registry = self.hysteria2_owner_registry.clone();
            let tuic_owner_registry = self.tuic_owner_registry.clone();
            let juicity_owner_registry = self.juicity_owner_registry.clone();
            let anytls_owner_registry = self.anytls_owner_registry.clone();
            *handle = Some(
                self.actor_executor
                    .spawn_actor(move || async move {
                        Ok(start_proxy_dns_udp_actor(
                            binding,
                            original_dst,
                            runtime_config,
                            metrics,
                            hysteria2_owner_registry,
                            tuic_owner_registry,
                            juicity_owner_registry,
                            anytls_owner_registry,
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
            .map(|handle| {
                let actor_executor = Arc::clone(&self.actor_executor);
                async move {
                    actor_executor
                        .join_actor_task(handle.task_id(), handle.completion(), deadline)
                        .await
                }
            })
            .collect::<FuturesUnordered<_>>();
        let mut closed = 0_usize;
        let mut timed_out = 0_usize;
        while let Some(result) = waits.next().await {
            match result {
                Ok(()) => closed = closed.saturating_add(1),
                Err(_) => timed_out = timed_out.saturating_add(1),
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

    pub(in crate::production_runtime_owner::resident_dataplane) fn owner_observation(
        &self,
    ) -> Arc<ResidentDnsTransportOwnerObservation> {
        Arc::clone(&self.owner_observation)
    }

    #[cfg(test)]
    pub(in crate::production_runtime_owner::resident_dataplane) fn actor_count(&self) -> usize {
        self.actors.len()
    }
}

#[cfg(test)]
mod tests;
