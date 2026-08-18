// UDP session manager keeps kernel sockets, routing maps, session queues, and metrics explicit.
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::io;
use std::path::Path;

#[cfg(not(test))]
use dae_datapath::TcpDialMode;
#[cfg(test)]
use dae_datapath::{OUTBOUND_BLOCK, OUTBOUND_CONTROL_PLANE_ROUTING, OUTBOUND_DIRECT, TcpDialMode};
#[cfg(test)]
use dae_ebpf_support::BpfRoutingResult;
use dae_routing::RoutingMatcher;
use serde_json::Value;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinSet;

use crate::UdpIngressMetricObservation;

use super::super::plan::resident_data_udp_network_type;
use super::super::{
    ActiveGenerationSlot, ResidentDataplaneGeneration, ResidentGenerationDrainControl,
};
use super::*;

mod dns_dispatcher;
mod dns_fast_path;
mod dns_runtime;
mod ingress;
mod pinned_route;
mod router;
mod session_shards;
mod shutdown_evidence;
mod sniff;
use self::dns_dispatcher::{ResidentDnsFastPathDispatcher, ResidentDnsFastPathHandle};
use self::dns_fast_path::{
    minimal_resident_dns_routing_result, resident_udp_dns_fast_path_applies,
    resident_udp_dns_fast_path_can_bypass_missing_tuple,
};
use self::dns_runtime::ResidentUdpDnsRuntime;
use self::ingress::recv_udp_batch_with_original_dst_async;
#[cfg(test)]
use self::pinned_route::ResidentUdpRetainedResources;
use self::pinned_route::{ResidentUdpPinnedRoute, retained_udp_resources_for_generation};
use self::router::{ResidentUdpRouteSelection, ResidentUdpRouter, ResidentUdpSelection};
use self::session_shards::{
    ResidentUdpSessionShardHandle, ResidentUdpSessionShardPool, SharedUdpSniffedDomain,
};
use self::shutdown_evidence::*;
use self::sniff::{
    UdpPendingSniffer, UdpSniffDecision, UdpSniffKey, prune_udp_sniffers,
    udp_sniff_reroute_decision,
};

const UDP_ROUTE_CHOSEN_EVENT: &str = "udp_route_chosen";
const UDP_ROUTE_KIND_PROXY: &str = "proxy";
const UDP_ROUTE_KIND_BLOCK: &str = "block";
const UDP_ROUTE_KIND_DIRECT: &str = "direct";
const UDP_ROUTE_POLICY_FIXED: &str = "fixed";
const UDP_ROUTE_DIALER_BLOCK: &str = "block";
const UDP_ROUTE_DIALER_DIRECT: &str = "direct";
const UDP_ROUTE_REASON_BLOCK: &str = "selected block outbound";
const UDP_ROUTE_REASON_LIMIT: &str = "session limit reached";
const UDP_ROUTE_REASON_QUEUE_FULL: &str = "session queue full";
const UDP_ROUTE_REASON_DISPATCH_QUEUE_FULL: &str = "session dispatch queue full";
const UDP_ROUTE_REASON_SESSION_UNAVAILABLE: &str = "session actor closed during recreation";
const UDP_ROUTE_REASON_QUEUED: &str = "queued packet for resident UDP session";
#[cfg(test)]
const UDP_ROUTE_REASON_DNS_FAST_PATH: &str = "handled resident DNS packet without UDP session";

/// Upper bound on `UdpGenerationPin` entries in the manager loop.
///
/// Pins are only reclaimed by the periodic idle sweep
/// (`retire_idle_udp_generations`), so under high tuple churn the map would
/// otherwise grow with `churn_rate * idle_timeout`. The cap follows the same
/// order of magnitude as the UDP sniffers' `UDP_PACKET_SNIFFER_MAX_ENTRIES`
/// (1024); evicting the pin whose expiry is closest only costs one re-route
/// for the next packet of that tuple, never a session teardown.
const UDP_GENERATION_PIN_MAX_ENTRIES: usize = 4096;

#[derive(Clone)]
pub(crate) struct ResidentUdpGenerationPlan {
    router: Arc<ResidentUdpRouter>,
    dns: ResidentDnsDispatcher,
    runtime_config: ResidentUdpRuntimeConfig,
    hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
}

impl ResidentUdpGenerationPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proxy_groups: SharedResidentProxyGroupMap,
        default_outbound: u8,
        routing_tuple_map_id: Option<u32>,
        routing_matcher: RoutingMatcher,
        dial_mode: TcpDialMode,
        so_mark_from_dae: u32,
        dns: ResidentDnsDispatcher,
        runtime_config: ResidentUdpRuntimeConfig,
        health_resuscitation: ResidentHealthResuscitationHandle,
        hysteria2_owner_registry: Hysteria2OwnerRegistryHandle,
        tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
        juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
        anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    ) -> Result<Self, String> {
        Ok(Self {
            router: Arc::new(ResidentUdpRouter::new(
                proxy_groups,
                default_outbound,
                routing_tuple_map_id,
                routing_matcher,
                dial_mode,
                so_mark_from_dae,
                health_resuscitation,
            )?),
            dns,
            runtime_config,
            hysteria2_owner_registry,
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpGenerationPinKey {
    peer: SocketAddr,
    original_dst: SocketAddr,
}

#[derive(Clone)]
struct UdpGenerationPin {
    generation: u64,
    expires_at: Instant,
    route: Option<ResidentUdpPinnedRoute>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpGenerationChoice {
    Available(u64),
    PinUnavailable,
}

struct ResidentUdpGenerationRuntime {
    generation_id: u64,
    reload_generation: u64,
    drain_control: Arc<ResidentGenerationDrainControl>,
    router: Option<Arc<ResidentUdpRouter>>,
    runtime_config: ResidentUdpRuntimeConfig,
    sniffers: HashMap<UdpSniffKey, UdpPendingSniffer>,
    reply_dispatcher: UdpReplyDispatcher,
    udp_reply: UdpReplyHandle,
    dns_runtime: Option<ResidentUdpDnsRuntime>,
    session_shards: ResidentUdpSessionShardPool,
    session_shard_handle: ResidentUdpSessionShardHandle,
}

impl ResidentUdpGenerationRuntime {
    fn start(
        generation: &ResidentDataplaneGeneration,
        event_file: &Path,
        event_lock: &Arc<Mutex<()>>,
        active_sessions: &Arc<AtomicUsize>,
    ) -> Self {
        let plan = &generation.udp;
        let config = plan.runtime_config.clone();
        let reply_dispatcher = UdpReplyDispatcher::start(
            config.reply_shards(),
            config.reply_queue_depth,
            config.reply_socket_cache_capacity,
            config.reply_socket_idle_timeout,
            config.reply_send_batch_limit,
            config.payload_admission.clone(),
            Arc::clone(&generation.metrics),
        );
        let udp_reply = reply_dispatcher.handle();
        let dns_runtime = ResidentUdpDnsRuntime::start(
            plan.dns.clone(),
            udp_reply.clone(),
            Arc::clone(&generation.metrics),
            config.dns_fast_path_concurrency,
            config.dns_fast_path_queue_depth,
        );
        let session_shards = ResidentUdpSessionShardPool::start(
            &config,
            event_file.to_path_buf(),
            Arc::clone(event_lock),
            Arc::clone(&generation.metrics),
            udp_reply.clone(),
            Arc::clone(active_sessions),
            plan.hysteria2_owner_registry.clone(),
            plan.tuic_owner_registry.clone(),
            plan.juicity_owner_registry.clone(),
            plan.anytls_owner_registry.clone(),
        );
        let session_shard_handle = session_shards.handle();
        generation.drain_control.register_udp_runtime();
        Self {
            generation_id: generation.id.get(),
            reload_generation: generation.reload_generation.get(),
            drain_control: Arc::clone(&generation.drain_control),
            router: Some(Arc::clone(&plan.router)),
            runtime_config: config,
            sniffers: HashMap::new(),
            reply_dispatcher,
            udp_reply,
            dns_runtime: Some(dns_runtime),
            session_shards,
            session_shard_handle,
        }
    }

    fn handle_packet(
        &mut self,
        packet: UdpOriginalDstPacket,
        event_file: &Path,
        event_lock: &Arc<Mutex<()>>,
    ) -> Option<ResidentUdpPinnedRoute> {
        let router = self.router.as_deref()?;
        let dns_fast_path = &self.dns_runtime.as_ref()?.handle;
        bind_manager_packet(
            packet,
            router,
            event_file,
            event_lock,
            &mut self.sniffers,
            dns_fast_path,
            &self.session_shard_handle,
            self.runtime_config.runtime_shards,
        )
    }

    fn handle_pinned_packet(
        &self,
        packet: UdpOriginalDstPacket,
        route: &ResidentUdpPinnedRoute,
        event_file: &Path,
        event_lock: &Arc<Mutex<()>>,
    ) {
        let dns_fast_path = self.dns_runtime.as_ref().map(|runtime| &runtime.handle);
        route.dispatch(
            packet,
            event_file,
            event_lock,
            dns_fast_path,
            &self.session_shard_handle,
            self.runtime_config.runtime_shards,
        );
    }

    fn detach_retired_resources(
        &mut self,
        keep_router: bool,
        keep_dns_runtime: bool,
    ) -> Option<(ResidentUdpDnsRuntime, Duration)> {
        let mut detached = false;
        if !keep_router && self.router.take().is_some() {
            self.sniffers.clear();
            self.drain_control.release_udp_router();
            detached = true;
        }
        let dns_runtime = if keep_dns_runtime {
            None
        } else {
            self.dns_runtime.take().map(|runtime| {
                self.drain_control.release_udp_dns_runtime();
                detached = true;
                (runtime, self.runtime_config.shutdown_timeout)
            })
        };
        if detached {
            request_udp_generation_reclaim();
        }
        dns_runtime
    }

    fn prune_pending_sniffers(&mut self) {
        prune_udp_sniffers(&mut self.sniffers);
    }

    fn has_pending_sniffer(&self, key: UdpGenerationPinKey) -> bool {
        self.sniffers
            .contains_key(&UdpSniffKey::new(key.peer, key.original_dst))
    }

    async fn shutdown(self) -> Value {
        self.drain_control.release_udp_router();
        self.drain_control.release_udp_dns_runtime();
        let ResidentUdpGenerationRuntime {
            generation_id,
            reload_generation,
            drain_control: _,
            router: _,
            runtime_config,
            sniffers,
            reply_dispatcher,
            udp_reply,
            dns_runtime,
            session_shards,
            session_shard_handle,
        } = self;
        let shutdown_deadline = time::Instant::now() + runtime_config.shutdown_timeout;
        let component_deadline = shutdown_deadline
            .checked_sub(RESIDENT_RUNTIME_FORCED_TASK_JOIN_GRACE)
            .unwrap_or(shutdown_deadline);
        drop(sniffers);
        drop(session_shard_handle);
        let dns_shutdown = async move {
            match dns_runtime {
                Some(runtime) => runtime.shutdown(component_deadline).await,
                None => json!({
                    "status": "pass",
                    "dnsFastPathDispatcher": {"status": "pass", "detached": true},
                    "dnsForwarders": {"status": "pass", "detached": true},
                }),
            }
        };
        let (session_shard_shutdown, dns_shutdown) =
            tokio::join!(session_shards.shutdown(component_deadline), dns_shutdown,);
        drop(udp_reply);
        let reply_shutdown = reply_dispatcher.shutdown(shutdown_deadline).await;
        let cleanup_passed =
            udp_generation_cleanup_passed(&session_shard_shutdown, &dns_shutdown, &reply_shutdown);
        let (graceful, completion_mode) = udp_cleanup_completion(
            cleanup_passed,
            [&session_shard_shutdown, &dns_shutdown, &reply_shutdown],
        );
        json!({
            "status": if cleanup_passed { "pass" } else { "fail" },
            "safetyStatus": if cleanup_passed { "pass" } else { "fail" },
            "graceful": graceful,
            "completionMode": completion_mode,
            "generation": reload_generation,
            "generationId": generation_id,
            "reloadGeneration": reload_generation,
            "queuedPayloadAdmission": runtime_config.payload_admission.snapshot(),
            "queuedPayloadAdmissionScope": "resident-runtime-shared",
            "sessionShards": session_shard_shutdown,
            "dnsFastPathDispatcher": dns_shutdown["dnsFastPathDispatcher"].clone(),
            "dnsForwarders": dns_shutdown["dnsForwarders"].clone(),
            "replyDispatcher": reply_shutdown,
        })
    }
}

pub(super) async fn run_resident_udp_session_manager_async(
    socket: UdpSocket,
    active_generation: ActiveGenerationSlot<ResidentDataplaneGeneration>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    active_sessions: Arc<AtomicUsize>,
) -> Value {
    let initial_generation = active_generation.load();
    let initial_plan = &initial_generation.udp;
    let initial_config = &initial_plan.runtime_config;
    let shared_payload_admission = initial_config.payload_admission.clone();
    if let Err(err) = socket.set_nonblocking(true) {
        let report = udp_session_manager_start_failure("socket-nonblocking", err.to_string());
        append_event(
            &event_file,
            &event_lock,
            udp_session_manager_event("udp_socket_nonblocking_failed", &report),
        );
        return report;
    }
    let socket = match AsyncFd::new(socket) {
        Ok(socket) => socket,
        Err(err) => {
            let report = udp_session_manager_start_failure("async-fd", err.to_string());
            append_event(
                &event_file,
                &event_lock,
                udp_session_manager_event("udp_session_manager_async_fd_failed", &report),
            );
            return report;
        }
    };
    let default_proxy_group = initial_plan.router.default_proxy_group();
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "udp_session_manager_started",
            "proxy_group": default_proxy_group.group_name,
            "group_policy": default_proxy_group.group_policy_name(),
            "candidate_count": default_proxy_group.candidate_count(),
            "admitted_candidate_count": default_proxy_group.admitted_candidate_count(),
            "default_outbound": initial_plan.router.default_outbound(),
            "routing_tuple_map_id": initial_plan.router.routing_tuple_map_id(),
            "session_admission": {
                "mode": if initial_config.session_admission_limit.is_some() { "fixed" } else { "automatic" },
                "fixed_limit": initial_config.session_admission_limit,
                "soft_watermark": initial_config.session_soft_watermark,
            },
            "dns_fast_path_concurrency": initial_config.dns_fast_path_concurrency,
            "dns_fast_path_queue_depth": initial_config.dns_fast_path_queue_depth,
            "forced_dns_session_lanes": initial_config.runtime_shards,
            "generation": initial_config.generation,
            "runtimeProfile": initial_config.profile,
            "queuedPayloadAdmission": initial_config.payload_admission.snapshot(),
            "generationAdmission": "fixed-at-transparent-session-boundary",
            "packetSessionManager": {
                "schemaVersion": 2,
                "manager": "resident-udp-session-manager",
                "runtime": "process-owned-shared-multi-thread",
                "sessionShardCount": initial_config.runtime_shards,
                "sharedDataPlaneWorkerThreads": initial_config.runtime_worker_threads,
                "sessionAdmission": {
                    "mode": if initial_config.session_admission_limit.is_some() { "fixed" } else { "automatic" },
                    "fixedLimit": initial_config.session_admission_limit,
                    "softWatermark": initial_config.session_soft_watermark,
                },
                "perSessionQueueDepth": initial_config.session_queue_depth,
                "replyQueueDepth": initial_config.reply_queue_depth,
                "replySocketCacheCapacity": initial_config.reply_socket_cache_capacity,
                "keyFields": [
                    "graphIdentityHash",
                    "outbound",
                    "peerSocketAddr",
                    "originalDestinationSocketAddr",
                    "packetSemantics",
                ],
            },
        }),
    );

    let payload_pool = UdpPayloadPool::new(
        initial_config.payload_pool_capacity(),
        initial_config.runtime_shards,
    );
    let mut ingress_batch_receiver =
        UdpBatchReceiver::new(initial_config.ingress_syscall_batch_limit);
    let ingress_drain_budget = initial_config.ingress_drain_budget;
    let mut ingress_packets = Vec::with_capacity(ingress_drain_budget.min(32));
    let mut generations = HashMap::<u64, ResidentUdpGenerationRuntime>::new();
    let mut pins = HashMap::<UdpGenerationPinKey, UdpGenerationPin>::new();
    let mut retired_shutdowns = JoinSet::new();
    let mut retired_component_shutdowns = JoinSet::new();
    let mut retired_shutdown_count = 0_u64;
    let mut retired_shutdown_failures = 0_u64;
    let mut retired_shutdown_forced = 0_u64;
    let mut retired_shutdown_degraded = 0_u64;
    let mut retired_component_shutdown_count = 0_u64;
    let mut retired_component_shutdown_failures = 0_u64;
    let mut retired_component_shutdown_forced = 0_u64;
    let mut retired_component_shutdown_degraded = 0_u64;
    generations.insert(
        initial_generation.id.get(),
        ResidentUdpGenerationRuntime::start(
            initial_generation.as_ref(),
            &event_file,
            &event_lock,
            &active_sessions,
        ),
    );
    drop(initial_generation);

    let mut stop_listener = stop.listener();
    let retirement = time::sleep(RESIDENT_IDLE_SLEEP);
    tokio::pin!(retirement);
    while !stop.load(Ordering::Relaxed) {
        tokio::select! {
            batch = recv_udp_batch_with_original_dst_async(
                &socket,
                &payload_pool,
                &mut ingress_batch_receiver,
                ingress_drain_budget,
                &mut ingress_packets,
            ) => {
                match batch {
                    Ok(batch) => {
                        let active = active_generation.load();
                        active.metrics.record_udp_ingress_batch(UdpIngressMetricObservation {
                            packets: ingress_packets.len(),
                            truncated: batch.truncated,
                            control_truncated: batch.control_truncated,
                            invalid: batch.invalid,
                            budget_hit: batch.budget_hit,
                            syscalls: batch.syscall_count,
                            syscall_batches: batch.batch_syscalls,
                            batch_datagrams: batch.batch_datagrams,
                            batch_max: batch.batch_max,
                            would_block: batch.would_block,
                        });
                        if let Some(reason) = &batch.fallback_activated {
                            append_event(
                                &event_file,
                                &event_lock,
                                json!({"event": "udp_recvmmsg_fallback", "reason": reason}),
                            );
                        }
                        let batch_now = Instant::now();
                        for mut packet in ingress_packets.drain(..) {
                            let now = batch_now;
                            let pin_key = packet.original_dst.map(|original_dst| UdpGenerationPinKey {
                                peer: packet.peer,
                                original_dst,
                            });
                            let pinned_generation = pin_key.and_then(|key| {
                                pins.get(&key)
                                    .filter(|pin| pin.expires_at > now)
                                    .filter(|pin| udp_generation_pin_is_eligible(pin, active.id.get()))
                                    .map(|pin| pin.generation)
                            });
                            if let (Some(pin_key), Some(generation_id)) =
                                (pin_key, pinned_generation)
                            {
                                if generation_id == active.id.get() {
                                    generations.entry(generation_id).or_insert_with(|| {
                                        ResidentUdpGenerationRuntime::start(
                                            active.as_ref(),
                                            &event_file,
                                            &event_lock,
                                            &active_sessions,
                                        )
                                    });
                                } else if !generations.contains_key(&generation_id) {
                                    active.metrics.udp_generation_pin_unavailable();
                                    continue;
                                }
                                let generation = generations
                                    .get_mut(&generation_id)
                                    .expect("eligible UDP generation runtime is installed");
                                let runtime_config = &generation.runtime_config;
                                let session_idle_timeout = runtime_config.session_idle_timeout;
                                let proxy_session_idle_timeout =
                                    runtime_config.proxy_session_idle_timeout;
                                if admit_udp_payload(
                                    &mut packet.payload,
                                    &runtime_config.payload_admission,
                                )
                                .is_err()
                                {
                                    continue;
                                }
                                let pin = pins
                                    .get_mut(&pin_key)
                                    .expect("eligible UDP generation pin is installed");
                                if let Some(route) = pin.route.as_ref() {
                                    generation.handle_pinned_packet(
                                        packet,
                                        route,
                                        &event_file,
                                        &event_lock,
                                    );
                                    pin.expires_at = now
                                        + route.idle_timeout(
                                            session_idle_timeout,
                                            proxy_session_idle_timeout,
                                        );
                                    continue;
                                }
                                let route =
                                    generation.handle_packet(packet, &event_file, &event_lock);
                                let idle_timeout = route
                                    .as_ref()
                                    .map(|route| {
                                        route.idle_timeout(
                                            session_idle_timeout,
                                            proxy_session_idle_timeout,
                                        )
                                    })
                                    .unwrap_or(session_idle_timeout);
                                pin.route = route;
                                pin.expires_at = now + idle_timeout;
                                continue;
                            }

                            let generation_id = active.id.get();
                            generations.entry(generation_id).or_insert_with(|| {
                                ResidentUdpGenerationRuntime::start(
                                        active.as_ref(),
                                        &event_file,
                                        &event_lock,
                                        &active_sessions,
                                    )
                            });
                            let generation = generations
                                .get_mut(&generation_id)
                                .expect("selected UDP generation runtime is installed");
                            let runtime_config = &generation.runtime_config;
                            let session_idle_timeout = runtime_config.session_idle_timeout;
                            let proxy_session_idle_timeout =
                                runtime_config.proxy_session_idle_timeout;
                            if admit_udp_payload(
                                &mut packet.payload,
                                &runtime_config.payload_admission,
                            )
                            .is_err()
                            {
                                continue;
                            }
                            let route = generation.handle_packet(packet, &event_file, &event_lock);
                            if let Some(pin_key) = pin_key {
                                let idle_timeout = route
                                    .as_ref()
                                    .map(|route| {
                                        route.idle_timeout(
                                            session_idle_timeout,
                                            proxy_session_idle_timeout,
                                        )
                                    })
                                    .unwrap_or(session_idle_timeout);
                                if pins.len() >= UDP_GENERATION_PIN_MAX_ENTRIES {
                                    evict_oldest_udp_generation_pin(&mut pins);
                                }
                                pins.insert(
                                    pin_key,
                                    UdpGenerationPin {
                                        generation: generation_id,
                                        expires_at: now + idle_timeout,
                                        route,
                                    },
                                );
                            }
                        }
                        if batch.budget_hit {
                            tokio::task::yield_now().await;
                        }
                    }
                    Err(err) => {
                        if !stop.load(Ordering::Relaxed) {
                            append_event(
                                &event_file,
                                &event_lock,
                                json!({"event": "udp_receive_failed", "error": err}),
                            );
                        }
                    }
                }
            }
            _ = &mut retirement => {
                retire_idle_udp_generations(
                    &active_generation,
                    &mut pins,
                    &mut generations,
                    &mut retired_shutdowns,
                    &mut retired_component_shutdowns,
                );
                retirement.as_mut().reset(time::Instant::now() + RESIDENT_IDLE_SLEEP);
            }
            completed = retired_shutdowns.join_next(), if !retired_shutdowns.is_empty() => {
                retired_shutdown_count = retired_shutdown_count.saturating_add(1);
                match completed {
                    Some(Ok(report)) if cleanup_report_passed(&report) => {
                        record_udp_cleanup_mode(
                            &report,
                            &mut retired_shutdown_forced,
                            &mut retired_shutdown_degraded,
                        );
                    }
                    _ => {
                        retired_shutdown_failures = retired_shutdown_failures.saturating_add(1);
                    }
                }
            }
            completed = retired_component_shutdowns.join_next(), if !retired_component_shutdowns.is_empty() => {
                retired_component_shutdown_count = retired_component_shutdown_count.saturating_add(1);
                match completed {
                    Some(Ok(report)) if cleanup_report_passed(&report) => {
                        record_udp_cleanup_mode(
                            &report,
                            &mut retired_component_shutdown_forced,
                            &mut retired_component_shutdown_degraded,
                        );
                    }
                    _ => {
                        retired_component_shutdown_failures = retired_component_shutdown_failures.saturating_add(1);
                    }
                }
            }
            _ = stop_listener.cancelled() => break,
        }
    }

    drop(pins);
    let active_generation_count = generations.len();
    for (_, generation) in generations {
        retired_shutdowns.spawn(generation.shutdown());
    }
    while let Some(completed) = retired_component_shutdowns.join_next().await {
        retired_component_shutdown_count = retired_component_shutdown_count.saturating_add(1);
        match completed {
            Ok(report) if cleanup_report_passed(&report) => {
                record_udp_cleanup_mode(
                    &report,
                    &mut retired_component_shutdown_forced,
                    &mut retired_component_shutdown_degraded,
                );
            }
            _ => {
                retired_component_shutdown_failures =
                    retired_component_shutdown_failures.saturating_add(1);
            }
        }
    }
    let mut generation_shutdown = Vec::with_capacity(active_generation_count);
    while let Some(completed) = retired_shutdowns.join_next().await {
        retired_shutdown_count = retired_shutdown_count.saturating_add(1);
        match completed {
            Ok(report) => {
                if !cleanup_report_passed(&report) {
                    retired_shutdown_failures = retired_shutdown_failures.saturating_add(1);
                } else {
                    record_udp_cleanup_mode(
                        &report,
                        &mut retired_shutdown_forced,
                        &mut retired_shutdown_degraded,
                    );
                }
                generation_shutdown.push(report);
            }
            Err(error) => {
                retired_shutdown_failures = retired_shutdown_failures.saturating_add(1);
                generation_shutdown.push(json!({
                    "status": "fail",
                    "error": error.to_string(),
                }));
            }
        }
    }
    let active_sessions = active_sessions.load(Ordering::Acquire);
    let queued_payload_admission = shared_payload_admission.snapshot();
    let queued_payload_released = queued_payload_admission["currentBytes"].as_u64() == Some(0);
    let cleanup_passed = udp_manager_cleanup_passed(
        active_sessions,
        retired_shutdown_failures,
        retired_component_shutdown_failures,
        queued_payload_released,
    );
    let forced_cleanup_count =
        retired_shutdown_forced.saturating_add(retired_component_shutdown_forced);
    let degraded_cleanup_count =
        retired_shutdown_degraded.saturating_add(retired_component_shutdown_degraded);
    let graceful = cleanup_passed && forced_cleanup_count == 0 && degraded_cleanup_count == 0;
    let completion_mode = if !cleanup_passed {
        "incomplete"
    } else if forced_cleanup_count != 0 {
        "forced-bounded"
    } else if graceful {
        "graceful"
    } else {
        "completed-degraded"
    };
    let report = json!({
        "status": if cleanup_passed { "pass" } else { "fail" },
        "safetyStatus": if cleanup_passed { "pass" } else { "fail" },
        "graceful": graceful,
        "completionMode": completion_mode,
        "activeSessions": active_sessions,
        "queuedPayloadAdmission": queued_payload_admission,
        "queuedPayloadReleased": queued_payload_released,
        "retiredGenerationShutdowns": retired_shutdown_count,
        "retiredGenerationShutdownFailures": retired_shutdown_failures,
        "retiredGenerationShutdownForced": retired_shutdown_forced,
        "retiredGenerationShutdownDegraded": retired_shutdown_degraded,
        "retiredComponentShutdowns": retired_component_shutdown_count,
        "retiredComponentShutdownFailures": retired_component_shutdown_failures,
        "retiredComponentShutdownForced": retired_component_shutdown_forced,
        "retiredComponentShutdownDegraded": retired_component_shutdown_degraded,
        "generations": generation_shutdown,
    });
    append_event(
        &event_file,
        &event_lock,
        udp_session_manager_event("udp_session_manager_stopped", &report),
    );
    report
}

#[cfg(test)]
fn udp_generation_pin_for_packet(
    pins: &HashMap<UdpGenerationPinKey, UdpGenerationPin>,
    key: UdpGenerationPinKey,
    now: Instant,
    active_generation: u64,
) -> Option<&UdpGenerationPin> {
    pins.get(&key)
        .filter(|pin| pin.expires_at > now)
        .filter(|pin| udp_generation_pin_is_eligible(pin, active_generation))
}

fn udp_generation_pin_is_eligible(pin: &UdpGenerationPin, active_generation: u64) -> bool {
    pin.generation == active_generation
        || !pin
            .route
            .as_ref()
            .is_some_and(ResidentUdpPinnedRoute::follows_active_generation)
}

/// Evict the pin with the earliest expiry once the map is at its cap.
///
/// Pins with the earliest `expires_at` are the ones closest to being reclaimed
/// by the idle sweep, so evicting them loses the least active routing state.
/// Active sessions keep refreshing their pin's `expires_at`, so an eviction
/// only forces the next packet of that tuple to be re-routed.
fn evict_oldest_udp_generation_pin(pins: &mut HashMap<UdpGenerationPinKey, UdpGenerationPin>) {
    let Some(oldest) = pins
        .iter()
        .min_by_key(|(_, pin)| pin.expires_at)
        .map(|(key, _)| *key)
    else {
        return;
    };
    pins.remove(&oldest);
}

#[cfg(test)]
fn udp_generation_choice(
    pinned: Option<u64>,
    active: u64,
    is_available: impl FnOnce(u64) -> bool,
) -> UdpGenerationChoice {
    match pinned {
        Some(generation) if is_available(generation) => UdpGenerationChoice::Available(generation),
        Some(_) => UdpGenerationChoice::PinUnavailable,
        None => UdpGenerationChoice::Available(active),
    }
}

fn retire_idle_udp_generations(
    active_generation: &ActiveGenerationSlot<ResidentDataplaneGeneration>,
    pins: &mut HashMap<UdpGenerationPinKey, UdpGenerationPin>,
    generations: &mut HashMap<u64, ResidentUdpGenerationRuntime>,
    shutdowns: &mut JoinSet<Value>,
    component_shutdowns: &mut JoinSet<Value>,
) {
    let now = Instant::now();
    let active_id = active_generation.load().id.get();
    pins.retain(|_, pin| pin.expires_at > now && udp_generation_pin_is_eligible(pin, active_id));
    for (generation_id, runtime) in generations.iter_mut() {
        if *generation_id != active_id
            && runtime.drain_control.stop_is_requested()
            && !runtime.drain_control.udp_stop_is_requested()
        {
            runtime.prune_pending_sniffers();
        }
    }
    pins.retain(|key, pin| {
        let runtime = generations.get(&pin.generation);
        if runtime.is_some_and(|runtime| runtime.drain_control.udp_stop_is_requested()) {
            return false;
        }
        udp_generation_pin_is_required(
            pin.generation == active_id,
            pin.route.is_some(),
            runtime.is_some_and(|runtime| runtime.drain_control.stop_is_requested()),
            runtime.is_some_and(|runtime| runtime.has_pending_sniffer(*key)),
        )
    });
    for (generation_id, runtime) in generations.iter_mut() {
        if *generation_id == active_id
            || !runtime.drain_control.stop_is_requested()
            || runtime.drain_control.udp_stop_is_requested()
        {
            continue;
        }
        let retained = retained_udp_resources_for_generation(pins, *generation_id);
        if retained.has_pin
            && let Some((dns_runtime, shutdown_timeout)) =
                runtime.detach_retired_resources(retained.router, retained.dns_runtime)
        {
            component_shutdowns.spawn(async move {
                let report = dns_runtime
                    .shutdown(time::Instant::now() + shutdown_timeout)
                    .await;
                request_udp_generation_reclaim();
                report
            });
        }
    }
    let retired = generations
        .keys()
        .copied()
        .filter(|generation| {
            *generation != active_id
                && (generations
                    .get(generation)
                    .is_some_and(|runtime| runtime.drain_control.udp_stop_is_requested())
                    || !pins.values().any(|pin| pin.generation == *generation))
        })
        .collect::<Vec<_>>();
    for generation in retired {
        if let Some(runtime) = generations.remove(&generation) {
            shutdowns.spawn(runtime.shutdown());
        }
    }
}

fn udp_generation_pin_is_required(
    active_generation: bool,
    route_is_bound: bool,
    retirement_started: bool,
    sniff_is_pending: bool,
) -> bool {
    active_generation || route_is_bound || !retirement_started || sniff_is_pending
}

fn udp_session_manager_start_failure(stage: &'static str, error: String) -> Value {
    json!({
        "status": "fail",
        "stage": stage,
        "error": error,
    })
}

#[cfg(not(test))]
fn request_udp_generation_reclaim() {
    resident_allocator_request_reclaim(ResidentAllocatorReclaimReason::RetiredGenerationReleased);
}

#[cfg(test)]
fn request_udp_generation_reclaim() {}

fn udp_session_manager_event(event: &'static str, report: &Value) -> Value {
    let mut value = report.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("event".to_owned(), json!(event));
    }
    value
}

fn bind_manager_packet(
    packet: UdpOriginalDstPacket,
    router: &ResidentUdpRouter,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    sniffers: &mut HashMap<UdpSniffKey, UdpPendingSniffer>,
    dns_fast_path: &ResidentDnsFastPathHandle,
    session_shards: &ResidentUdpSessionShardHandle,
    forced_dns_session_lanes: usize,
) -> Option<ResidentUdpPinnedRoute> {
    let Some(original_dst) = packet.original_dst else {
        append_event(
            event_file,
            event_lock,
            json!({"event": "udp_packet_skipped", "reason": "missing original destination", "peer": resident_socket_addr_display(packet.peer)}),
        );
        return None;
    };
    let initial = match router.lookup_routing_result(packet.peer, original_dst) {
        Ok(initial) => initial,
        Err(err) => {
            if resident_udp_dns_fast_path_can_bypass_missing_tuple(original_dst, &packet.payload) {
                minimal_resident_dns_routing_result()
            } else {
                append_udp_route_selection_failed(
                    event_file,
                    event_lock,
                    packet.peer,
                    original_dst,
                    None,
                    err,
                );
                return None;
            }
        }
    };
    let ready = match udp_sniff_reroute_decision(packet, router, original_dst, initial, sniffers) {
        UdpSniffDecision::Ready(ready) => ready,
        UdpSniffDecision::Pending => return None,
    };
    let sniffed_domain = if ready.sniffed_domain.is_empty() {
        None
    } else {
        Some(Arc::<str>::from(ready.sniffed_domain))
    };
    let first = ready.packets.first()?;
    let first_original_dst = first.original_dst?;
    let selection = match router.select_from_routing_result_with_domain(
        first.peer,
        first_original_dst,
        ready.initial,
        sniffed_domain.as_deref().unwrap_or_default(),
    ) {
        Ok(selection) => selection,
        Err(err) => {
            append_udp_route_selection_failed(
                event_file,
                event_lock,
                first.peer,
                first_original_dst,
                Some(ready.initial.dscp),
                err,
            );
            return None;
        }
    };
    let route = match selection {
        ResidentUdpSelection::ResidentDns => ResidentUdpPinnedRoute::ResidentDns,
        ResidentUdpSelection::Proxy(selection) => {
            let graph_identity_hash = graph_identity_hash(selection.proxy.plan());
            ResidentUdpPinnedRoute::Proxy {
                proxy: selection.proxy,
                graph_identity_hash,
                selected_network_type: selection.selected_network_type,
                force_proxy_packet: selection.force_proxy_packet,
                route: selection.route,
                data_udp_availability: selection.data_udp_availability,
                sniffed_domain,
                dscp: ready.initial.dscp,
            }
        }
        ResidentUdpSelection::Direct(selection) => ResidentUdpPinnedRoute::Direct {
            route: selection.route,
            sniffed_domain,
            dscp: ready.initial.dscp,
        },
        ResidentUdpSelection::Block(route) => ResidentUdpPinnedRoute::Block {
            route,
            sniffed_domain,
            dscp: ready.initial.dscp,
        },
    };
    for packet in ready.packets {
        route.dispatch(
            packet,
            event_file,
            event_lock,
            Some(dns_fast_path),
            session_shards,
            forced_dns_session_lanes,
        );
    }
    Some(route)
}

fn append_udp_route_selection_failed(
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
    peer: SocketAddr,
    original_dst: SocketAddr,
    dscp: Option<u8>,
    err: String,
) {
    let mut event = json!({
        "event": "udp_exchange_failed",
        "peer": resident_socket_addr_display(peer),
        "original_dst": resident_socket_addr_display(original_dst),
        "error": err,
        "network": resident_udp_network_name(original_dst),
    });
    if let Some(dscp) = dscp {
        event["dscp"] = json!(dscp);
    }
    append_event(event_file, event_lock, event);
}

fn udp_route_chosen_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    proxy: Option<&ResidentProxyPlan>,
    packet_session: Option<&UdpSessionKey>,
    sniffed_domain: &str,
    dscp: u8,
    task_queued: bool,
    reason: &str,
) -> serde_json::Value {
    let outbound_kind = if proxy.is_some() {
        UDP_ROUTE_KIND_PROXY
    } else {
        UDP_ROUTE_KIND_BLOCK
    };
    let outbound = proxy
        .map(|proxy| proxy.group_name.as_str())
        .unwrap_or(UDP_ROUTE_KIND_BLOCK);
    let policy = proxy
        .map(|proxy| proxy.group_policy.as_str())
        .unwrap_or(UDP_ROUTE_POLICY_FIXED);
    let dialer = proxy
        .map(|proxy| proxy.node_tag.as_str())
        .unwrap_or(UDP_ROUTE_DIALER_BLOCK);
    let mut event = json!({
        "event": UDP_ROUTE_CHOSEN_EVENT,
        "outbound_kind": outbound_kind,
        "peer": resident_socket_addr_display(peer),
        "original_dst": resident_socket_addr_display(original_dst),
        "direct_target": resident_socket_addr_display(original_dst),
        "initial_outbound": route.initial_outbound,
        "final_outbound": route.final_outbound,
        "final_mark": route.final_mark,
        "userspace_route_executed": route.userspace_route_executed,
        "userspace_route_must": route.userspace_route_must,
        "sniffed_domain": sniffed_domain,
        "network": resident_udp_network_name(original_dst),
        "outbound": outbound,
        "policy": policy,
        "dialer": dialer,
        "ip": resident_socket_addr_display(original_dst),
        "task_queued": task_queued,
        "reason": reason,
        "dscp": dscp,
    });
    if let Some(proxy) = proxy
        && let Some(map) = event.as_object_mut()
    {
        map.insert(
            "proxy_group".to_owned(),
            serde_json::Value::String(proxy.group_name.clone()),
        );
        map.insert(
            "group_policy".to_owned(),
            serde_json::Value::String(proxy.group_policy.clone()),
        );
        map.insert(
            "node_tag".to_owned(),
            serde_json::Value::String(proxy.node_tag.clone()),
        );
        map.insert(
            "protocol".to_owned(),
            serde_json::Value::String(proxy.protocol.to_owned()),
        );
        map.insert(
            "handler".to_owned(),
            serde_json::Value::String(resident_udp_proxy_handler_name(proxy).to_owned()),
        );
        map.insert(
            "graphId".to_owned(),
            serde_json::Value::String(proxy.graph_id.clone()),
        );
        let packet_session = packet_session
            .map(UdpSessionKey::to_value)
            .unwrap_or_else(|| UdpSessionKey::new(proxy, peer, original_dst).to_value());
        map.insert("packetSession".to_owned(), packet_session);
    }
    event
}

fn udp_direct_route_chosen_event(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    key: &UdpDirectSessionKey,
    sniffed_domain: &str,
    dscp: u8,
    task_queued: bool,
    reason: &str,
) -> serde_json::Value {
    json!({
        "event": UDP_ROUTE_CHOSEN_EVENT,
        "outbound_kind": UDP_ROUTE_KIND_DIRECT,
        "peer": resident_socket_addr_display(peer),
        "original_dst": resident_socket_addr_display(original_dst),
        "direct_target": resident_socket_addr_display(original_dst),
        "initial_outbound": route.initial_outbound,
        "final_outbound": route.final_outbound,
        "final_mark": route.final_mark,
        "userspace_route_executed": route.userspace_route_executed,
        "userspace_route_must": route.userspace_route_must,
        "sniffed_domain": sniffed_domain,
        "network": resident_udp_network_name(original_dst),
        "outbound": UDP_ROUTE_KIND_DIRECT,
        "policy": UDP_ROUTE_POLICY_FIXED,
        "dialer": UDP_ROUTE_DIALER_DIRECT,
        "ip": resident_socket_addr_display(original_dst),
        "task_queued": task_queued,
        "reason": reason,
        "dscp": dscp,
        "packetSession": key.to_value(),
    })
}

#[cfg(test)]
fn udp_route_chosen_event_without_packet_session(
    peer: SocketAddr,
    original_dst: SocketAddr,
    route: &ResidentUdpRouteSelection,
    proxy: &ResidentProxyPlan,
    sniffed_domain: &str,
    dscp: u8,
    reason: &str,
) -> serde_json::Value {
    let mut event = udp_route_chosen_event(
        peer,
        original_dst,
        route,
        Some(proxy),
        None,
        sniffed_domain,
        dscp,
        false,
        reason,
    );
    if let Some(map) = event.as_object_mut() {
        map.remove("packetSession");
    }
    event
}

#[cfg(test)]
mod tests;
