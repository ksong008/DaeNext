use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpRuntimeConfig {
    pub(crate) generation: u64,
    pub(crate) profile: &'static str,
    pub(crate) session_limit: usize,
    pub(crate) session_queue_depth: usize,
    pub(crate) runtime_shards: usize,
    pub(crate) runtime_worker_threads: usize,
    pub(crate) worker_stack_bytes: usize,
    pub(crate) dispatch_queue_depth: usize,
    pub(crate) ingress_drain_budget: usize,
    pub(crate) reply_queue_depth: usize,
    pub(crate) reply_socket_cache_capacity: usize,
    pub(crate) reply_socket_idle_timeout: Duration,
    pub(crate) direct_response_buffer_idle_timeout: Duration,
    pub(crate) payload_admission: ResidentUdpPayloadAdmission,
    pub(crate) dns_fast_path_concurrency: usize,
    pub(crate) dns_fast_path_queue_depth: usize,
    pub(crate) dns_udp_forwarder_queue_depth: usize,
    pub(crate) dns_udp_forwarder_pending_limit: usize,
    pub(crate) dns_udp_forwarder_attempts: usize,
    pub(crate) dns_proxy_udp_actor_limit: usize,
    pub(crate) shutdown_timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentDnsUdpRuntimeConfig {
    pub(crate) generation: u64,
    pub(crate) direct_shards: usize,
    pub(crate) proxy_actor_limit: usize,
    pub(crate) actor_worker_threads: usize,
    pub(crate) worker_stack_bytes: usize,
    pub(crate) queue_depth: usize,
    pub(crate) pending_limit: usize,
    pub(crate) attempts: usize,
    pub(crate) attempt_timeout: Duration,
    pub(crate) shutdown_timeout: Duration,
    pub(crate) payload_admission: ResidentUdpPayloadAdmission,
}

impl ResidentUdpRuntimeConfig {
    pub(crate) fn from_resources(
        generation: u64,
        resources: &ResidentRuntimeResourceConfig,
        payload_admission: ResidentUdpPayloadAdmission,
    ) -> Self {
        let session_limit = resources.udp_session_limit.value().max(1);
        let session_queue_depth = resources.udp_session_queue_depth.value().max(1);
        let requested_runtime_shards = resources
            .udp_runtime_shards
            .value()
            .max(1)
            .min(session_limit);
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let (runtime_shards, runtime_worker_threads) = resident_udp_runtime_topology(
            requested_runtime_shards,
            session_limit,
            available_parallelism,
        );
        let dispatch_queue_depth = resources
            .udp_dispatch_queue_depth
            .value()
            .max(runtime_shards);
        Self {
            generation,
            profile: resources.runtime_profile.profile.name(),
            session_limit,
            session_queue_depth,
            runtime_shards,
            runtime_worker_threads,
            worker_stack_bytes: resources.tcp_flow_stack_bytes.value(),
            dispatch_queue_depth,
            ingress_drain_budget: session_queue_depth,
            reply_queue_depth: dispatch_queue_depth,
            reply_socket_cache_capacity: session_limit,
            reply_socket_idle_timeout: resources
                .runtime_profile
                .profile
                .udp_reply_socket_idle_timeout(),
            direct_response_buffer_idle_timeout: resources
                .runtime_profile
                .profile
                .udp_direct_response_buffer_idle_timeout(),
            payload_admission,
            dns_fast_path_concurrency: resources.dns_fast_path_concurrency.value().max(1),
            dns_fast_path_queue_depth: resources.dns_fast_path_queue_depth.value().max(1),
            dns_udp_forwarder_queue_depth: resources.dns_udp_forwarder_queue_depth.value().max(1),
            dns_udp_forwarder_pending_limit: resources
                .dns_udp_forwarder_pending_limit
                .value()
                .max(1)
                .min(u16::MAX as usize + 1),
            dns_udp_forwarder_attempts: resources.dns_udp_forwarder_attempts.value().max(1),
            dns_proxy_udp_actor_limit: resources.dns_proxy_udp_actors.value().max(1),
            shutdown_timeout: RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
        }
    }

    pub(crate) fn payload_pool_capacity(&self) -> usize {
        self.session_limit
            .saturating_mul(self.session_queue_depth)
            .clamp(16, 1_024)
    }

    pub(crate) fn per_shard_dispatch_queue_depth(&self) -> usize {
        self.dispatch_queue_depth
            .div_ceil(self.runtime_shards.max(1))
            .max(1)
    }

    pub(crate) fn per_shard_cleanup_queue_depth(&self) -> usize {
        self.session_limit.max(1)
    }

    pub(crate) fn dns_udp_runtime_config(&self) -> ResidentDnsUdpRuntimeConfig {
        let direct_shards = self
            .runtime_shards
            .min(self.dns_udp_forwarder_queue_depth)
            .min(self.dns_udp_forwarder_pending_limit)
            .max(1);
        ResidentDnsUdpRuntimeConfig {
            generation: self.generation,
            direct_shards,
            proxy_actor_limit: self
                .dns_proxy_udp_actor_limit
                .min(self.dns_udp_forwarder_queue_depth)
                .min(self.dns_udp_forwarder_pending_limit)
                .max(1),
            actor_worker_threads: self.runtime_worker_threads.max(1),
            worker_stack_bytes: self.worker_stack_bytes,
            queue_depth: self.dns_udp_forwarder_queue_depth,
            pending_limit: self.dns_udp_forwarder_pending_limit,
            attempts: self.dns_udp_forwarder_attempts,
            attempt_timeout: resident_dns_udp_attempt_timeout(self.dns_udp_forwarder_attempts),
            shutdown_timeout: self.shutdown_timeout,
            payload_admission: self.payload_admission.clone(),
        }
    }

    pub(crate) fn resource_inventory(&self) -> Value {
        let dns_udp = self.dns_udp_runtime_config();
        json!({
            "schemaVersion": 1,
            "generation": self.generation,
            "profile": self.profile,
            "ingress": {
                "owner": "resident-udp-ingress",
                "drainBudget": self.ingress_drain_budget,
            },
            "sessionShards": {
                "owner": "resident-udp-session-shards",
                "count": self.runtime_shards,
                "workerThreads": self.runtime_worker_threads,
                "workerStackBytes": self.worker_stack_bytes,
                "globalSessionLimit": self.session_limit,
                "perSessionQueueDepth": self.session_queue_depth,
                "dispatchQueueDepth": self.dispatch_queue_depth,
                "perShardDispatchQueueDepth": self.per_shard_dispatch_queue_depth(),
                "perShardCleanupQueueDepth": self.per_shard_cleanup_queue_depth(),
                "affinity": "stable-session-hash",
            },
            "transparentReply": {
                "owner": "resident-udp-reply-actor",
                "queueDepth": self.reply_queue_depth,
                "socketCacheCapacity": self.reply_socket_cache_capacity,
                "socketIdleTimeoutMs": self.reply_socket_idle_timeout.as_millis(),
            },
            "queuedPayload": {
                "limitBytes": self.payload_admission.limit(),
            },
            "dnsFastPath": {
                "owner": "resident-dns-fast-path-dispatcher",
                "concurrency": self.dns_fast_path_concurrency,
                "queueDepth": self.dns_fast_path_queue_depth,
            },
            "dnsUdpForwarder": {
                "owner": "resident-dns-udp-forwarder-actors",
                "directActors": dns_udp.direct_shards,
                "proxyActorLimit": dns_udp.proxy_actor_limit,
                "actorWorkerThreads": self.runtime_worker_threads.max(1),
                "workerStackBytes": self.worker_stack_bytes,
                "queueDepth": self.dns_udp_forwarder_queue_depth,
                "pendingLimit": self.dns_udp_forwarder_pending_limit,
                "attempts": self.dns_udp_forwarder_attempts,
                "attemptTimeoutMs": resident_dns_udp_attempt_timeout(self.dns_udp_forwarder_attempts).as_millis(),
            },
            "deadlines": {
                "sessionIdleMs": RESIDENT_UDP_SESSION_IDLE_TIMEOUT.as_millis(),
                "dnsSessionIdleMs": RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT.as_millis(),
                "requestMs": RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis(),
                "shutdownMs": self.shutdown_timeout.as_millis(),
            },
        })
    }
}

impl ResidentDnsUdpRuntimeConfig {
    pub(crate) fn standalone() -> Self {
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let profile = ResidentRuntimeProfile::Balanced;
        let requested_shards = profile.udp_runtime_shards_default(available_parallelism);
        let (direct_shards, actor_worker_threads) =
            resident_udp_runtime_topology(requested_shards, usize::MAX, available_parallelism);
        Self {
            generation: 0,
            direct_shards,
            proxy_actor_limit: profile.dns_proxy_udp_actors_default(),
            actor_worker_threads: actor_worker_threads.max(1),
            worker_stack_bytes: RESIDENT_TCP_FLOW_STACK_BYTES_DEFAULT,
            queue_depth: profile.dns_udp_forwarder_queue_depth_default(),
            pending_limit: profile.dns_udp_forwarder_pending_limit_default(),
            attempts: profile.dns_udp_forwarder_attempts_default(),
            attempt_timeout: resident_dns_udp_attempt_timeout(
                profile.dns_udp_forwarder_attempts_default(),
            ),
            shutdown_timeout: RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
            payload_admission: ResidentUdpPayloadAdmission::new(
                0,
                profile.udp_queued_payload_bytes_default(),
            ),
        }
    }

    pub(crate) fn actor_partition(&self, actor_index: usize, actor_count: usize) -> Self {
        let actor_count = actor_count.max(1);
        let actor_index = actor_index.min(actor_count - 1);
        let mut partition = self.clone();
        partition.queue_depth = partitioned_resource(self.queue_depth, actor_index, actor_count);
        partition.pending_limit =
            partitioned_resource(self.pending_limit, actor_index, actor_count);
        partition
    }
}

fn partitioned_resource(total: usize, index: usize, partitions: usize) -> usize {
    let partitions = partitions.max(1).min(total.max(1));
    let index = index.min(partitions - 1);
    let base = total.max(1) / partitions;
    let remainder = total.max(1) % partitions;
    base.saturating_add(usize::from(index < remainder)).max(1)
}

fn resident_dns_udp_attempt_timeout(attempts: usize) -> Duration {
    let divisor = (attempts.max(1) as u128).saturating_add(1);
    let millis = RESIDENT_UDP_RESPONSE_TIMEOUT
        .as_millis()
        .saturating_div(divisor)
        .max(1);
    Duration::from_millis(millis.min(u128::from(u64::MAX)) as u64)
}

fn resident_udp_runtime_topology(
    requested_shards: usize,
    session_limit: usize,
    available_parallelism: usize,
) -> (usize, usize) {
    let available_parallelism = available_parallelism.max(1);
    let runtime_shards = requested_shards
        .max(1)
        .min(session_limit.max(1))
        .min(available_parallelism);
    let worker_threads = if runtime_shards > 1 {
        runtime_shards.min(available_parallelism.saturating_sub(1))
    } else {
        0
    };
    (runtime_shards, worker_threads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_runtime_config_bounds_shards_and_derived_queues() {
        let runtime = ResidentUdpRuntimeConfig {
            generation: 9,
            profile: "test",
            session_limit: 512,
            session_queue_depth: 128,
            runtime_shards: 4,
            runtime_worker_threads: 3,
            worker_stack_bytes: 512 * 1024,
            dispatch_queue_depth: 512,
            ingress_drain_budget: 128,
            reply_queue_depth: 512,
            reply_socket_cache_capacity: 512,
            reply_socket_idle_timeout: Duration::from_secs(180),
            direct_response_buffer_idle_timeout: Duration::from_secs(30),
            payload_admission: ResidentUdpPayloadAdmission::new(9, 32 * 1024 * 1024),
            dns_fast_path_concurrency: 512,
            dns_fast_path_queue_depth: 1_024,
            dns_udp_forwarder_queue_depth: 1_024,
            dns_udp_forwarder_pending_limit: 1_024,
            dns_udp_forwarder_attempts: 3,
            dns_proxy_udp_actor_limit: 8,
            shutdown_timeout: RESIDENT_UDP_RESPONSE_TIMEOUT,
        };
        assert!(runtime.runtime_shards >= 1);
        assert!(runtime.runtime_shards <= runtime.session_limit);
        assert!(runtime.per_shard_dispatch_queue_depth() >= 1);
        assert!(runtime.per_shard_cleanup_queue_depth() >= 1);
        assert!(runtime.payload_pool_capacity() <= 1_024);
        assert_eq!(runtime.resource_inventory()["generation"], json!(9));
    }

    #[test]
    fn udp_runtime_topology_keeps_single_core_single_owner() {
        assert_eq!(resident_udp_runtime_topology(8, 512, 1), (1, 0));
    }

    #[test]
    fn udp_runtime_topology_reserves_capacity_for_ingress_owner() {
        assert_eq!(resident_udp_runtime_topology(8, 512, 4), (4, 3));
        assert_eq!(resident_udp_runtime_topology(2, 1, 8), (1, 0));
    }

    #[test]
    fn dns_udp_runtime_config_comes_from_the_generation_resource_contract() {
        let runtime = ResidentUdpRuntimeConfig {
            generation: 12,
            profile: "test",
            session_limit: 64,
            session_queue_depth: 16,
            runtime_shards: 3,
            runtime_worker_threads: 2,
            worker_stack_bytes: 768 * 1024,
            dispatch_queue_depth: 96,
            ingress_drain_budget: 16,
            reply_queue_depth: 96,
            reply_socket_cache_capacity: 64,
            reply_socket_idle_timeout: Duration::from_secs(180),
            direct_response_buffer_idle_timeout: Duration::from_secs(30),
            payload_admission: ResidentUdpPayloadAdmission::new(12, 32 * 1024 * 1024),
            dns_fast_path_concurrency: 32,
            dns_fast_path_queue_depth: 64,
            dns_udp_forwarder_queue_depth: 80,
            dns_udp_forwarder_pending_limit: 72,
            dns_udp_forwarder_attempts: 4,
            dns_proxy_udp_actor_limit: 6,
            shutdown_timeout: Duration::from_millis(900),
        };
        let dns = runtime.dns_udp_runtime_config();
        assert_eq!(dns.generation, 12);
        assert_eq!(dns.direct_shards, 3);
        assert_eq!(dns.proxy_actor_limit, 6);
        assert_eq!(dns.actor_worker_threads, 2);
        assert_eq!(dns.queue_depth, 80);
        assert_eq!(dns.pending_limit, 72);
        assert_eq!(dns.attempts, 4);
        assert_eq!(dns.attempt_timeout, Duration::from_millis(1_600));
    }

    #[test]
    fn generation_resource_drain_finishes_before_the_owner_join_deadline() {
        assert!(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE < RESIDENT_RUNTIME_TASK_JOIN_GRACE);
    }

    #[test]
    fn dns_udp_actor_partitions_preserve_the_generation_limits() {
        let mut runtime = ResidentDnsUdpRuntimeConfig::standalone();
        runtime.queue_depth = 10;
        runtime.pending_limit = 7;
        let partitions = (0..3)
            .map(|index| runtime.actor_partition(index, 3))
            .collect::<Vec<_>>();
        assert_eq!(
            partitions
                .iter()
                .map(|item| item.queue_depth)
                .sum::<usize>(),
            10
        );
        assert_eq!(
            partitions
                .iter()
                .map(|item| item.pending_limit)
                .sum::<usize>(),
            7
        );
    }
}
