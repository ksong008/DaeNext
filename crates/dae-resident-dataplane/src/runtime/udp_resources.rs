use super::*;

const RESIDENT_UDP_REPLY_SHARDS_MAX: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpRuntimeConfig {
    pub(crate) generation: u64,
    pub(crate) profile: &'static str,
    pub(crate) session_admission_limit: Option<usize>,
    pub(crate) session_soft_watermark: usize,
    pub(crate) session_queue_depth: usize,
    pub(crate) session_idle_timeout: Duration,
    pub(crate) proxy_session_idle_timeout: Duration,
    pub(crate) runtime_shards: usize,
    pub(crate) runtime_worker_threads: usize,
    pub(crate) worker_stack_bytes: usize,
    pub(crate) socket_buffer_bytes: usize,
    pub(crate) dispatch_queue_depth: usize,
    pub(crate) ingress_drain_budget: usize,
    pub(crate) ingress_syscall_batch_limit: usize,
    pub(crate) reply_queue_depth: usize,
    pub(crate) reply_send_batch_limit: usize,
    pub(crate) reply_socket_cache_capacity: usize,
    pub(crate) reply_socket_idle_timeout: Duration,
    pub(crate) direct_response_buffer_idle_timeout: Duration,
    pub(crate) payload_admission: ResidentUdpPayloadAdmission,
    pub(crate) dns_fast_path_concurrency: usize,
    pub(crate) dns_fast_path_queue_depth: usize,
    pub(crate) dns_udp_forwarder_queue_depth: usize,
    pub(crate) dns_udp_forwarder_pending_limit: usize,
    pub(crate) dns_udp_forwarder_inflight_window: usize,
    pub(crate) dns_udp_forwarder_attempts: usize,
    pub(crate) dns_udp_shard_idle_timeout: Duration,
    pub(crate) dns_proxy_udp_actor_limit: usize,
    pub(crate) shutdown_timeout: Duration,
}

impl ResidentUdpRuntimeConfig {
    pub(crate) fn from_resources(
        generation: u64,
        resources: &ResidentRuntimeResourceConfig,
        payload_admission: ResidentUdpPayloadAdmission,
    ) -> Self {
        let session_soft_watermark = resources.udp_session_limit.value().max(1);
        let session_admission_limit = resources.udp_session_limit.explicit_value();
        let session_queue_depth = resources.udp_session_queue_depth.value().max(1);
        let requested_runtime_shards = resources.udp_runtime_shards.value().max(1);
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let (runtime_shards, runtime_worker_threads) =
            resident_udp_runtime_topology(requested_runtime_shards, available_parallelism);
        let dispatch_queue_depth = resources
            .udp_dispatch_queue_depth
            .value()
            .max(runtime_shards);
        let runtime_profile = resources.runtime_profile.profile;
        Self {
            generation,
            profile: runtime_profile.name(),
            session_admission_limit,
            session_soft_watermark,
            session_queue_depth,
            session_idle_timeout: runtime_profile.udp_session_idle_timeout(),
            proxy_session_idle_timeout: runtime_profile.udp_proxy_session_idle_timeout(),
            runtime_shards,
            runtime_worker_threads,
            worker_stack_bytes: resources.tcp_flow_stack_bytes.value(),
            socket_buffer_bytes: resources.udp_socket_buffer_bytes.value(),
            dispatch_queue_depth,
            ingress_drain_budget: session_queue_depth,
            ingress_syscall_batch_limit: runtime_profile.udp_syscall_batch_limit(),
            reply_queue_depth: dispatch_queue_depth,
            reply_send_batch_limit: runtime_profile.udp_syscall_batch_limit(),
            reply_socket_cache_capacity: session_admission_limit.unwrap_or(session_soft_watermark),
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
            dns_udp_forwarder_inflight_window: runtime_profile
                .dns_udp_forwarder_inflight_window_default(),
            dns_udp_forwarder_attempts: resources.dns_udp_forwarder_attempts.value().max(1),
            dns_udp_shard_idle_timeout: runtime_profile.dns_udp_shard_idle_timeout(),
            dns_proxy_udp_actor_limit: resources.dns_proxy_udp_actors.value().max(1),
            shutdown_timeout: RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
        }
    }

    pub(crate) fn payload_pool_capacity(&self) -> usize {
        self.session_soft_watermark
            .saturating_mul(self.session_queue_depth)
            .clamp(16, 1_024)
    }

    pub(crate) fn per_shard_dispatch_queue_depth(&self) -> usize {
        self.dispatch_queue_depth
            .div_ceil(self.runtime_shards.max(1))
            .max(1)
    }

    pub(crate) fn per_shard_cleanup_queue_depth(&self) -> usize {
        self.session_soft_watermark.max(1)
    }

    pub(crate) fn reply_shards(&self) -> usize {
        self.runtime_shards
            .min(RESIDENT_UDP_REPLY_SHARDS_MAX)
            .min(self.reply_queue_depth)
            .min(self.reply_socket_cache_capacity)
            .max(1)
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
            worker_stack_bytes: self
                .worker_stack_bytes
                .max(RESIDENT_DNS_TRANSPORT_WORKER_STACK_BYTES_MIN),
            socket_buffer_bytes: self.socket_buffer_bytes,
            queue_depth: self.dns_udp_forwarder_queue_depth,
            pending_limit: self.dns_udp_forwarder_pending_limit,
            inflight_window: self
                .dns_udp_forwarder_inflight_window
                .min(self.dns_udp_forwarder_pending_limit)
                .max(1),
            send_batch_limit: self.ingress_syscall_batch_limit,
            attempts: self.dns_udp_forwarder_attempts,
            attempt_timeout: ResidentDnsUdpRuntimeConfig::attempt_timeout_for(
                self.dns_udp_forwarder_attempts,
            ),
            shard_idle_timeout: self.dns_udp_shard_idle_timeout,
            actor_idle_timeout: None,
            shutdown_timeout: self.shutdown_timeout,
            payload_admission: self.payload_admission.clone(),
        }
    }

    pub(crate) fn resource_inventory(&self) -> Value {
        let dns_udp = self.dns_udp_runtime_config();
        json!({
            "schemaVersion": 2,
            "generation": self.generation,
            "profile": self.profile,
            "ingress": {
                "owner": "resident-udp-ingress",
                "drainBudget": self.ingress_drain_budget,
                "syscallBatchLimit": self.ingress_syscall_batch_limit,
            },
            "sessionShards": {
                "owner": "resident-udp-session-shards",
                "count": self.runtime_shards,
                "workerThreads": self.runtime_worker_threads,
                "workerStackBytes": self.worker_stack_bytes,
                "sessionAdmission": {
                    "mode": if self.session_admission_limit.is_some() { "fixed" } else { "automatic" },
                    "fixedLimit": self.session_admission_limit,
                    "softWatermark": self.session_soft_watermark,
                },
                "perSessionQueueDepth": self.session_queue_depth,
                "dispatchQueueDepth": self.dispatch_queue_depth,
                "perShardDispatchQueueDepth": self.per_shard_dispatch_queue_depth(),
                "perShardCleanupQueueDepth": self.per_shard_cleanup_queue_depth(),
                "affinity": "stable-session-hash",
            },
            "transparentReply": {
                "owner": "resident-udp-reply-shards",
                "shards": self.reply_shards(),
                "queueDepth": self.reply_queue_depth,
                "socketCacheCapacity": self.reply_socket_cache_capacity,
                "socketIdleTimeoutMs": self.reply_socket_idle_timeout.as_millis(),
                "sendBatchLimit": self.reply_send_batch_limit,
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
                "inflightWindow": self.dns_udp_forwarder_inflight_window,
                "sendBatchLimit": dns_udp.send_batch_limit,
                "attempts": self.dns_udp_forwarder_attempts,
                "attemptTimeoutMs": ResidentDnsUdpRuntimeConfig::attempt_timeout_for(self.dns_udp_forwarder_attempts).as_millis(),
                "shardIdleTimeoutMs": dns_udp.shard_idle_timeout.as_millis(),
            },
            "deadlines": {
                "sessionIdleMs": self.session_idle_timeout.as_millis(),
                "proxySessionIdleMs": self.proxy_session_idle_timeout.as_millis(),
                "dnsSessionIdleMs": RESIDENT_UDP_DNS_SESSION_IDLE_TIMEOUT.as_millis(),
                "requestMs": RESIDENT_UDP_RESPONSE_TIMEOUT.as_millis(),
                "shutdownMs": self.shutdown_timeout.as_millis(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_runtime_config_bounds_shards_and_derived_queues() {
        let runtime = ResidentUdpRuntimeConfig {
            generation: 9,
            profile: "test",
            session_admission_limit: None,
            session_soft_watermark: 512,
            session_queue_depth: 128,
            session_idle_timeout: Duration::from_secs(120),
            proxy_session_idle_timeout: Duration::from_secs(120),
            runtime_shards: 4,
            runtime_worker_threads: 3,
            worker_stack_bytes: 512 * 1024,
            socket_buffer_bytes: 4 * 1024 * 1024,
            dispatch_queue_depth: 512,
            ingress_drain_budget: 128,
            ingress_syscall_batch_limit: 16,
            reply_queue_depth: 512,
            reply_send_batch_limit: 16,
            reply_socket_cache_capacity: 512,
            reply_socket_idle_timeout: Duration::from_secs(180),
            direct_response_buffer_idle_timeout: Duration::from_secs(30),
            payload_admission: ResidentUdpPayloadAdmission::new(9, 32 * 1024 * 1024),
            dns_fast_path_concurrency: 512,
            dns_fast_path_queue_depth: 1_024,
            dns_udp_forwarder_queue_depth: 1_024,
            dns_udp_forwarder_pending_limit: 1_024,
            dns_udp_forwarder_inflight_window: 64,
            dns_udp_forwarder_attempts: 3,
            dns_udp_shard_idle_timeout: Duration::from_secs(30),
            dns_proxy_udp_actor_limit: 8,
            shutdown_timeout: RESIDENT_UDP_RESPONSE_TIMEOUT,
        };
        assert!(runtime.runtime_shards >= 1);
        assert!(runtime.per_shard_dispatch_queue_depth() >= 1);
        assert!(runtime.per_shard_cleanup_queue_depth() >= 1);
        assert!(runtime.payload_pool_capacity() <= 1_024);
        assert_eq!(runtime.resource_inventory()["generation"], json!(9));
    }

    #[test]
    fn default_session_admission_is_automatic_and_keeps_bounded_derived_resources() {
        let sections = dae_config::parser::parse_config(
            "global {}\nnode {}\ngroup {}\nrouting { fallback: direct }\ndns {}",
        )
        .unwrap();
        let config = dae_config::schema::build_config(&sections).unwrap();
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let runtime = ResidentUdpRuntimeConfig::from_resources(
            9,
            &resources,
            ResidentUdpPayloadAdmission::new(9, 32 * 1024 * 1024),
        );

        assert_eq!(runtime.session_admission_limit, None);
        assert!(runtime.session_soft_watermark >= 1);
        assert!(runtime.proxy_session_idle_timeout >= runtime.session_idle_timeout);
        assert_eq!(
            runtime.reply_socket_cache_capacity,
            runtime.session_soft_watermark
        );
        assert_eq!(
            runtime.resource_inventory()["sessionShards"]["sessionAdmission"]["mode"],
            "automatic"
        );
        assert_eq!(
            runtime.resource_inventory()["sessionShards"]["sessionAdmission"]["fixedLimit"],
            Value::Null
        );
    }

    #[test]
    fn configured_session_limit_sizes_fixed_admission_and_reply_socket_cache() {
        let sections = dae_config::parser::parse_config(
            "global {}\nnode {}\ngroup {}\nrouting { fallback: direct }\ndns {}",
        )
        .unwrap();
        let mut config = dae_config::schema::build_config(&sections).unwrap();
        config.global.resident_udp_session_limit = Some(4_096);
        let resources = ResidentRuntimeResourceConfig::from_config(&config);
        let runtime = ResidentUdpRuntimeConfig::from_resources(
            9,
            &resources,
            ResidentUdpPayloadAdmission::new(9, 32 * 1024 * 1024),
        );

        assert_eq!(runtime.session_admission_limit, Some(4_096));
        assert_eq!(runtime.reply_socket_cache_capacity, 4_096);
        assert_eq!(
            runtime.resource_inventory()["sessionShards"]["sessionAdmission"]["fixedLimit"],
            4_096
        );
        assert_eq!(
            runtime.resource_inventory()["transparentReply"]["socketCacheCapacity"],
            4_096
        );
    }

    #[test]
    fn udp_runtime_topology_keeps_single_core_single_owner() {
        assert_eq!(resident_udp_runtime_topology(8, 1), (1, 0));
    }

    #[test]
    fn udp_runtime_topology_reserves_capacity_for_ingress_owner() {
        assert_eq!(resident_udp_runtime_topology(8, 4), (4, 3));
        assert_eq!(resident_udp_runtime_topology(2, 8), (2, 2));
    }

    #[test]
    fn dns_udp_runtime_config_comes_from_the_generation_resource_contract() {
        let runtime = ResidentUdpRuntimeConfig {
            generation: 12,
            profile: "test",
            session_admission_limit: Some(64),
            session_soft_watermark: 64,
            session_queue_depth: 16,
            session_idle_timeout: Duration::from_secs(120),
            proxy_session_idle_timeout: Duration::from_secs(120),
            runtime_shards: 3,
            runtime_worker_threads: 2,
            worker_stack_bytes: 768 * 1024,
            socket_buffer_bytes: 4 * 1024 * 1024,
            dispatch_queue_depth: 96,
            ingress_drain_budget: 16,
            ingress_syscall_batch_limit: 8,
            reply_queue_depth: 96,
            reply_send_batch_limit: 8,
            reply_socket_cache_capacity: 64,
            reply_socket_idle_timeout: Duration::from_secs(180),
            direct_response_buffer_idle_timeout: Duration::from_secs(30),
            payload_admission: ResidentUdpPayloadAdmission::new(12, 32 * 1024 * 1024),
            dns_fast_path_concurrency: 32,
            dns_fast_path_queue_depth: 64,
            dns_udp_forwarder_queue_depth: 80,
            dns_udp_forwarder_pending_limit: 72,
            dns_udp_forwarder_inflight_window: 24,
            dns_udp_forwarder_attempts: 4,
            dns_udp_shard_idle_timeout: Duration::from_secs(30),
            dns_proxy_udp_actor_limit: 6,
            shutdown_timeout: Duration::from_millis(900),
        };
        let dns = runtime.dns_udp_runtime_config();
        assert_eq!(dns.generation, 12);
        assert_eq!(dns.direct_shards, 3);
        assert_eq!(dns.proxy_actor_limit, 6);
        assert_eq!(dns.actor_worker_threads, 2);
        assert_eq!(
            dns.worker_stack_bytes,
            RESIDENT_DNS_TRANSPORT_WORKER_STACK_BYTES_MIN
        );
        assert_eq!(dns.queue_depth, 80);
        assert_eq!(dns.pending_limit, 72);
        assert_eq!(dns.inflight_window, 24);
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
        runtime.inflight_window = 5;
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
        assert_eq!(
            partitions
                .iter()
                .map(|item| item.inflight_window)
                .sum::<usize>(),
            5
        );
    }
}
