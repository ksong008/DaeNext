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
    pub(crate) dns_fast_path_concurrency: usize,
    pub(crate) dns_fast_path_queue_depth: usize,
    pub(crate) dns_udp_forwarder_queue_depth: usize,
    pub(crate) dns_udp_forwarder_pending_limit: usize,
    pub(crate) shutdown_timeout: Duration,
}

impl ResidentUdpRuntimeConfig {
    pub(crate) fn from_resources(
        generation: u64,
        resources: &ResidentRuntimeResourceConfig,
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
            dns_fast_path_concurrency: resources.dns_fast_path_concurrency.value().max(1),
            dns_fast_path_queue_depth: resources.dns_fast_path_queue_depth.value().max(1),
            dns_udp_forwarder_queue_depth: resources.dns_udp_forwarder_queue_depth.value().max(1),
            dns_udp_forwarder_pending_limit: resources
                .dns_udp_forwarder_pending_limit
                .value()
                .max(1)
                .min(u16::MAX as usize + 1),
            shutdown_timeout: RESIDENT_UDP_RESPONSE_TIMEOUT,
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
        self.session_limit
            .div_ceil(self.runtime_shards.max(1))
            .max(1)
    }

    pub(crate) fn resource_inventory(&self) -> Value {
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
            },
            "dnsFastPath": {
                "owner": "resident-dns-fast-path-dispatcher",
                "concurrency": self.dns_fast_path_concurrency,
                "queueDepth": self.dns_fast_path_queue_depth,
            },
            "dnsUdpForwarder": {
                "owner": "resident-dns-udp-forwarder-actors",
                "queueDepth": self.dns_udp_forwarder_queue_depth,
                "pendingLimit": self.dns_udp_forwarder_pending_limit,
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
            dns_fast_path_concurrency: 512,
            dns_fast_path_queue_depth: 1_024,
            dns_udp_forwarder_queue_depth: 1_024,
            dns_udp_forwarder_pending_limit: 1_024,
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
}
