use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentUdpRuntimeConfig {
    pub(crate) generation: u64,
    pub(crate) profile: &'static str,
    pub(crate) session_limit: usize,
    pub(crate) session_queue_depth: usize,
    pub(crate) runtime_shards: usize,
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
        let runtime_shards = resources
            .udp_runtime_shards
            .value()
            .max(1)
            .min(session_limit);
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
                "globalSessionLimit": self.session_limit,
                "perSessionQueueDepth": self.session_queue_depth,
                "dispatchQueueDepth": self.dispatch_queue_depth,
                "perShardDispatchQueueDepth": self.per_shard_dispatch_queue_depth(),
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
        assert!(runtime.payload_pool_capacity() <= 1_024);
        assert_eq!(runtime.resource_inventory()["generation"], json!(9));
    }
}
