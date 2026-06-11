use super::*;
pub(crate) fn resource_pool_policy_json() -> Value {
    json!({
        "udpEndpoint": {
            "defaultMaxEntries": DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES,
            "trimTarget": udp_endpoint_pool_trim_target(DEFAULT_UDP_ENDPOINT_POOL_MAX_ENTRIES),
            "defaultNatTimeoutMs": DEFAULT_NAT_TIMEOUT_MS,
            "dnsNatTimeoutMs": DNS_NAT_TIMEOUT_MS,
            "anyfromTimeoutMs": ANYFROM_TIMEOUT_MS,
            "maxRetry": MAX_RETRY,
            "currentEntries": 0,
            "evictions": 0,
        },
        "udpTask": {
            "queueLength": UDP_TASK_QUEUE_LENGTH,
            "maxQueues": UDP_TASK_POOL_MAX_QUEUES,
            "currentQueues": 0,
            "dropTotal": 0,
        },
        "packetSniffer": {
            "ttlMs": PACKET_SNIFFER_TTL_MS,
            "maxEntries": PACKET_SNIFFER_POOL_MAX_ENTRIES,
            "currentEntries": 0,
            "evictions": 0,
        },
        "bufferPool": {
            "status": "planned",
            "maxClassBytes": 65536,
        }
    })
}
