use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectUdpPoolClearReport {
    pub pools: usize,
    pub connections: usize,
    pub locked_pools: usize,
    pub registry_locked: bool,
}

pub fn clear_connect_udp_h2_pools(_generation: u64) -> ConnectUdpPoolClearReport {
    ConnectUdpPoolClearReport::default()
}

pub fn clear_connect_udp_h3_pools(_generation: u64) -> ConnectUdpPoolClearReport {
    ConnectUdpPoolClearReport::default()
}

pub fn connect_udp_pool_metrics_snapshot(generation: u64) -> Value {
    json!({
        "schemaVersion": 1,
        "reloadGeneration": generation,
        "h2": { "poolCount": 0, "connectionCount": 0 },
        "h3": { "poolCount": 0, "connectionCount": 0 },
    })
}
