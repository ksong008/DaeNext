use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ConnectUdpPoolClearReport {
    pub(in crate::production_runtime_owner::resident_dataplane) pools: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) connections: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) locked_pools: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) registry_locked: bool,
}

pub(in crate::production_runtime_owner::resident_dataplane) fn clear_connect_udp_h2_pools(
    _generation: u64,
) -> ConnectUdpPoolClearReport {
    ConnectUdpPoolClearReport::default()
}

pub(in crate::production_runtime_owner::resident_dataplane) fn clear_connect_udp_h3_pools(
    _generation: u64,
) -> ConnectUdpPoolClearReport {
    ConnectUdpPoolClearReport::default()
}

pub(in crate::production_runtime_owner::resident_dataplane) fn connect_udp_pool_metrics_snapshot(
    generation: u64,
) -> Value {
    json!({
        "schemaVersion": 1,
        "reloadGeneration": generation,
        "h2": { "poolCount": 0, "connectionCount": 0 },
        "h3": { "poolCount": 0, "connectionCount": 0 },
    })
}
