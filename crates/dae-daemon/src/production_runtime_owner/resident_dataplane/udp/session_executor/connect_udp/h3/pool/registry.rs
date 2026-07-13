use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::key::ConnectUdpH3PoolKey;
use super::state::{ConnectUdpH3ActorLease, ConnectUdpH3Pool, ConnectUdpH3PoolSnapshot};
use super::*;

mod snapshot;

pub(in crate::production_runtime_owner::resident_dataplane) use self::snapshot::connect_udp_h3_pool_metrics_snapshot;

static CONNECT_UDP_H3_POOLS: OnceLock<Mutex<HashMap<ConnectUdpH3PoolKey, Arc<ConnectUdpH3Pool>>>> =
    OnceLock::new();

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) struct ConnectUdpH3PoolClearReport {
    pub(in crate::production_runtime_owner::resident_dataplane) pools: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) connections: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) locked_pools: usize,
    pub(in crate::production_runtime_owner::resident_dataplane) registry_locked: bool,
}

pub(in crate::production_runtime_owner::resident_dataplane::udp::session_executor::connect_udp::h3) async fn acquire_connect_udp_h3_actor(
    proxy: &ResidentProxyPlan,
) -> Result<ConnectUdpH3ActorLease, String> {
    let (key, runtime) = ConnectUdpH3PoolKey::from_proxy(proxy)?;
    let pool = {
        let mut pools = CONNECT_UDP_H3_POOLS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| "CONNECT-UDP H3 pool registry lock poisoned".to_owned())?;
        Arc::clone(
            pools
                .entry(key)
                .or_insert_with(|| Arc::new(ConnectUdpH3Pool::new(runtime))),
        )
    };
    pool.acquire(proxy, runtime).await
}

pub(in crate::production_runtime_owner::resident_dataplane) fn clear_connect_udp_h3_pools(
    generation: u64,
) -> ConnectUdpH3PoolClearReport {
    let Some(pools) = CONNECT_UDP_H3_POOLS.get() else {
        return ConnectUdpH3PoolClearReport::default();
    };
    let Ok(mut pools) = pools.lock() else {
        return ConnectUdpH3PoolClearReport {
            registry_locked: true,
            ..ConnectUdpH3PoolClearReport::default()
        };
    };
    let keys = pools
        .keys()
        .filter(|key| key.generation == generation)
        .cloned()
        .collect::<Vec<_>>();
    let removed = keys
        .into_iter()
        .filter_map(|key| pools.remove(&key))
        .collect::<Vec<_>>();
    drop(pools);
    let mut report = ConnectUdpH3PoolClearReport {
        pools: removed.len(),
        connections: 0,
        locked_pools: 0,
        registry_locked: false,
    };
    for pool in removed {
        match pool.close() {
            Ok(connections) => {
                report.connections = report.connections.saturating_add(connections);
            }
            Err(()) => report.locked_pools = report.locked_pools.saturating_add(1),
        }
    }
    report
}
