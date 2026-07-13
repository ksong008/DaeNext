use serde_json::{Value, json};

use super::*;

pub(in crate::production_runtime_owner::resident_dataplane) fn connect_udp_h2_pool_metrics_snapshot(
    generation: u64,
) -> Value {
    let Some(pools) = CONNECT_UDP_H2_POOLS.get() else {
        return empty_snapshot(generation, false);
    };
    let selected = match pools.lock() {
        Ok(pools) => pools
            .iter()
            .filter(|(key, _)| key.generation == generation)
            .map(|(_, pool)| Arc::clone(pool))
            .collect::<Vec<_>>(),
        Err(_) => return empty_snapshot(generation, true),
    };

    let mut aggregate = ConnectUdpH2PoolSnapshot::default();
    let mut locked_pools = 0_usize;
    for pool in &selected {
        let Ok(snapshot) = pool.snapshot() else {
            locked_pools = locked_pools.saturating_add(1);
            continue;
        };
        aggregate.accepting_connections = aggregate
            .accepting_connections
            .saturating_add(snapshot.accepting_connections);
        aggregate.retiring_connections = aggregate
            .retiring_connections
            .saturating_add(snapshot.retiring_connections);
        aggregate.active_sessions = aggregate
            .active_sessions
            .saturating_add(snapshot.active_sessions);
        aggregate.opening_connections = aggregate
            .opening_connections
            .saturating_add(snapshot.opening_connections);
        aggregate.stream_capacity = aggregate
            .stream_capacity
            .saturating_add(snapshot.stream_capacity);
        aggregate.stream_slots_available = aggregate
            .stream_slots_available
            .saturating_add(snapshot.stream_slots_available);
        aggregate.events.connection_retirements = aggregate
            .events
            .connection_retirements
            .saturating_add(snapshot.events.connection_retirements);
        aggregate.events.goaway_events = aggregate
            .events
            .goaway_events
            .saturating_add(snapshot.events.goaway_events);
        aggregate.events.reset_events = aggregate
            .events
            .reset_events
            .saturating_add(snapshot.events.reset_events);
        aggregate.events.queue_full_events = aggregate
            .events
            .queue_full_events
            .saturating_add(snapshot.events.queue_full_events);
        aggregate.events.mtu_rejections = aggregate
            .events
            .mtu_rejections
            .saturating_add(snapshot.events.mtu_rejections);
    }

    json!({
        "transport": "h2-capsule",
        "reloadGeneration": generation,
        "poolCount": selected.len(),
        "acceptingConnections": aggregate.accepting_connections,
        "retiringConnections": aggregate.retiring_connections,
        "openingConnections": aggregate.opening_connections,
        "activeSessions": aggregate.active_sessions,
        "streamCapacity": aggregate.stream_capacity,
        "streamSlotsAvailable": aggregate.stream_slots_available,
        "negotiatedDatagrams": false,
        "negotiatedDatagramLimitMin": Value::Null,
        "negotiatedDatagramLimitMax": Value::Null,
        "connectionRetirements": aggregate.events.connection_retirements,
        "goawayEvents": aggregate.events.goaway_events,
        "resetEvents": aggregate.events.reset_events,
        "queueFullEvents": aggregate.events.queue_full_events,
        "mtuRejections": aggregate.events.mtu_rejections,
        "lockedPools": locked_pools,
        "registryLocked": false,
    })
}

fn empty_snapshot(generation: u64, registry_locked: bool) -> Value {
    json!({
        "transport": "h2-capsule",
        "reloadGeneration": generation,
        "poolCount": 0,
        "acceptingConnections": 0,
        "retiringConnections": 0,
        "openingConnections": 0,
        "activeSessions": 0,
        "streamCapacity": 0,
        "streamSlotsAvailable": 0,
        "negotiatedDatagrams": false,
        "negotiatedDatagramLimitMin": Value::Null,
        "negotiatedDatagramLimitMax": Value::Null,
        "connectionRetirements": 0,
        "goawayEvents": 0,
        "resetEvents": 0,
        "queueFullEvents": 0,
        "mtuRejections": 0,
        "lockedPools": 0,
        "registryLocked": registry_locked,
    })
}
