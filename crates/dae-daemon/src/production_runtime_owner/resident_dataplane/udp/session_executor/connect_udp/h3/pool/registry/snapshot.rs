use serde_json::{Value, json};

use super::*;

pub(in crate::production_runtime_owner::resident_dataplane) fn connect_udp_h3_pool_metrics_snapshot(
    generation: u64,
) -> Value {
    let Some(pools) = CONNECT_UDP_H3_POOLS.get() else {
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

    let mut aggregate = ConnectUdpH3PoolSnapshot::default();
    let mut locked_pools = 0_usize;
    for pool in &selected {
        let Ok(snapshot) = pool.snapshot() else {
            locked_pools = locked_pools.saturating_add(1);
            continue;
        };
        aggregate.accepting_actors = aggregate
            .accepting_actors
            .saturating_add(snapshot.accepting_actors);
        aggregate.retiring_actors = aggregate
            .retiring_actors
            .saturating_add(snapshot.retiring_actors);
        aggregate.active_sessions = aggregate
            .active_sessions
            .saturating_add(snapshot.active_sessions);
        aggregate.opening_actors = aggregate
            .opening_actors
            .saturating_add(snapshot.opening_actors);
        aggregate.command_queue_capacity = aggregate
            .command_queue_capacity
            .saturating_add(snapshot.command_queue_capacity);
        aggregate.command_queue_used = aggregate
            .command_queue_used
            .saturating_add(snapshot.command_queue_used);
        aggregate.negotiated_datagram_limit_min = match (
            aggregate.negotiated_datagram_limit_min,
            snapshot.negotiated_datagram_limit_min,
        ) {
            (Some(current), Some(value)) => Some(current.min(value)),
            (None, value) | (value, None) => value,
        };
        aggregate.negotiated_datagram_limit_max = match (
            aggregate.negotiated_datagram_limit_max,
            snapshot.negotiated_datagram_limit_max,
        ) {
            (Some(current), Some(value)) => Some(current.max(value)),
            (None, value) | (value, None) => value,
        };
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
        "transport": "h3-http-datagram",
        "reloadGeneration": generation,
        "poolCount": selected.len(),
        "acceptingActors": aggregate.accepting_actors,
        "retiringActors": aggregate.retiring_actors,
        "openingActors": aggregate.opening_actors,
        "activeSessions": aggregate.active_sessions,
        "commandQueueCapacity": aggregate.command_queue_capacity,
        "commandQueueUsed": aggregate.command_queue_used,
        "negotiatedDatagrams": aggregate.accepting_actors + aggregate.retiring_actors > 0,
        "negotiatedDatagramLimitMin": aggregate.negotiated_datagram_limit_min,
        "negotiatedDatagramLimitMax": aggregate.negotiated_datagram_limit_max,
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
        "transport": "h3-http-datagram",
        "reloadGeneration": generation,
        "poolCount": 0,
        "acceptingActors": 0,
        "retiringActors": 0,
        "openingActors": 0,
        "activeSessions": 0,
        "commandQueueCapacity": 0,
        "commandQueueUsed": 0,
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
