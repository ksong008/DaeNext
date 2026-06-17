use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use dae_control::{
    DomainRoutingOwner, DomainRoutingOwnerSnapshot, DomainRoutingReloadClearPlan,
    DomainRoutingSyncPlan, OutboundConnectivityOwner, OutboundConnectivityState,
};
use dae_datapath::{
    OUTBOUND_DIRECT, OUTBOUND_USER_DEFINED_MIN, TcpDialMode, choose_dial_target, magic_network_len,
    udp_endpoint_pool_trim_target, write_magic_network_bytes,
};
use dae_ebpf_support::{ConnectivityEvent, ConnectivityKey};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "control/magic_network_mark_mptcp",
            default_iters: 100_000,
            run: bench_magic_network_mark_mptcp,
        },
        BenchCase {
            id: "control/choose_dial_target_domain",
            default_iters: 100_000,
            run: bench_choose_dial_target_domain,
        },
        BenchCase {
            id: "control/choose_dial_target_domain_plus_plus",
            default_iters: 100_000,
            run: bench_choose_dial_target_domain_plus_plus,
        },
        BenchCase {
            id: "control/udp_endpoint_trim_target",
            default_iters: 100_000,
            run: bench_udp_endpoint_trim_target,
        },
        BenchCase {
            id: "control/outbound_connectivity_state_stable",
            default_iters: 1_000_000,
            run: bench_outbound_connectivity_state_stable,
        },
        BenchCase {
            id: "control/outbound_connectivity_state_toggle",
            default_iters: 1_000_000,
            run: bench_outbound_connectivity_state_toggle,
        },
        BenchCase {
            id: "control/outbound_connectivity_owner_toggle",
            default_iters: 1_000_000,
            run: bench_outbound_connectivity_owner_toggle,
        },
        BenchCase {
            id: "control/domain_routing_owner_merge",
            default_iters: 100_000,
            run: bench_domain_routing_owner_merge,
        },
        BenchCase {
            id: "control/domain_routing_reload_clear",
            default_iters: 100_000,
            run: bench_domain_routing_reload_clear,
        },
        BenchCase {
            id: "control/domain_routing_reload_clear_plan",
            default_iters: 100_000,
            run: bench_domain_routing_reload_clear_plan,
        },
    ]
}

fn bench_magic_network_mark_mptcp(iters: u64, warmup: u64) -> Result<Measurement, String> {
    const TPROXY_MARK: u32 = 0x0800_0000;
    let mut network = Vec::with_capacity(magic_network_len("tcp", TPROXY_MARK, true));
    Ok(measure(
        || {
            network.clear();
            write_magic_network_bytes(black_box("tcp"), black_box(TPROXY_MARK), true, &mut network);
            black_box(network.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_choose_dial_target_domain(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443);
    Ok(measure(
        || {
            let decision = choose_dial_target(
                black_box(TcpDialMode::Ip),
                black_box(OUTBOUND_DIRECT),
                black_box(dest),
                black_box("example.com"),
                black_box(false),
            );
            black_box(decision.dial_target.len() as u64 ^ decision.dial_ip as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_choose_dial_target_domain_plus_plus(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
    Ok(measure(
        || {
            let decision = choose_dial_target(
                black_box(TcpDialMode::DomainPlusPlus),
                black_box(OUTBOUND_USER_DEFINED_MIN),
                black_box(dest),
                black_box("example.com"),
                black_box(true),
            );
            black_box(
                decision.dial_target.len() as u64
                    ^ ((decision.should_reroute as u64) << 8)
                    ^ decision.dial_ip as u64,
            )
        },
        iters,
        warmup,
    ))
}

fn bench_udp_endpoint_trim_target(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || black_box(udp_endpoint_pool_trim_target(black_box(4096)) as u64),
        iters,
        warmup,
    ))
}

fn bench_outbound_connectivity_state_stable(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let key = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };
    let mut state = OutboundConnectivityState::default();
    state.update(connectivity_event(key, true, true, false));
    Ok(measure(
        || {
            let update = state.update(connectivity_event(black_box(key), true, false, false));
            black_box(connectivity_update_checksum(update))
        },
        iters,
        warmup,
    ))
}

fn bench_outbound_connectivity_state_toggle(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let key = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };
    let mut state = OutboundConnectivityState::default();
    let mut alive = false;
    Ok(measure(
        || {
            alive = !alive;
            let update = state.update(connectivity_event(black_box(key), alive, false, false));
            black_box(connectivity_update_checksum(update))
        },
        iters,
        warmup,
    ))
}

fn bench_outbound_connectivity_owner_toggle(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let key = ConnectivityKey {
        outbound: 2,
        l4proto: 6,
        ipversion: 4,
    };
    let mut owner = OutboundConnectivityOwner::default();
    owner.install_map(1001);
    let mut alive = false;
    Ok(measure(
        || {
            alive = !alive;
            let update = owner.apply_event(connectivity_event(black_box(key), alive, false, false));
            black_box(connectivity_owner_update_checksum(update))
        },
        iters,
        warmup,
    ))
}

fn bench_domain_routing_owner_merge(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let owner_a = DomainRoutingOwnerSnapshot::new(&[0x3, 0x8], &["192.0.2.1", "2001:db8::1"]);
    let owner_b = DomainRoutingOwnerSnapshot::new(&[0x4], &["192.0.2.1", "198.51.100.7"]);
    Ok(measure(
        || {
            let mut owner = DomainRoutingOwner::default();
            let first = owner.apply_owner_snapshot_ref("a", black_box(&owner_a));
            let second = owner.apply_owner_snapshot_ref("b", black_box(&owner_b));
            let third = owner.apply_owner_snapshot("a", DomainRoutingOwnerSnapshot::default());
            black_box(
                domain_routing_plan_checksum(first.plan)
                    ^ domain_routing_plan_checksum(second.plan)
                    ^ domain_routing_plan_checksum(third.plan),
            )
        },
        iters,
        warmup,
    ))
}

fn bench_domain_routing_reload_clear(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let owner_a = DomainRoutingOwnerSnapshot::new(&[0x3, 0x8], &["192.0.2.1", "2001:db8::1"]);
    let stale_keys = owner_a.ips.to_vec();
    Ok(measure(
        || {
            let mut owner = DomainRoutingOwner::default();
            owner.install_map(1001);
            owner.apply_owner_snapshot_ref("a", black_box(&owner_a));
            let clear = owner.prepare_reload_map(1001, black_box(stale_keys.clone()));
            black_box(domain_routing_reload_clear_checksum(clear))
        },
        iters,
        warmup,
    ))
}

fn bench_domain_routing_reload_clear_plan(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let stale_keys = DomainRoutingOwnerSnapshot::new(&[0x3, 0x8], &["192.0.2.1", "2001:db8::1"])
        .ips
        .to_vec();
    Ok(measure(
        || {
            let mut owner = DomainRoutingOwner::default();
            owner.install_map(1001);
            let clear = owner.prepare_reload_map(1001, black_box(stale_keys.clone()));
            black_box(domain_routing_reload_clear_checksum(clear))
        },
        iters,
        warmup,
    ))
}

fn connectivity_event(
    key: ConnectivityKey,
    alive: bool,
    is_init: bool,
    dryrun: bool,
) -> ConnectivityEvent {
    ConnectivityEvent {
        key,
        alive,
        is_init,
        dryrun,
    }
}

fn connectivity_update_checksum(update: dae_control::ConnectivityStateUpdate) -> u64 {
    update.key.outbound as u64
        ^ ((update.key.l4proto as u64) << 8)
        ^ ((update.key.ipversion as u64) << 16)
        ^ ((update.value as u64) << 24)
        ^ ((update.accepted as u64) << 32)
        ^ ((update.changed as u64) << 33)
        ^ ((update.flush as u64) << 34)
        ^ ((update.len as u64) << 40)
}

fn connectivity_owner_update_checksum(update: dae_control::ConnectivityOwnerUpdate) -> u64 {
    connectivity_update_checksum(update.state)
        ^ ((update.map_id.unwrap_or_default() as u64) << 7)
        ^ ((update.flush as u64) << 39)
}

fn domain_routing_plan_checksum(plan: DomainRoutingSyncPlan) -> u64 {
    let mut checksum = ((plan.owner_count as u64) << 32) ^ ((plan.ip_count as u64) << 40);
    for entry in plan.updates {
        checksum ^= entry
            .key
            .iter()
            .fold(0_u64, |acc, word| acc ^ u64::from(*word));
        checksum ^= entry
            .bitmap
            .iter()
            .fold(0_u64, |acc, word| acc ^ u64::from(*word));
    }
    for key in plan.deletes {
        checksum ^= key.iter().fold(0_u64, |acc, word| acc ^ u64::from(*word)) << 16;
    }
    checksum
}

fn domain_routing_reload_clear_checksum(plan: DomainRoutingReloadClearPlan) -> u64 {
    let mut checksum = u64::from(plan.map_id)
        ^ ((plan.map_id_changed as u64) << 16)
        ^ ((plan.owner_count as u64) << 32)
        ^ ((plan.ip_count as u64) << 40);
    for key in plan.deletes {
        checksum ^= key.iter().fold(0_u64, |acc, word| acc ^ u64::from(*word)) << 8;
    }
    checksum
}
