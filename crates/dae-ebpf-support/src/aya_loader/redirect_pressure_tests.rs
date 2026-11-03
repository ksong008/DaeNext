//! Protocol isolation at both redirect lookup boundaries, with real kernel LRU.
use super::listener_lifecycle_tests::{bytes, load, loaded_with_profile, map_fd};
use super::*;
use crate::BpfMatchSet;
use crate::runtime_maps::update_map_elem_bytes;
use aya::programs::{TestRun, TestRunOptions};

fn run(loaded: &AyaUserspaceLoadedObject, name: &str, data: &[u8]) -> u32 {
    let mut context = [0u32; 12];
    context[10] = 1;
    let program: &SchedClassifier = loaded.ebpf.program(name).unwrap().try_into().unwrap();
    program
        .test_run(TestRunOptions {
            data_in: Some(data),
            ctx_in: Some(bytes(&context)),
            ..Default::default()
        })
        .unwrap()
        .return_value
}

fn packet(ipv6: bool, proto: u8) -> (Vec<u8>, Vec<u8>) {
    let (mut forward, mut reverse, _) = super::udp_direction_tests::flow(ipv6);
    for data in [&mut forward, &mut reverse] {
        data[if ipv6 { 20 } else { 23 }] = proto;
        if proto == 6 {
            let offset = if ipv6 { 54 } else { 34 };
            data[offset + 4..offset + 8].fill(0);
            data[offset + 12] = 0x50;
            data[offset + 13] = 2;
        }
    }
    (forward, reverse)
}

#[test]
fn low_memory_protocol_churn_cannot_evict_the_other_protocol_at_either_boundary() {
    for ipv6 in [false, true] {
        for churn_protocol in [6, 17] {
            let Some(mut loaded) =
                loaded_with_profile(None, Some(crate::RuntimeMapProfile::LowMemory))
            else {
                return;
            };
            for name in [
                "tproxy_lan_ingress_l2",
                "tproxy_dae0peer_ingress",
                "tproxy_dae0_ingress",
            ] {
                load(&mut loaded, name);
            }
            for name in ["redirect_track", "redirect_udp"] {
                assert_eq!(
                    crate::map_info(map_fd(&loaded, name)).unwrap().max_entries,
                    8192
                );
            }
            let fallback = BpfMatchSet {
                kind: crate::MATCH_TYPE_FALLBACK,
                outbound: 2,
                ..Default::default()
            };
            update_map_elem_bytes(
                map_fd(&loaded, "routing_map"),
                &0u32.to_ne_bytes(),
                bytes(&fallback),
            )
            .unwrap();
            let (tcp, tcp_reply) = packet(ipv6, 6);
            let (udp, udp_reply) = packet(ipv6, 17);
            for data in [&tcp, &udp] {
                assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", data), 7);
                assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", data), 2); // reaches unpublished listener
            }
            let (mut churn, _) = packet(ipv6, churn_protocol);
            // Exceed this redirect pool without exhausting the independent
            // 16384-entry UDP connection-state map used by UDP churn.
            for sequence in 0..12288u16 {
                let offset = if ipv6 { 36 } else { 28 };
                churn[offset..offset + 2].copy_from_slice(&(sequence + 256).to_be_bytes());
                assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", &churn), 7);
                assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", &churn), 2);
            }
            let (protected, protected_reply, evicted, evicted_reply) = if churn_protocol == 6 {
                (&udp, &udp_reply, &tcp, &tcp_reply)
            } else {
                (&tcp, &tcp_reply, &udp, &udp_reply)
            };
            assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", protected), 2);
            run(&loaded, "tproxy_dae0_ingress", protected_reply);
            let isolated = read_aya_tproxy_metrics(&loaded).unwrap();
            assert_eq!(isolated.redirect_peer_lookup_miss_total, 0);
            assert_eq!(isolated.redirect_return_lookup_miss_total, 0);
            // A pool can still evict its own protocol. Keep this limitation
            // explicit, and ensure both miss counters and repair still work.
            assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", evicted), 2);
            run(&loaded, "tproxy_dae0_ingress", evicted_reply);
            let pressure = read_aya_tproxy_metrics(&loaded).unwrap();
            assert_eq!(pressure.redirect_peer_lookup_miss_total, 1);
            assert_eq!(pressure.redirect_return_lookup_miss_total, 1);
            assert_eq!(pressure.redirect_track_update_failure_total, 0);
            assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", evicted), 7);
            assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", evicted), 2);
            let repaired = read_aya_tproxy_metrics(&loaded).unwrap();
            assert_eq!(repaired.redirect_peer_lookup_miss_total, 1);
            eprintln!(
                "ipv6={ipv6}, churn={churn_protocol}: isolated={isolated:?}, same-protocol pressure={pressure:?}"
            );
        }
    }
}

#[test]
fn redirect_pools_preserve_single_protocol_capacity_for_every_profile() {
    let Some(default) = loaded_with_profile(None, None) else {
        return;
    };
    for name in ["redirect_track", "redirect_udp"] {
        assert_eq!(
            crate::map_info(map_fd(&default, name)).unwrap().max_entries,
            65536
        );
    }
    drop(default);
    for (profile, capacity) in [
        (crate::RuntimeMapProfile::LowMemory, 8192),
        (crate::RuntimeMapProfile::Balanced, 32768),
        (crate::RuntimeMapProfile::HighPerformance, 65536),
    ] {
        for ipv6 in [false, true] {
            for protocol in [6, 17] {
                let mut loaded = loaded_with_profile(None, Some(profile)).unwrap();
                for name in [
                    "tproxy_lan_ingress_l2",
                    "tproxy_dae0peer_ingress",
                    "tproxy_dae0_ingress",
                ] {
                    load(&mut loaded, name);
                }
                for name in ["redirect_track", "redirect_udp"] {
                    let fd = map_fd(&loaded, name);
                    assert_eq!(crate::map_info(fd).unwrap().max_entries, capacity);
                    eprintln!(
                        "{profile:?} {name}: {}",
                        std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap()
                    );
                }
                let fallback = BpfMatchSet {
                    kind: crate::MATCH_TYPE_FALLBACK,
                    outbound: 2,
                    ..Default::default()
                };
                update_map_elem_bytes(
                    map_fd(&loaded, "routing_map"),
                    &0u32.to_ne_bytes(),
                    bytes(&fallback),
                )
                .unwrap();
                // Fit within the old pool with headroom, but exceed a half pool.
                // Delay every peer/return lookup until all entries are inserted.
                let count = capacity * 3 / 4;
                let (mut forward, mut reverse) = packet(ipv6, protocol);
                let source = if ipv6 { 36 } else { 28 };
                let destination = if ipv6 { 52 } else { 32 };
                for sequence in 0..count {
                    forward[source..source + 2]
                        .copy_from_slice(&((sequence + 256) as u16).to_be_bytes());
                    assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", &forward), 7);
                }
                for sequence in 0..count {
                    let address = ((sequence + 256) as u16).to_be_bytes();
                    forward[source..source + 2].copy_from_slice(&address);
                    reverse[destination..destination + 2].copy_from_slice(&address);
                    assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", &forward), 2);
                    run(&loaded, "tproxy_dae0_ingress", &reverse);
                }
                let metrics = read_aya_tproxy_metrics(&loaded).unwrap();
                assert_eq!(metrics.redirect_peer_lookup_miss_total, 0);
                assert_eq!(metrics.redirect_return_lookup_miss_total, 0);
                assert_eq!(metrics.redirect_track_update_failure_total, 0);
                assert_eq!(metrics.listener_not_ready_total, u64::from(count));
                eprintln!(
                    "{profile:?} ipv6={ipv6} protocol={protocol}: {count} delayed lookups preserved"
                );
            }
        }
    }
}
