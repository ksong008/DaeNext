//! Kernel LRU pressure exercises the two redirect lookup failure boundaries.
use super::listener_lifecycle_tests::{bytes, load, loaded_with_profile, map_fd, packet};
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

#[test]
fn low_memory_tcp_churn_exposes_both_udp_redirect_miss_counters() {
    let Some(mut loaded) = loaded_with_profile(None, Some(crate::RuntimeMapProfile::LowMemory))
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
    let tracking = map_fd(&loaded, "redirect_track");
    assert_eq!(crate::map_info(tracking).unwrap().max_entries, 8192);
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
    let udp = packet(17);
    assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", &udp), 7);
    // No published listener: peer must find the redirect entry and reach the
    // independent ready guard, rather than fail the tracking lookup.
    assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", &udp), 2);
    let initial = read_aya_tproxy_metrics(&loaded).unwrap();
    assert_eq!(initial.redirect_peer_lookup_miss_total, 0);
    assert_eq!(initial.listener_not_ready_total, 1);
    let mut tcp = packet(6);
    for sequence in 0..32768u32 {
        tcp[26..30].copy_from_slice(&[127, 1, (sequence >> 8) as u8, sequence as u8]);
        assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", &tcp), 7);
        assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", &tcp), 2);
    }
    // A suspended write->peer interval deliberately exposes the short race;
    // the same eviction also models a delayed upstream response interval.
    assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", &udp), 2);
    let mut reverse = udp.clone();
    reverse[26..30].copy_from_slice(&udp[30..34]);
    reverse[30..34].copy_from_slice(&udp[26..30]);
    reverse[34..36].copy_from_slice(&udp[36..38]);
    reverse[36..38].copy_from_slice(&udp[34..36]);
    assert_eq!(run(&loaded, "tproxy_dae0_ingress", &reverse), 0);
    let pressure = read_aya_tproxy_metrics(&loaded).unwrap();
    assert_eq!(pressure.redirect_peer_lookup_miss_total, 1);
    assert_eq!(pressure.redirect_return_lookup_miss_total, 1);
    assert_eq!(pressure.redirect_track_update_failure_total, 0);
    // A new client packet repairs the entry. It does not prove that earlier
    // responses were delivered or that sustained pressure loses only one.
    assert_eq!(run(&loaded, "tproxy_lan_ingress_l2", &udp), 7);
    assert_eq!(run(&loaded, "tproxy_dae0peer_ingress", &udp), 2);
    let repaired = read_aya_tproxy_metrics(&loaded).unwrap();
    assert_eq!(repaired.redirect_peer_lookup_miss_total, 1);
    assert_eq!(repaired.listener_not_ready_total, 32770);
    eprintln!(
        "LowMemory TCP churn: capacity=8192, TCP SYNs=32768, before={initial:?}, pressure={pressure:?}, repaired={repaired:?}"
    );
}
