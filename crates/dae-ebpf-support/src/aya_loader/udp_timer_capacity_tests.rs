//! Distinguish deliberate full-table rejection from timer initialization races.
use super::listener_lifecycle_tests::{bytes, load, loaded_with_profile, map_fd, packet};
use super::*;
use aya::programs::{TestRun, TestRunOptions};
use std::time::{Duration, Instant};

#[test]
fn low_memory_udp_state_preserves_entries_until_ttl_and_recovers_full_capacity() {
    let idle_ns = std::env::var("DAE_TEST_UDP_IDLE_TIMEOUT_NS")
        .map_or(5_000_000_000, |value| value.parse::<u64>().unwrap());
    let Some(mut loaded) =
        loaded_with_profile(Some(idle_ns), Some(crate::RuntimeMapProfile::LowMemory))
    else {
        return;
    };
    let name = "tproxy_lan_ingress_l2";
    load(&mut loaded, name);
    let direct = crate::BpfMatchSet {
        kind: crate::MATCH_TYPE_FALLBACK,
        outbound: 0,
        ..Default::default()
    };
    crate::runtime_maps::update_map_elem_bytes(
        map_fd(&loaded, "routing_map"),
        &0_u32.to_ne_bytes(),
        bytes(&direct),
    )
    .unwrap();
    let state_fd = map_fd(&loaded, "udp_conn_state_map");
    let capacity = loaded
        .report
        .loaded_map_specs
        .iter()
        .find(|map| map.name == "udp_conn_state_map")
        .unwrap()
        .max_entries;
    assert_eq!(capacity, 16384);
    let program: &SchedClassifier = loaded.ebpf.program(name).unwrap().try_into().unwrap();
    let mut context = [0_u32; 12];
    context[10] = 1;
    let invoke = |index: u32| {
        let mut data = packet(17);
        data[34..36].copy_from_slice(&(1024 + index as u16).to_be_bytes());
        program
            .test_run(TestRunOptions {
                data_in: Some(&data),
                ctx_in: Some(bytes(&context)),
                ..Default::default()
            })
            .unwrap()
            .return_value
    };
    let started = Instant::now();
    for index in 0..capacity {
        assert_eq!(
            invoke(index),
            u32::MAX,
            "unexpected reject before full table at {index}"
        );
    }
    assert!(
        started.elapsed() < Duration::from_nanos(idle_ns),
        "fixture fill exceeded TTL"
    );
    assert_eq!(
        crate::count_map_entries_by_fd(state_fd).unwrap(),
        u64::from(capacity)
    );
    for index in capacity..capacity + 32 {
        assert_eq!(invoke(index), 2, "full table must fail closed");
    }
    for index in 0..64 {
        assert_eq!(
            invoke(index),
            u32::MAX,
            "full table rejected an existing flow"
        );
    }
    let metrics = read_aya_udp_state_metrics(&loaded).unwrap();
    assert_eq!(metrics.state_created_total, u64::from(capacity));
    assert_eq!(metrics.insert_failure_total, 32);
    assert_eq!(
        metrics.timer_init_failure_total
            + metrics.timer_callback_failure_total
            + metrics.timer_start_failure_total,
        0
    );
    let deadline = Instant::now() + Duration::from_nanos(idle_ns) + Duration::from_secs(5);
    while crate::count_map_entries_by_fd(state_fd).unwrap() != 0 {
        assert!(
            Instant::now() < deadline,
            "full UDP state table did not reclaim all timers"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        invoke(capacity),
        u32::MAX,
        "expired capacity was not reusable"
    );
    eprintln!(
        "LowMemory: {capacity} admitted, 32 deliberate full-table rejects, 64 existing refreshes, all expired, new flow admitted; TTL={idle_ns}ns"
    );
}
