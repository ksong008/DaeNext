use std::collections::HashSet;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use dae_engine::{
    DnsObservabilityStats, RuntimeOverview, RuntimeStatsSnapshot, RuntimeTrafficSample,
    cleanup_subscription_persist_files, parse_config_sections, route_aware_dial_target,
};

fn main() {
    let iters = std::env::var("DAE_STAGE6_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100_000);
    bench_route_aware_target(iters);
    bench_runtime_overview(iters);
    bench_parse_config_api(iters);

    let cleanup_iters = std::env::var("DAE_STAGE6_CLEANUP_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000);
    bench_subscription_persist_cleanup(cleanup_iters);
}

fn bench_route_aware_target(iters: usize) {
    let started = Instant::now();
    for _ in 0..iters {
        let target = route_aware_dial_target(black_box("example.com"), black_box("443")).unwrap();
        black_box(target);
    }
    print_ns("engine_route_aware_target_domain", started, iters);
}

fn bench_runtime_overview(iters: usize) {
    let snapshot = RuntimeStatsSnapshot {
        updated_at_unix: 1_700_000_300,
        upload_rate: 10,
        download_rate: 20,
        upload_total: 30,
        download_total: 40,
        udp_task_queues: 99,
        udp_task_drop_total: 88,
        packet_sniffer_sessions: 77,
        dns: DnsObservabilityStats {
            dns_cache_hit_total: 101,
            dns_cache_expired_removal_total: 102,
            dns_udp_retry_total: 103,
            dns_truncated_tcp_fallback_total: 104,
            dns_doh_status_failure_total: 105,
            dns_doh_content_type_failure_total: 106,
            dns_upstream_refresh_success_total: 107,
            dns_upstream_refresh_failure_total: 108,
            dns_upstream_refresh_stale_reuse_total: 109,
        },
        samples: vec![RuntimeTrafficSample {
            timestamp_unix: 1_700_000_300,
            upload_rate: 11,
            download_rate: 22,
        }],
        ..RuntimeStatsSnapshot::default()
    };
    let started = Instant::now();
    for _ in 0..iters {
        let overview = RuntimeOverview::from_snapshot(black_box(snapshot.clone()), None);
        black_box(overview);
    }
    print_ns("engine_runtime_overview_no_control_plane", started, iters);
}

fn bench_parse_config_api(iters: usize) {
    let global = r#"global {
    log_level: debug
    udp_endpoint_pool_size: 8192
}"#;
    let routing = r#"routing {
    domain(suffix: example.com) -> must_proxy
    fallback: must_direct
}"#;
    let started = Instant::now();
    for _ in 0..iters {
        let config = parse_config_sections(Some(global), None, Some(routing)).unwrap();
        black_box(config);
    }
    print_ns("engine_parse_config_api", started, iters);
}

fn bench_subscription_persist_cleanup(iters: usize) {
    let active = HashSet::from(["active".to_owned()]);
    let root =
        std::env::temp_dir().join(format!("dae-fixture-cleanup-bench-{}", std::process::id()));
    let persist = root.join("persist.d");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&persist).unwrap();
    let started = Instant::now();
    for _ in 0..iters {
        fs::write(persist.join("active.sub"), "payload").unwrap();
        fs::write(persist.join("stale.sub"), "payload").unwrap();
        fs::write(persist.join("note.txt"), "payload").unwrap();
        let remaining = cleanup_subscription_persist_files(&root, &active).unwrap();
        black_box(remaining);
    }
    print_ns("engine_subscription_persist_cleanup", started, iters);
    let _ = fs::remove_dir_all(&root);
}

fn print_ns(name: &str, started: Instant, iters: usize) {
    let ns = started.elapsed().as_nanos() as f64 / iters as f64;
    println!("{name}: {ns:.1} ns/op ({iters} iters)");
}
