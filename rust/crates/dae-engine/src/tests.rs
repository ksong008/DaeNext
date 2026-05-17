use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use dae_config::DynamicFunctionValue;
use serde_json::Value;

use crate::*;

#[test]
fn dry_runtime_matches_golden_fixture() {
    let fixture = load("engine/dry_runtime/reload_stop.json");
    let timeout_ms = fixture["before_run_reload"]["context_timeout_ms"]
        .as_u64()
        .unwrap();
    let engine = Engine::new(EngineOptions::default());
    let err = engine
        .reload_with_timeout(Duration::from_millis(timeout_ms))
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        fixture["before_run_reload"]["error"].as_str().unwrap()
    );

    let engine = Arc::new(Engine::new(EngineOptions::default()));
    let runner = Arc::clone(&engine);
    let handle = std::thread::spawn(move || runner.run(true));
    assert!(engine.reload_with_timeout(Duration::from_secs(1)).is_ok());
    assert!(engine.stop(Duration::from_secs(1)).is_ok());
    assert!(handle.join().unwrap().is_ok());
}

#[test]
fn route_aware_target_matches_golden_fixture() {
    let fixture = load("engine/route_aware/target.json");
    for case in fixture["cases"].as_array().unwrap() {
        let got = route_aware_dial_target(
            case["host"].as_str().unwrap(),
            case["port"].as_str().unwrap(),
        );
        if case["ok"].as_bool().unwrap() {
            let got = got.unwrap();
            assert_eq!(got.domain, case["domain"].as_str().unwrap());
            assert_eq!(got.dest.to_string(), case["dest"].as_str().unwrap());
            assert_eq!(
                got.dest_is_unspecified(),
                case["dest_is_unspecified"].as_bool().unwrap()
            );
        } else {
            assert_eq!(
                got.unwrap_err().to_string(),
                case["error"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn runtime_overview_matches_golden_fixture() {
    let fixture = load("engine/runtime_overview/basic.json");
    let no_control = &fixture["no_control_plane"];
    let snapshot = snapshot_from_fixture(no_control);
    let overview = RuntimeOverview::from_snapshot(snapshot, None);
    assert_eq!(
        overview.upload_rate,
        no_control["upload_rate"].as_u64().unwrap()
    );
    assert_eq!(
        overview.dns.dns_cache_hit_total,
        no_control["dns_cache_hit_total"].as_u64().unwrap()
    );
    assert_eq!(overview.samples.len(), 1);
    assert_eq!(
        overview.samples[0].upload_rate,
        no_control["samples"][0]["upload_rate"].as_u64().unwrap()
    );

    let scoped = &fixture["scoped_udp_task_pool"];
    let snapshot = RuntimeStatsSnapshot {
        udp_task_queues: scoped["snapshot_queue_input"].as_i64().unwrap() as i32,
        udp_task_drop_total: scoped["snapshot_drop_input"].as_u64().unwrap(),
        packet_sniffer_sessions: scoped["packet_sniffer_kept"].as_i64().unwrap() as i32,
        ..RuntimeStatsSnapshot::default()
    };
    let overview = RuntimeOverview::from_snapshot(
        snapshot,
        Some((
            scoped["udp_task_queues"].as_i64().unwrap() as i32,
            scoped["udp_task_drop_total"].as_u64().unwrap(),
        )),
    );
    assert_eq!(
        overview.udp_task_queues,
        scoped["udp_task_queues"].as_i64().unwrap() as i32
    );
    assert_eq!(
        overview.udp_task_drop_total,
        scoped["udp_task_drop_total"].as_u64().unwrap()
    );
    assert_eq!(
        overview.packet_sniffer_sessions,
        scoped["packet_sniffer_kept"].as_i64().unwrap() as i32
    );
}

#[test]
fn config_api_matches_golden_fixture() {
    let fixture = load("engine/config_api/empty_parse.json");
    let empty_fixture = &fixture["empty_config"];
    let empty = empty_config().unwrap();
    assert_eq!(
        empty.global.log_level,
        empty_fixture["log_level"].as_str().unwrap()
    );
    assert_eq!(
        empty.global.fallback_resolver,
        empty_fixture["fallback_resolver"].as_str().unwrap()
    );
    assert_eq!(
        empty.global.udp_endpoint_pool_size,
        empty_fixture["udp_endpoint_pool_size"].as_i64().unwrap() as i32
    );

    let parse_fixture = &fixture["parse_config"];
    let parsed = parse_config_sections(
        Some(parse_fixture["global_input"].as_str().unwrap()),
        None,
        Some(parse_fixture["routing_input"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(
        parsed.global.log_level,
        parse_fixture["log_level"].as_str().unwrap()
    );
    assert_eq!(
        parsed.global.udp_endpoint_pool_size,
        parse_fixture["udp_pool_size"].as_i64().unwrap() as i32
    );
    assert_eq!(
        necessary_outbounds(&parsed.routing),
        parse_fixture["necessary_outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        parsed.routing.rules[0].outbound.name,
        parse_fixture["first_rule_outbound"]["name"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        parsed.routing.rules[1].outbound.name,
        parse_fixture["second_rule_outbound"]["name"]
            .as_str()
            .unwrap()
    );
    match &parsed.routing.fallback {
        DynamicFunctionValue::Function(function) => {
            assert_eq!(
                function.name,
                parse_fixture["fallback"]["name"].as_str().unwrap()
            );
            assert_eq!(function.params[0].val, "must");
        }
        other => panic!("fallback should be a function, got {other:?}"),
    }
}

#[test]
fn subscription_persist_cleanup_matches_golden_fixture() {
    let fixture = load("engine/subscription/persist_cleanup.json");
    assert_eq!(
        SUBSCRIPTION_RESOLVE_CONCURRENCY,
        fixture["concurrency_limit"].as_u64().unwrap() as usize
    );
    let tree = TempTree::new("dae-engine-subscription-cleanup");
    let persist_dir = tree.path("persist.d");
    fs::create_dir_all(&persist_dir).unwrap();
    for file in fixture["input_files"].as_array().unwrap() {
        fs::write(persist_dir.join(file.as_str().unwrap()), "payload").unwrap();
    }
    let active = fixture["active_tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<HashSet<_>>();
    let remaining = cleanup_subscription_persist_files(tree.root(), &active).unwrap();
    assert_eq!(
        remaining,
        fixture["remaining_files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    let missing = cleanup_subscription_persist_files(tree.path("missing"), &HashSet::new());
    assert!(missing.unwrap().is_empty());
}

fn snapshot_from_fixture(value: &Value) -> RuntimeStatsSnapshot {
    RuntimeStatsSnapshot {
        updated_at_unix: value["updated_at_unix"].as_i64().unwrap(),
        upload_rate: value["upload_rate"].as_u64().unwrap(),
        download_rate: value["download_rate"].as_u64().unwrap(),
        upload_total: value["upload_total"].as_u64().unwrap(),
        download_total: value["download_total"].as_u64().unwrap(),
        active_connections: value["active_connections"].as_i64().unwrap() as i32,
        udp_sessions: value["udp_sessions"].as_i64().unwrap() as i32,
        udp_task_queues: value["udp_task_queues"].as_i64().unwrap() as i32,
        udp_task_drop_total: value["udp_task_drop_total"].as_u64().unwrap(),
        packet_sniffer_sessions: value["packet_sniffer_sessions"].as_i64().unwrap() as i32,
        rss_bytes: value["rss_bytes"].as_u64().unwrap(),
        heap_alloc_bytes: value["heap_alloc_bytes"].as_u64().unwrap(),
        goroutines: value["goroutines"].as_i64().unwrap() as i32,
        dns: DnsObservabilityStats {
            dns_cache_hit_total: value["dns_cache_hit_total"].as_u64().unwrap(),
            dns_cache_expired_removal_total: value["dns_cache_expired_removal_total"]
                .as_u64()
                .unwrap(),
            dns_udp_retry_total: value["dns_udp_retry_total"].as_u64().unwrap(),
            dns_truncated_tcp_fallback_total: value["dns_truncated_tcp_fallback_total"]
                .as_u64()
                .unwrap(),
            dns_doh_status_failure_total: value["dns_doh_status_failure_total"].as_u64().unwrap(),
            dns_doh_content_type_failure_total: value["dns_doh_content_type_failure_total"]
                .as_u64()
                .unwrap(),
            dns_upstream_refresh_success_total: value["dns_upstream_refresh_success_total"]
                .as_u64()
                .unwrap(),
            dns_upstream_refresh_failure_total: value["dns_upstream_refresh_failure_total"]
                .as_u64()
                .unwrap(),
            dns_upstream_refresh_stale_reuse_total: value["dns_upstream_refresh_stale_reuse_total"]
                .as_u64()
                .unwrap(),
        },
        samples: value["samples"]
            .as_array()
            .unwrap()
            .iter()
            .map(|sample| RuntimeTrafficSample {
                timestamp_unix: sample["timestamp_unix"].as_i64().unwrap(),
                upload_rate: sample["upload_rate"].as_u64().unwrap(),
                download_rate: sample["download_rate"].as_u64().unwrap(),
            })
            .collect(),
    }
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

struct TempTree {
    root: std::path::PathBuf,
}

impl TempTree {
    fn new(prefix: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn root(&self) -> &std::path::Path {
        &self.root
    }

    fn path(&self, rel: &str) -> std::path::PathBuf {
        self.root.join(rel)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
