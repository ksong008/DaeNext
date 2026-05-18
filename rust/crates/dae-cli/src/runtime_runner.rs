use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use dae_engine::{
    DnsObservabilityStats, Engine, EngineOptions, RuntimeOverview, RuntimeStatsSnapshot,
    RuntimeTrafficSample, route_aware_dial_target,
};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;
use crate::runtime_host_preflight::run_stage22_host_preflight;
use crate::runtime_live_plan::run_stage22_live_plan;
use crate::runtime_stage26_candidate::run_stage26_candidate_plan;
use crate::runtime_stage27_candidate::run_stage27_candidate;

pub(crate) fn run_runtime(args: &[String]) -> RunnerOutput {
    match args.first().map(String::as_str) {
        Some("dry-run-smoke") => run_dry_run_smoke(),
        Some("route-target") => run_route_target(&args[1..]),
        Some("overview-basic") => run_overview_basic(),
        Some("stage22-smoke") => run_stage22_smoke(),
        Some("stage22-host-preflight") => run_stage22_host_preflight(&args[1..]),
        Some("stage22-live-plan") => run_stage22_live_plan(&args[1..]),
        Some("stage26-candidate-plan") => run_stage26_candidate_plan(&args[1..]),
        Some("stage27-run-candidate") => run_stage27_candidate(&args[1..]),
        Some(subcommand) => {
            RunnerOutput::usage(format!("unsupported runtime subcommand: {subcommand}"))
        }
        None => RunnerOutput::usage("missing runtime subcommand"),
    }
}

fn run_dry_run_smoke() -> RunnerOutput {
    let engine = Arc::new(Engine::new(EngineOptions::default()));
    let runner = Arc::clone(&engine);
    let handle = std::thread::spawn(move || runner.run(true));
    if let Err(err) = engine.reload_with_timeout(Duration::from_secs(1)) {
        return RunnerOutput::stdout_error(err.to_string());
    }
    if let Err(err) = engine.stop(Duration::from_secs(1)) {
        return RunnerOutput::stdout_error(err.to_string());
    }
    match handle.join() {
        Ok(Ok(())) => RunnerOutput::ok(String::new()),
        Ok(Err(err)) => RunnerOutput::stdout_error(err.to_string()),
        Err(_) => RunnerOutput::stdout_error("runtime thread panicked"),
    }
}

fn run_route_target(args: &[String]) -> RunnerOutput {
    let mut host = None;
    let mut port = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--host" => host = iter.next().map(String::as_str),
            "--port" => port = iter.next().map(String::as_str),
            _ if arg.starts_with("--host=") => {
                host = arg.split_once('=').map(|(_, value)| value);
            }
            _ if arg.starts_with("--port=") => {
                port = arg.split_once('=').map(|(_, value)| value);
            }
            _ => {
                return RunnerOutput::usage(format!(
                    "unsupported runtime route-target argument: {arg}"
                ));
            }
        }
    }
    let Some(host) = host else {
        return RunnerOutput::usage("missing runtime route-target --host");
    };
    let Some(port) = port else {
        return RunnerOutput::usage("missing runtime route-target --port");
    };
    match route_aware_dial_target(host, port) {
        Ok(target) => RunnerOutput::ok(format!(
            "{{\"domain\":{},\"dest\":{},\"dest_is_unspecified\":{}}}\n",
            json_string(&target.domain),
            json_string(&target.dest.to_string()),
            target.dest_is_unspecified()
        )),
        Err(err) => RunnerOutput::stdout_error(err.to_string()),
    }
}

fn run_overview_basic() -> RunnerOutput {
    RunnerOutput::ok(format!("{}\n", overview_basic_value()))
}

fn run_stage22_smoke() -> RunnerOutput {
    let dry = run_dry_run_smoke();
    if dry.exit_code != 0 {
        return dry;
    }
    let target = match route_aware_dial_target("example.com", "443") {
        Ok(target) => target,
        Err(err) => return RunnerOutput::stdout_error(err.to_string()),
    };
    let overview = overview_basic_value();
    let smoke = json!({
        "name": "stage22-runtime-smoke-helper",
        "evidence_class": "opt-in-helper-smoke",
        "default_switch_allowed": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "default_path_mutated": false,
        "live_daemon_started": false,
        "dry_runtime_reload_stop": true,
        "route_aware": {
            "host": "example.com",
            "port": "443",
            "domain": target.domain,
            "dest": target.dest.to_string(),
            "dest_is_unspecified": target.dest_is_unspecified(),
            "system_dns_resolution": false,
        },
        "runtime_overview_without_control_plane": true,
        "overview": {
            "active_connections": overview["active_connections"],
            "udp_sessions": overview["udp_sessions"],
            "udp_task_queues": overview["udp_task_queues"],
            "udp_task_drop_total": overview["udp_task_drop_total"],
            "dns_cache_hit_total": overview["dns_cache_hit_total"],
            "samples": overview["samples"],
        },
        "remaining_runtime_evidence": [
            "daemon live run smoke",
            "active TCP traffic with mark and mptcp",
            "active UDP and DNS UDP/53 traffic",
            "reload success and rollback under injected failure",
            "daemon runtime Go/Rust benchmark",
        ],
    });
    RunnerOutput::ok(format!("{}\n", smoke))
}

fn overview_basic_value() -> Value {
    let overview = RuntimeOverview::from_snapshot(
        RuntimeStatsSnapshot {
            updated_at_unix: 1_700_000_300,
            upload_rate: 10,
            download_rate: 20,
            upload_total: 30,
            download_total: 40,
            active_connections: 0,
            udp_sessions: 0,
            udp_task_queues: 99,
            udp_task_drop_total: 88,
            packet_sniffer_sessions: 77,
            rss_bytes: 50,
            heap_alloc_bytes: 60,
            goroutines: 70,
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
        },
        None,
    );
    json!({
        "updated_at_unix": overview.updated_at_unix,
        "upload_rate": overview.upload_rate,
        "download_rate": overview.download_rate,
        "upload_total": overview.upload_total,
        "download_total": overview.download_total,
        "active_connections": overview.active_connections,
        "udp_sessions": overview.udp_sessions,
        "udp_task_queues": overview.udp_task_queues,
        "udp_task_drop_total": overview.udp_task_drop_total,
        "packet_sniffer_sessions": overview.packet_sniffer_sessions,
        "rss_bytes": overview.rss_bytes,
        "heap_alloc_bytes": overview.heap_alloc_bytes,
        "goroutines": overview.goroutines,
        "dns_cache_hit_total": overview.dns.dns_cache_hit_total,
        "dns_cache_expired_removal_total": overview.dns.dns_cache_expired_removal_total,
        "dns_udp_retry_total": overview.dns.dns_udp_retry_total,
        "dns_truncated_tcp_fallback_total": overview.dns.dns_truncated_tcp_fallback_total,
        "dns_doh_status_failure_total": overview.dns.dns_doh_status_failure_total,
        "dns_doh_content_type_failure_total": overview.dns.dns_doh_content_type_failure_total,
        "dns_upstream_refresh_success_total": overview.dns.dns_upstream_refresh_success_total,
        "dns_upstream_refresh_failure_total": overview.dns.dns_upstream_refresh_failure_total,
        "dns_upstream_refresh_stale_reuse_total": overview.dns.dns_upstream_refresh_stale_reuse_total,
        "samples": overview.samples.iter().map(|sample| {
            json!({
                "timestamp_unix": sample.timestamp_unix,
                "upload_rate": sample.upload_rate,
                "download_rate": sample.download_rate,
            })
        }).collect::<Vec<_>>(),
    })
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                write!(out, "\\u{:04x}", ch as u32).unwrap();
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
