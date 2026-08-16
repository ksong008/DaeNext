use std::collections::HashSet;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;

use dae_config::{necessary_outbounds, parse_config_sections};
use dae_config_util::cleanup_subscription_persist_files;
use dae_netutil::route_aware_dial_target;
use dae_runtime_control::{
    DnsObservabilityStats, RuntimeOverview, RuntimeStatsSnapshot, RuntimeTrafficSample,
};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "engine/runtime_overview",
            default_iters: 100_000,
            run: bench_engine_runtime_overview,
        },
        BenchCase {
            id: "engine/runtime_overview_scoped_udp",
            default_iters: 100_000,
            run: bench_engine_runtime_overview_scoped_udp,
        },
        BenchCase {
            id: "engine/route_aware_target",
            default_iters: 100_000,
            run: bench_engine_route_aware_target,
        },
        BenchCase {
            id: "engine/parse_config_api",
            default_iters: 1_000,
            run: bench_engine_parse_config_api,
        },
        BenchCase {
            id: "engine/read_config_file_minimal",
            default_iters: 1_000,
            run: bench_engine_read_config_file_minimal,
        },
        BenchCase {
            id: "engine/necessary_outbounds",
            default_iters: 100_000,
            run: bench_engine_necessary_outbounds,
        },
        BenchCase {
            id: "engine/subscription_persist_cleanup",
            default_iters: 1_000,
            run: bench_engine_subscription_persist_cleanup,
        },
    ]
}

fn bench_engine_runtime_overview(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let snapshot = runtime_snapshot();
    Ok(measure(
        || {
            let overview = RuntimeOverview::from_snapshot(black_box(snapshot.clone()), None);
            black_box(overview.samples.len() as u64 ^ overview.upload_rate)
        },
        iters,
        warmup,
    ))
}

fn bench_engine_runtime_overview_scoped_udp(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let snapshot = RuntimeStatsSnapshot {
        updated_at_unix: 1_700_000_400,
        udp_task_queues: 99,
        udp_task_drop_total: 88,
        packet_sniffer_sessions: 77,
        ..RuntimeStatsSnapshot::default()
    };
    Ok(measure(
        || {
            let overview =
                RuntimeOverview::from_snapshot(black_box(snapshot.clone()), Some((1, 0)));
            black_box(
                overview.udp_task_queues as u64
                    ^ overview.udp_task_drop_total
                    ^ overview.packet_sniffer_sessions as u64,
            )
        },
        iters,
        warmup,
    ))
}

fn bench_engine_route_aware_target(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let inputs = [
        ("example.com", "443"),
        ("192.0.2.1", "8443"),
        ("2001:db8::1", "9443"),
    ];
    Ok(measure(
        || {
            let mut checksum = 0_u64;
            for (host, port) in black_box(inputs) {
                let target = route_aware_dial_target(host, port).expect("route aware target");
                checksum ^= target.domain.len() as u64;
                checksum ^= target.dest.port() as u64;
                checksum ^= target.dest_is_unspecified() as u64;
            }
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

fn bench_engine_parse_config_api(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let global = r#"global {
    log_level: debug
    udp_endpoint_pool_size: 8192
}"#;
    let routing = r#"routing {
    domain(suffix: example.com) -> must_proxy
    fallback: must_direct
}"#;
    Ok(measure(
        || {
            let config =
                parse_config_sections(Some(black_box(global)), None, Some(black_box(routing)))
                    .expect("parse engine config api");
            black_box(
                config.global.udp_endpoint_pool_size as u64 ^ config.routing.rules.len() as u64,
            )
        },
        iters,
        warmup,
    ))
}

fn bench_engine_necessary_outbounds(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let global = r#"global {
    log_level: debug
    udp_endpoint_pool_size: 8192
}"#;
    let routing = r#"routing {
    domain(suffix: example.com) -> must_proxy
    domain(full: force.example.com) -> must_rules
    fallback: must_direct
}"#;
    let config = parse_config_sections(Some(global), None, Some(routing))
        .map_err(|err| format!("parse engine config api failed: {err}"))?;
    Ok(measure(
        || {
            let outbounds = necessary_outbounds(black_box(&config.routing));
            black_box(outbounds.len() as u64 ^ outbounds[0].len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_engine_read_config_file_minimal(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let tree = TempConfig::new("dae-bench-engine-read-config")?;
    let path = tree.write("config.dae", "global {}\nrouting {}\n")?;
    // Assessment (kept as-is): this case measures reading a config file from
    // disk, so the read inside merge_config_file is the workload itself, not
    // pollution. dae-config exposes no in-memory merge that would let the IO
    // move to a warmup phase; the warmup loop pre-heats the page cache and the
    // residual open/read syscall cost is part of what this case measures.
    Ok(measure(
        || {
            let merged = dae_config::merger::merge_config_file(black_box(&path))
                .expect("merge minimal config");
            let entries_len = merged.entries.len();
            let config = dae_config::schema::build_config_owned(merged.sections)
                .expect("build minimal config");
            black_box(config.global.log_level.len() as u64 ^ entries_len as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_engine_subscription_persist_cleanup(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let active = HashSet::from(["active".to_owned()]);
    let root = std::env::temp_dir().join(format!(
        "dae-bench-engine-subscription-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let persist = root.join("persist.d");
    fs::create_dir_all(&persist)
        .map_err(|err| format!("create {} failed: {err}", persist.display()))?;

    // Assessment (kept as-is): this case measures subscription persist-file
    // cleanup, which is inherently disk-bound: the measured closure writes the
    // fixture files and cleanup_subscription_persist_files scans the directory
    // on disk. There is no in-memory variant of the cleanup API to move the IO
    // into a warmup phase, so the disk operations stay inside the timed window
    // and are the subject of the measurement.
    let measurement = measure(
        || {
            fs::write(persist.join("active.sub"), b"payload").expect("write active persist file");
            fs::write(persist.join("stale.sub"), b"payload").expect("write stale persist file");
            fs::write(persist.join("note.txt"), b"payload").expect("write inactive persist file");
            let remaining =
                cleanup_subscription_persist_files(black_box(&root), black_box(&active))
                    .expect("cleanup subscription persist files");
            black_box(remaining.len() as u64)
        },
        iters,
        warmup,
    );
    let _ = fs::remove_dir_all(&root);
    Ok(measurement)
}

struct TempConfig {
    root: PathBuf,
}

impl TempConfig {
    fn new(name: &str) -> Result<Self, String> {
        let root = std::env::temp_dir().join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root)
            .map_err(|err| format!("create temp config root {} failed: {err}", root.display()))?;
        Ok(Self { root })
    }

    fn write(&self, rel: &str, content: &str) -> Result<PathBuf, String> {
        let path = self.root.join(rel);
        fs::write(&path, content)
            .map_err(|err| format!("write {} failed: {err}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|err| format!("chmod {} failed: {err}", path.display()))?;
        }
        Ok(path)
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn runtime_snapshot() -> RuntimeStatsSnapshot {
    RuntimeStatsSnapshot {
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
    }
}
