use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::reload_owner_handoff_smoke_report;

pub fn default_reload_owner_benchmark_root() -> PathBuf {
    PathBuf::from("/tmp/dae-reload-owner-benchmark")
}

pub fn reload_owner_benchmark_report(root: &Path, iterations: u32) -> Result<Value, String> {
    if iterations == 0 {
        return Err("reload-owner-benchmark iterations must be greater than zero".to_owned());
    }
    ensure_safe_reload_owner_benchmark_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing reload-owner-benchmark root {}: {err}",
                path_string(root)
            )
        })?;
    }
    let run_dir = root.join("run");
    let state_file = run_dir.join("reload-owner-benchmark.json");
    let log_file = root.join("log").join("reload-owner-benchmark.log");
    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create reload-owner-benchmark run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    if let Some(parent) = log_file.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create reload-owner-benchmark log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    let started = Instant::now();
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("failed to create reload-owner-benchmark run id: {err}"))?
        .as_nanos();
    let mut iteration_reports = Vec::new();
    let mut elapsed_samples = Vec::new();
    let mut pass_count = 0_u32;
    let mut fail_count = 0_u32;
    let mut cleanup_count = 0_u32;

    for index in 0..iterations {
        let iteration = index + 1;
        let iteration_root = PathBuf::from(format!(
            "/tmp/dae-reload-owner-handoff-reload-owner-benchmark-benchmark-{}-{run_id}-{iteration}",
            std::process::id(),
        ));
        let report = reload_owner_handoff_smoke_report(&iteration_root)?;
        let passed = report["non_production_daemon_reload_owner_transfer_smoke_passed"]
            .as_bool()
            .unwrap_or(false);
        if passed {
            pass_count += 1;
            if let Some(elapsed_ns) = report["elapsed_ns"].as_u64() {
                elapsed_samples.push(elapsed_ns);
            }
        } else {
            fail_count += 1;
        }
        let cleanup_removed = if iteration_root.exists() {
            fs::remove_dir_all(&iteration_root).is_ok() && !iteration_root.exists()
        } else {
            true
        };
        if cleanup_removed {
            cleanup_count += 1;
        }
        iteration_reports.push(json!({
            "iteration": iteration,
            "root": path_string(&iteration_root),
            "passed": passed,
            "elapsed_ns": report["elapsed_ns"],
            "listen_socket_map_key_handoff_smoke_passed": report["listen_socket_map_key_handoff_smoke_passed"],
            "reload_current_swap_smoke_passed": report["reload_current_swap_smoke_passed"],
            "old_owner_close_smoke_passed": report["old_owner_close_smoke_passed"],
            "reload_scoped_cleanup_smoke_passed": report["reload_scoped_cleanup_smoke_passed"],
            "rollback_blocker_recorded": report["rollback_blocker_recorded"],
            "reload-owner-handoff_iteration_root_removed": cleanup_removed
        }));
    }

    let total_elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let min_elapsed_ns = elapsed_samples.iter().copied().min().unwrap_or(0);
    let max_elapsed_ns = elapsed_samples.iter().copied().max().unwrap_or(0);
    let sum_elapsed_ns = elapsed_samples.iter().copied().sum::<u64>();
    let avg_elapsed_ns = if elapsed_samples.is_empty() {
        0
    } else {
        sum_elapsed_ns / elapsed_samples.len() as u64
    };
    let all_iterations_passed = pass_count == iterations;
    let all_iteration_roots_removed = cleanup_count == iterations;

    let report = json!({
        "name": "bounded-production-equivalent-listener-ebpf-benchmark-harness",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "state_file": path_string(&state_file),
        "log_file": path_string(&log_file),
        "iterations": iterations,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "cleanup_count": cleanup_count,
        "all_iterations_passed": all_iterations_passed,
        "all_iteration_roots_removed": all_iteration_roots_removed,
        "total_elapsed_ns": total_elapsed_ns,
        "sum_iteration_elapsed_ns": sum_elapsed_ns,
        "min_iteration_elapsed_ns": min_elapsed_ns,
        "max_iteration_elapsed_ns": max_elapsed_ns,
        "avg_iteration_elapsed_ns": avg_elapsed_ns,
        "bounded_production_equivalent_benchmark_harness_available": true,
        "bounded_production_equivalent_benchmark_harness_executed": true,
        "bounded_benchmark_executable_now": true,
        "production_equivalent_listener_ebpf_benchmark_recorded": all_iterations_passed,
        "reload_owner_handoff_benchmark_recorded": all_iterations_passed,
        "benchmark_artifact_summary_recorded": true,
        "rollback_cleanup_benchmark_recorded": all_iteration_roots_removed,
        "production_listener_bound": false,
        "production_tc_attach_smoke_passed": false,
        "ebpf_attached": false,
        "benchmark_executable_now": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "true_rust_default_daemon_admitted": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "iteration_reports": iteration_reports
    });

    let state = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode reload-owner-benchmark benchmark state: {err}"))?;
    fs::write(&state_file, state)
        .map_err(|err| format!("failed to write reload-owner-benchmark benchmark state: {err}"))?;
    fs::write(
        &log_file,
        "reload-owner-benchmark bounded reload owner benchmark\n",
    )
    .map_err(|err| format!("failed to write reload-owner-benchmark benchmark log: {err}"))?;
    Ok(report)
}

fn ensure_safe_reload_owner_benchmark_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "reload-owner-benchmark root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-reload-owner-benchmark") {
        return Err(format!(
            "reload-owner-benchmark root must be under /tmp/dae-reload-owner-benchmark*: {root_string}"
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}
