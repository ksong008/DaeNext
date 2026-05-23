use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionDataplaneHarnessOptions {
    pub execute: bool,
    pub ack_root_gate: bool,
    pub benchmark_iters: u32,
    pub cargo_manifest: PathBuf,
}

impl Default for ProductionDataplaneHarnessOptions {
    fn default() -> Self {
        Self {
            execute: false,
            ack_root_gate: false,
            benchmark_iters: 5,
            cargo_manifest: PathBuf::from("rust/Cargo.toml"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct StageSpec {
    stage: &'static str,
    command: &'static str,
    root_prefix: &'static str,
    pass_key: &'static str,
    benchmark_recorded_key: Option<&'static str>,
}

pub fn production_dataplane_harness_report(
    run_root: &Path,
    options: &ProductionDataplaneHarnessOptions,
) -> Result<Value, String> {
    if options.benchmark_iters == 0 {
        return Err("production dataplane --dataplane-benchmark-iters must be non-zero".to_owned());
    }
    if options.execute && !options.ack_root_gate {
        return Err(
            "production dataplane smoke requires --ack-root-gate with --execute-production-dataplane-smoke"
                .to_owned(),
        );
    }
    if options.execute && !options.cargo_manifest.is_file() {
        return Err(format!(
            "production dataplane cargo manifest does not exist: {}",
            path_string(&options.cargo_manifest)
        ));
    }

    let artifact_dir = run_root.join("run").join("production-dataplane");
    let stage_plan = stage_specs()
        .into_iter()
        .map(|spec| {
            json!({
                "stage": spec.stage,
                "command": spec.command,
                "root": path_string(&stage_root(spec, run_root)),
                "pass_key": spec.pass_key,
                "benchmark_recorded_key": spec.benchmark_recorded_key,
            })
        })
        .collect::<Vec<_>>();

    if !options.execute {
        return Ok(base_report(
            options,
            &artifact_dir,
            stage_plan,
            Vec::new(),
            false,
        ));
    }

    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create production dataplane artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;

    let mut stages = Vec::new();
    for spec in stage_specs() {
        let root = stage_root(spec, run_root);
        ensure_tmp_stage_root(&root, spec.root_prefix)?;
        if root.exists() {
            fs::remove_dir_all(&root).map_err(|err| {
                format!(
                    "failed to remove existing production dataplane stage root {}: {err}",
                    path_string(&root)
                )
            })?;
        }
        let result = run_stage(spec, &root, options, &artifact_dir)?;
        stages.push(result);
    }

    let passed = stages
        .iter()
        .all(|stage| stage["passed"].as_bool().unwrap_or(false));
    Ok(base_report(
        options,
        &artifact_dir,
        stage_plan,
        stages,
        passed,
    ))
}

fn base_report(
    options: &ProductionDataplaneHarnessOptions,
    artifact_dir: &Path,
    stage_plan: Vec<Value>,
    stages: Vec<Value>,
    passed: bool,
) -> Value {
    let stage_pass = |stage_name: &str| -> bool {
        stages
            .iter()
            .find(|entry| entry["stage"].as_str() == Some(stage_name))
            .and_then(|entry| entry["passed"].as_bool())
            .unwrap_or(false)
    };
    let stage49_passed = stage_pass("stage49");
    let stage50_passed = stage_pass("stage50");
    let stage51_passed = stage_pass("stage51");
    let stage53_passed = stage_pass("stage53");
    let stage54_passed = stage_pass("stage54");
    let benchmark_records = benchmark_records(&stages);
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("daemon-run-production-dataplane-harness"),
    );
    report.insert(
        "evidence_class".to_owned(),
        json!("run-integrated-root-gated-stage49-stage50-stage51-stage53-stage54-harness"),
    );
    report.insert("execute_smoke".to_owned(), json!(options.execute));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(options.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!options.execute));
    report.insert("blocked".to_owned(), json!(options.execute && !passed));
    report.insert("artifact_dir".to_owned(), json!(path_string(artifact_dir)));
    report.insert(
        "cargo_manifest".to_owned(),
        json!(path_string(&options.cargo_manifest)),
    );
    report.insert("benchmark_iters".to_owned(), json!(options.benchmark_iters));
    report.insert("stage_plan".to_owned(), json!(stage_plan));
    report.insert("stages".to_owned(), json!(stages));
    report.insert(
        "production_dataplane_harness_integrated_in_run".to_owned(),
        json!(true),
    );
    report.insert(
        "production_dataplane_harness_executed".to_owned(),
        json!(options.execute),
    );
    report.insert(
        "production_dataplane_harness_passed".to_owned(),
        json!(options.execute && passed),
    );
    for (key, value) in [
        ("stage49_passed", stage49_passed),
        ("stage50_passed", stage50_passed),
        ("stage51_passed", stage51_passed),
        ("stage53_passed", stage53_passed),
        ("stage54_passed", stage54_passed),
    ] {
        report.insert(key.to_owned(), json!(value));
    }
    report.insert("benchmark_records".to_owned(), json!(benchmark_records));
    for key in [
        "production_listener_bound",
        "production_tc_attach_smoke_passed",
        "ebpf_attached",
        "production_dataplane_admitted",
        "reload_runtime_parity_admitted",
        "matched_go_rust_default_daemon_benchmark_recorded",
        "true_rust_default_daemon_admitted",
        "default_switch_allowed",
        "default_path_mutation_allowed",
        "product_chain_switch_allowed",
    ] {
        report.insert(key.to_owned(), json!(false));
    }
    report.insert(
        "production_dataplane_admission_scope".to_owned(),
        json!(if options.execute && passed {
            "run-integrated-harness-only"
        } else if options.execute {
            "run-integrated-harness-failed"
        } else {
            "not-executed"
        }),
    );
    report.insert("go_default_path_preserved".to_owned(), json!(true));
    report.insert("go_fallback_required".to_owned(), json!(true));
    report.insert(
        "source".to_owned(),
        json!([
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage194-196",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.8"
        ]),
    );
    Value::Object(report)
}

fn run_stage(
    spec: StageSpec,
    root: &Path,
    options: &ProductionDataplaneHarnessOptions,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let args = stage_args(spec, root, options);
    let output = Command::new("cargo").args(&args).output().map_err(|err| {
        format!(
            "failed to execute production dataplane stage {}: {err}",
            spec.stage
        )
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout_file = artifact_dir.join(format!("{}.stdout.json", spec.stage));
    let stderr_file = artifact_dir.join(format!("{}.stderr.log", spec.stage));
    fs::write(&stdout_file, &stdout).map_err(|err| {
        format!(
            "failed to write production dataplane stdout artifact {}: {err}",
            path_string(&stdout_file)
        )
    })?;
    fs::write(&stderr_file, &stderr).map_err(|err| {
        format!(
            "failed to write production dataplane stderr artifact {}: {err}",
            path_string(&stderr_file)
        )
    })?;

    let parsed = parse_json_stdout(&stdout).map_err(|err| {
        format!(
            "production dataplane stage {} did not emit parseable JSON: {err}; stdout={}; stderr={}",
            spec.stage,
            cap_text(&stdout),
            cap_text(&stderr)
        )
    })?;
    let blocked = parsed["blocked"].as_bool().unwrap_or(false);
    let pass_value = parsed[spec.pass_key].as_bool().unwrap_or(false);
    let passed = output.status.success() && !blocked && pass_value;
    let benchmark_recorded = spec
        .benchmark_recorded_key
        .and_then(|key| parsed[key].as_bool())
        .unwrap_or(false);
    let benchmark = if benchmark_recorded {
        parsed["benchmark"].clone()
    } else {
        Value::Null
    };

    let summary = json!({
        "stage": spec.stage,
        "command": spec.command,
        "root": path_string(root),
        "exit_code": output.status.code(),
        "passed": passed,
        "blocked": blocked,
        "pass_key": spec.pass_key,
        "pass_value": pass_value,
        "benchmark_recorded_key": spec.benchmark_recorded_key,
        "benchmark_recorded": benchmark_recorded,
        "benchmark": benchmark,
        "stdout_file": path_string(&stdout_file),
        "stderr_file": path_string(&stderr_file),
        "blockers": parsed["blockers"].clone(),
        "cleanup": cleanup_summary(&parsed),
        "selected_evidence": selected_evidence(spec.stage, &parsed),
    });
    let summary_file = artifact_dir.join(format!("{}.summary.json", spec.stage));
    let encoded = serde_json::to_vec_pretty(&summary).map_err(|err| {
        format!(
            "failed to encode production dataplane summary for {}: {err}",
            spec.stage
        )
    })?;
    fs::write(&summary_file, encoded).map_err(|err| {
        format!(
            "failed to write production dataplane summary artifact {}: {err}",
            path_string(&summary_file)
        )
    })?;

    if !passed {
        return Err(format!(
            "production dataplane stage {} failed; summary={}",
            spec.stage, summary
        ));
    }
    Ok(summary)
}

fn stage_args(
    spec: StageSpec,
    root: &Path,
    options: &ProductionDataplaneHarnessOptions,
) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--manifest-path".to_owned(),
        path_string(&options.cargo_manifest),
        "-p".to_owned(),
        "dae-cli".to_owned(),
        "--bin".to_owned(),
        "dae-cli-optin".to_owned(),
        "--quiet".to_owned(),
        "--".to_owned(),
        "runtime".to_owned(),
        spec.command.to_owned(),
        "--execute-smoke".to_owned(),
        "--ack-root-gate".to_owned(),
        "--root".to_owned(),
        path_string(root),
    ];
    if spec.benchmark_recorded_key.is_some() {
        args.push("--benchmark-iters".to_owned());
        args.push(options.benchmark_iters.to_string());
    }
    args
}

fn stage_specs() -> [StageSpec; 5] {
    [
        StageSpec {
            stage: "stage49",
            command: "stage49-production-param-listener-admission",
            root_prefix: "/tmp/dae-stage49-run",
            pass_key: "combined_production_param_listener_smoke_passed",
            benchmark_recorded_key: None,
        },
        StageSpec {
            stage: "stage50",
            command: "stage50-active-tcp-tproxy-ingress-admission",
            root_prefix: "/tmp/dae-stage50-run",
            pass_key: "active_tcp_tproxy_ingress_smoke_passed",
            benchmark_recorded_key: None,
        },
        StageSpec {
            stage: "stage51",
            command: "stage51-active-tcp-route-dial-relay-admission",
            root_prefix: "/tmp/dae-stage51-run",
            pass_key: "active_tcp_relay_smoke_passed",
            benchmark_recorded_key: Some("active_tcp_relay_benchmark_recorded"),
        },
        StageSpec {
            stage: "stage53",
            command: "stage53-active-udp-tproxy-endpoint-admission",
            root_prefix: "/tmp/dae-stage53-run",
            pass_key: "active_udp_tproxy_smoke_passed",
            benchmark_recorded_key: Some("active_udp_tproxy_benchmark_recorded"),
        },
        StageSpec {
            stage: "stage54",
            command: "stage54-active-dns-tproxy-cache-admission",
            root_prefix: "/tmp/dae-stage54-run",
            pass_key: "active_dns_tproxy_smoke_passed",
            benchmark_recorded_key: Some("active_dns_tproxy_benchmark_recorded"),
        },
    ]
}

fn stage_root(spec: StageSpec, run_root: &Path) -> PathBuf {
    let suffix = run_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_suffix)
        .filter(|suffix| !suffix.is_empty())
        .unwrap_or_else(|| "run".to_owned());
    PathBuf::from(format!("{}-{suffix}", spec.root_prefix))
}

fn ensure_tmp_stage_root(root: &Path, prefix: &str) -> Result<(), String> {
    if !root.is_absolute() || root.parent() != Some(Path::new("/tmp")) {
        return Err(format!(
            "production dataplane stage root must be an absolute /tmp child: {}",
            path_string(root)
        ));
    }
    let root = path_string(root);
    if !root.starts_with(prefix) {
        return Err(format!(
            "production dataplane stage root {root} must start with {prefix}"
        ));
    }
    Ok(())
}

fn parse_json_stdout(stdout: &str) -> Result<Value, String> {
    let trimmed = stdout.trim();
    serde_json::from_str(trimmed).or_else(|first_err| {
        stdout
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| line.starts_with('{'))
            .ok_or_else(|| first_err.to_string())
            .and_then(|line| serde_json::from_str(line).map_err(|err| err.to_string()))
    })
}

fn cleanup_summary(value: &Value) -> Value {
    let map_id_snapshots = &value["map_id_snapshots"];
    let temporary_resources = if value["temporary_resources"].is_object() {
        &value["temporary_resources"]
    } else {
        &value["temporary_production_named_resources"]
    };
    json!({
        "loaded_map_cleaned": map_id_snapshots["loaded_map_cleaned"].clone(),
        "loaded_maps_cleaned": map_id_snapshots["loaded_maps_cleaned"].clone(),
        "leftovers_after_cleanup": temporary_resources["leftovers_after_cleanup"].clone(),
        "sys_fs_bpf_dae_mutated": value["sys_fs_bpf_dae"]["mutated"].clone(),
    })
}

fn selected_evidence(stage: &str, value: &Value) -> Value {
    let keys: &[&str] = match stage {
        "stage49" => &[
            "combined_production_param_listener_admitted",
            "production_name_dae0_dae0peer_attach_executed",
            "param_aware_object_load_executed",
            "transparent_listener_socket_options_verified",
            "production_param_transparent_listener_handoff_executed",
        ],
        "stage50" => &[
            "active_tcp_tproxy_admitted",
            "active_tcp_syn_reached_transparent_listener",
            "original_destination_observed",
            "tcp_reply_path_succeeded",
            "active_tproxy_traffic_executed",
        ],
        "stage51" => &[
            "active_tcp_tproxy_admitted",
            "route_dial_tcp_direct_path_executed",
            "outbound_relay_recorded",
            "tcp_reply_path_succeeded",
            "so_mark_real_outbound_socket_observed",
            "mptcp_real_outbound_socket_observed",
            "active_tcp_relay_benchmark_recorded",
        ],
        "stage53" => &[
            "active_udp_tproxy_admitted",
            "active_udp_original_destination_observed",
            "udp_endpoint_pool_live_recorded",
            "udp_packetconn_write_read_recorded",
            "udp_sendpkt_reply_recorded",
            "udp_so_mark_real_outbound_socket_observed",
            "active_udp_tproxy_benchmark_recorded",
        ],
        "stage54" => &[
            "active_dns_tproxy_admitted",
            "active_dns_original_destination_observed",
            "dns_controller_path_recorded",
            "dns_upstream_query_recorded",
            "dns_response_validation_recorded",
            "dns_cache_restore_recorded",
            "domain_routing_owner_migration_recorded",
            "dns_sendpkt_reply_recorded",
            "dns_so_mark_upstream_socket_observed",
            "active_dns_tproxy_benchmark_recorded",
        ],
        _ => &[],
    };
    let mut selected = Map::new();
    for key in keys {
        selected.insert((*key).to_owned(), value[*key].clone());
    }
    Value::Object(selected)
}

fn benchmark_records(stages: &[Value]) -> Vec<Value> {
    stages
        .iter()
        .filter(|stage| {
            stage["benchmark_recorded"].as_bool().unwrap_or(false) && !stage["benchmark"].is_null()
        })
        .map(|stage| {
            json!({
                "stage": stage["stage"].clone(),
                "root": stage["root"].clone(),
                "benchmark": stage["benchmark"].clone(),
            })
        })
        .collect()
}

fn sanitize_suffix(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn cap_text(value: &str) -> String {
    const MAX: usize = 4000;
    if value.len() <= MAX {
        return value.to_owned();
    }
    let truncated = value.chars().take(MAX).collect::<String>();
    format!(
        "{}...[truncated {} bytes]",
        truncated,
        value.len().saturating_sub(truncated.len())
    )
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_dataplane_report_is_read_only_by_default() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-dataplane-default-{}",
            std::process::id()
        ));
        let report = production_dataplane_harness_report(
            &root,
            &ProductionDataplaneHarnessOptions::default(),
        )
        .unwrap();
        assert!(
            !report["production_dataplane_harness_executed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["production_dataplane_harness_passed"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            report["production_dataplane_admission_scope"]
                .as_str()
                .unwrap(),
            "not-executed"
        );
        assert_eq!(report["stage_plan"].as_array().unwrap().len(), 5);
        assert!(report["stages"].as_array().unwrap().is_empty());
    }

    #[test]
    fn production_dataplane_execute_requires_root_gate_ack() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-dataplane-noack-{}",
            std::process::id()
        ));
        let options = ProductionDataplaneHarnessOptions {
            execute: true,
            cargo_manifest: PathBuf::from("rust/Cargo.toml"),
            ..ProductionDataplaneHarnessOptions::default()
        };
        let err = production_dataplane_harness_report(&root, &options).unwrap_err();
        assert!(err.contains("--ack-root-gate"));
    }

    #[test]
    fn production_dataplane_rejects_zero_benchmark_iters() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-dataplane-zero-{}",
            std::process::id()
        ));
        let options = ProductionDataplaneHarnessOptions {
            benchmark_iters: 0,
            ..ProductionDataplaneHarnessOptions::default()
        };
        let err = production_dataplane_harness_report(&root, &options).unwrap_err();
        assert!(err.contains("benchmark-iters"));
    }
}
