use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::production_runtime_owner::{
    ProductionRuntimeOwnerOptions, production_runtime_owner_report,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionDataplaneHarnessOptions {
    pub execute: bool,
    pub ack_root_gate: bool,
    pub benchmark_iters: u32,
}

impl Default for ProductionDataplaneHarnessOptions {
    fn default() -> Self {
        Self {
            execute: false,
            ack_root_gate: false,
            benchmark_iters: 5,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct DataplaneAdmissionSpec {
    check_id: &'static str,
    profile: &'static str,
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
    let artifact_dir = run_root.join("run").join("production-dataplane");
    let admission_plan = dataplane_admission_specs()
        .into_iter()
        .map(|spec| {
            json!({
                "check_id": spec.check_id,
                "profile": spec.profile,
                "root": path_string(&admission_root(spec, run_root)),
                "pass_key": spec.pass_key,
                "benchmark_recorded_key": spec.benchmark_recorded_key,
            })
        })
        .collect::<Vec<_>>();

    if !options.execute {
        return Ok(base_report(
            options,
            &artifact_dir,
            admission_plan,
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

    let mut admissions = Vec::new();
    for spec in dataplane_admission_specs() {
        let root = admission_root(spec, run_root);
        ensure_tmp_admission_root(&root, spec.root_prefix)?;
        if root.exists() {
            fs::remove_dir_all(&root).map_err(|err| {
                format!(
                    "failed to remove existing production dataplane admission root {}: {err}",
                    path_string(&root)
                )
            })?;
        }
        let result = run_admission(spec, &root, options, &artifact_dir)?;
        admissions.push(result);
    }

    let passed = admissions
        .iter()
        .all(|admission| admission["passed"].as_bool().unwrap_or(false));
    Ok(base_report(
        options,
        &artifact_dir,
        admission_plan,
        admissions,
        passed,
    ))
}

fn base_report(
    options: &ProductionDataplaneHarnessOptions,
    artifact_dir: &Path,
    admission_plan: Vec<Value>,
    admissions: Vec<Value>,
    passed: bool,
) -> Value {
    let admission_pass = |check_id: &str| -> bool {
        admissions
            .iter()
            .find(|entry| entry["check_id"].as_str() == Some(check_id))
            .and_then(|entry| entry["passed"].as_bool())
            .unwrap_or(false)
    };
    let production_param_listener_passed = admission_pass("production-param-listener");
    let active_tcp_tproxy_ingress_passed = admission_pass("active-tcp-tproxy-ingress");
    let active_tcp_route_dial_relay_passed = admission_pass("active-tcp-route-dial-relay");
    let active_udp_tproxy_endpoint_passed = admission_pass("active-udp-tproxy-endpoint");
    let active_dns_tproxy_cache_passed = admission_pass("active-dns-tproxy-cache");
    let benchmark_records = benchmark_records(&admissions);
    let mut report = Map::new();
    report.insert(
        "name".to_owned(),
        json!("daemon-run-production-dataplane-harness"),
    );
    report.insert(
        "evidence_class".to_owned(),
        json!("run-integrated-root-gated-active-dataplane-harness"),
    );
    report.insert("execute_smoke".to_owned(), json!(options.execute));
    report.insert(
        "root_gate_acknowledged".to_owned(),
        json!(options.ack_root_gate),
    );
    report.insert("read_only".to_owned(), json!(!options.execute));
    report.insert("blocked".to_owned(), json!(options.execute && !passed));
    report.insert("artifact_dir".to_owned(), json!(path_string(artifact_dir)));
    report.insert("benchmark_iters".to_owned(), json!(options.benchmark_iters));
    report.insert("admission_plan".to_owned(), json!(admission_plan));
    report.insert("admissions".to_owned(), json!(admissions));
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
        (
            "production_param_listener_passed",
            production_param_listener_passed,
        ),
        (
            "active_tcp_tproxy_ingress_passed",
            active_tcp_tproxy_ingress_passed,
        ),
        (
            "active_tcp_route_dial_relay_passed",
            active_tcp_route_dial_relay_passed,
        ),
        (
            "active_udp_tproxy_endpoint_passed",
            active_udp_tproxy_endpoint_passed,
        ),
        (
            "active_dns_tproxy_cache_passed",
            active_dns_tproxy_cache_passed,
        ),
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
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:18.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:22.8"
        ]),
    );
    Value::Object(report)
}

fn run_admission(
    spec: DataplaneAdmissionSpec,
    root: &Path,
    options: &ProductionDataplaneHarnessOptions,
    artifact_dir: &Path,
) -> Result<Value, String> {
    let owner_options = owner_options_for_admission(spec, options);
    let owner_report = production_runtime_owner_report(root, &owner_options).map_err(|err| {
        format!(
            "production dataplane admission {} failed through daemon-owned production runtime owner: {err}",
            spec.check_id
        )
    })?;
    let owner_report_file = artifact_dir.join(format!("{}.owner-report.json", spec.check_id));
    let owner_report_encoded = serde_json::to_vec_pretty(&owner_report).map_err(|err| {
        format!(
            "failed to encode production dataplane owner report for {}: {err}",
            spec.check_id
        )
    })?;
    fs::write(&owner_report_file, owner_report_encoded).map_err(|err| {
        format!(
            "failed to write production dataplane owner report artifact {}: {err}",
            path_string(&owner_report_file)
        )
    })?;

    let blocked = false;
    let pass_value = owner_report[spec.pass_key].as_bool().unwrap_or(false);
    let passed = pass_value;
    let benchmark_recorded = spec
        .benchmark_recorded_key
        .and_then(|key| owner_report[key].as_bool())
        .unwrap_or(false);
    let benchmark = if benchmark_recorded {
        benchmark_value(spec.check_id, &owner_report)
    } else {
        Value::Null
    };

    let summary = json!({
        "check_id": spec.check_id,
        "profile": spec.profile,
        "root": path_string(root),
        "passed": passed,
        "blocked": blocked,
        "pass_key": spec.pass_key,
        "pass_value": pass_value,
        "benchmark_recorded_key": spec.benchmark_recorded_key,
        "benchmark_recorded": benchmark_recorded,
        "benchmark": benchmark,
        "owner_report_file": path_string(&owner_report_file),
        "owner_scope": owner_report["production_runtime_owner_scope"].clone(),
        "cleanup": cleanup_summary(&owner_report),
        "selected_evidence": selected_evidence(spec.check_id, &owner_report),
    });
    let summary_file = artifact_dir.join(format!("{}.summary.json", spec.check_id));
    let encoded = serde_json::to_vec_pretty(&summary).map_err(|err| {
        format!(
            "failed to encode production dataplane summary for {}: {err}",
            spec.check_id
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
            "production dataplane admission {} failed; summary={}",
            spec.check_id, summary
        ));
    }
    Ok(summary)
}

fn owner_options_for_admission(
    spec: DataplaneAdmissionSpec,
    options: &ProductionDataplaneHarnessOptions,
) -> ProductionRuntimeOwnerOptions {
    let mut owner_options = ProductionRuntimeOwnerOptions {
        execute: true,
        ack_root_gate: options.ack_root_gate,
        active_tcp_benchmark_iters: options.benchmark_iters,
        active_udp_benchmark_iters: options.benchmark_iters,
        active_dns_benchmark_iters: options.benchmark_iters,
        ..ProductionRuntimeOwnerOptions::default()
    };

    match spec.check_id {
        "production-param-listener" => {}
        "active-tcp-tproxy-ingress" => {
            owner_options.execute_active_tcp = true;
        }
        "active-tcp-route-dial-relay" => {
            owner_options.execute_active_tcp = true;
            owner_options.execute_active_tcp_relay = true;
        }
        "active-udp-tproxy-endpoint" => {
            owner_options.execute_active_tcp = true;
            owner_options.execute_active_udp = true;
        }
        "active-dns-tproxy-cache" => {
            owner_options.execute_active_tcp = true;
            owner_options.execute_active_udp = true;
            owner_options.execute_active_dns = true;
        }
        _ => {}
    }
    owner_options
}

fn dataplane_admission_specs() -> [DataplaneAdmissionSpec; 5] {
    [
        DataplaneAdmissionSpec {
            check_id: "production-param-listener",
            profile: "daemon-owned-production-param-listener",
            root_prefix: "/tmp/dae-daemon-production-param-listener",
            pass_key: "daemon_owned_production_runtime_owner_smoke_passed",
            benchmark_recorded_key: None,
        },
        DataplaneAdmissionSpec {
            check_id: "active-tcp-tproxy-ingress",
            profile: "daemon-owned-active-tcp-tproxy-ingress",
            root_prefix: "/tmp/dae-daemon-active-tcp-tproxy",
            pass_key: "active_tcp_tproxy_ingress_smoke_passed",
            benchmark_recorded_key: None,
        },
        DataplaneAdmissionSpec {
            check_id: "active-tcp-route-dial-relay",
            profile: "daemon-owned-active-tcp-route-dial-relay",
            root_prefix: "/tmp/dae-daemon-active-tcp-relay",
            pass_key: "active_tcp_relay_smoke_passed",
            benchmark_recorded_key: Some("active_tcp_relay_benchmark_recorded"),
        },
        DataplaneAdmissionSpec {
            check_id: "active-udp-tproxy-endpoint",
            profile: "daemon-owned-active-udp-tproxy-endpoint",
            root_prefix: "/tmp/dae-daemon-active-udp-tproxy",
            pass_key: "active_udp_tproxy_smoke_passed",
            benchmark_recorded_key: Some("active_udp_tproxy_benchmark_recorded"),
        },
        DataplaneAdmissionSpec {
            check_id: "active-dns-tproxy-cache",
            profile: "daemon-owned-active-dns-tproxy-cache",
            root_prefix: "/tmp/dae-daemon-active-dns-tproxy",
            pass_key: "active_dns_tproxy_smoke_passed",
            benchmark_recorded_key: Some("active_dns_tproxy_benchmark_recorded"),
        },
    ]
}

fn admission_root(spec: DataplaneAdmissionSpec, run_root: &Path) -> PathBuf {
    let suffix = run_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_suffix)
        .filter(|suffix| !suffix.is_empty())
        .unwrap_or_else(|| "run".to_owned());
    PathBuf::from(format!("{}-{suffix}", spec.root_prefix))
}

fn ensure_tmp_admission_root(root: &Path, prefix: &str) -> Result<(), String> {
    if !root.is_absolute() || root.parent() != Some(Path::new("/tmp")) {
        return Err(format!(
            "production dataplane admission root must be an absolute /tmp child: {}",
            path_string(root)
        ));
    }
    let root = path_string(root);
    if !root.starts_with(prefix) {
        return Err(format!(
            "production dataplane admission root {root} must start with {prefix}"
        ));
    }
    Ok(())
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

fn selected_evidence(check_id: &str, value: &Value) -> Value {
    let keys: &[&str] = match check_id {
        "production-param-listener" => &[
            "daemon_owned_production_runtime_owner_smoke_passed",
            "production_listener_bound_during_owner_smoke",
            "listen_socket_map_written_during_owner_smoke",
            "production_tc_attach_smoke_passed",
            "ebpf_attached_during_owner_smoke",
        ],
        "active-tcp-tproxy-ingress" => &[
            "active_tcp_tproxy_admitted_during_owner_smoke",
            "active_tcp_syn_reached_transparent_listener",
            "active_tcp_original_destination_observed",
            "active_tcp_reply_path_succeeded",
            "production_runtime_active_tcp_passed",
        ],
        "active-tcp-route-dial-relay" => &[
            "active_tcp_tproxy_admitted",
            "route_dial_tcp_direct_path_executed",
            "outbound_relay_recorded",
            "tcp_reply_path_succeeded",
            "so_mark_real_outbound_socket_observed",
            "mptcp_real_outbound_socket_observed",
            "active_tcp_relay_benchmark_recorded",
        ],
        "active-udp-tproxy-endpoint" => &[
            "active_udp_tproxy_admitted",
            "active_udp_original_destination_observed",
            "udp_endpoint_pool_live_recorded",
            "udp_packetconn_write_read_recorded",
            "udp_sendpkt_reply_recorded",
            "udp_so_mark_real_outbound_socket_observed",
            "active_udp_tproxy_benchmark_recorded",
        ],
        "active-dns-tproxy-cache" => &[
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

fn benchmark_value(check_id: &str, value: &Value) -> Value {
    match check_id {
        "active-tcp-route-dial-relay" => value["active_tcp"]["relay_benchmark"].clone(),
        "active-udp-tproxy-endpoint" => value["active_udp"]["benchmark"].clone(),
        "active-dns-tproxy-cache" => value["active_dns"]["benchmark"].clone(),
        _ => Value::Null,
    }
}

fn benchmark_records(admissions: &[Value]) -> Vec<Value> {
    admissions
        .iter()
        .filter(|admission| {
            admission["benchmark_recorded"].as_bool().unwrap_or(false)
                && !admission["benchmark"].is_null()
        })
        .map(|admission| {
            json!({
                "check_id": admission["check_id"].clone(),
                "root": admission["root"].clone(),
                "benchmark": admission["benchmark"].clone(),
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
        assert_eq!(report["admission_plan"].as_array().unwrap().len(), 5);
        assert!(
            report["admission_plan"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["command"].is_null())
        );
        assert!(report["admissions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn production_dataplane_execute_requires_root_gate_ack() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-production-dataplane-noack-{}",
            std::process::id()
        ));
        let options = ProductionDataplaneHarnessOptions {
            execute: true,
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

    #[test]
    fn production_dataplane_owner_profiles_match_admissions() {
        let options = ProductionDataplaneHarnessOptions {
            ack_root_gate: true,
            benchmark_iters: 7,
            ..ProductionDataplaneHarnessOptions::default()
        };
        let specs = dataplane_admission_specs();

        let listener = owner_options_for_admission(specs[0], &options);
        assert!(listener.execute);
        assert!(listener.ack_root_gate);
        assert!(!listener.execute_active_tcp);

        let tcp = owner_options_for_admission(specs[1], &options);
        assert!(tcp.execute_active_tcp);
        assert!(!tcp.execute_active_tcp_relay);

        let relay = owner_options_for_admission(specs[2], &options);
        assert!(relay.execute_active_tcp);
        assert!(relay.execute_active_tcp_relay);
        assert_eq!(relay.active_tcp_benchmark_iters, 7);

        let udp = owner_options_for_admission(specs[3], &options);
        assert!(udp.execute_active_tcp);
        assert!(udp.execute_active_udp);
        assert!(!udp.execute_active_dns);
        assert_eq!(udp.active_udp_benchmark_iters, 7);

        let dns = owner_options_for_admission(specs[4], &options);
        assert!(dns.execute_active_tcp);
        assert!(dns.execute_active_udp);
        assert!(dns.execute_active_dns);
        assert_eq!(dns.active_dns_benchmark_iters, 7);
    }
}
