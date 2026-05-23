use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductChainRecertificationOptions {
    pub execute: bool,
    pub default_path_mutation_requested: bool,
    pub production_run_command_replacement_dry_run_requested: bool,
    pub dae_repo: PathBuf,
    pub dae_wing_repo: PathBuf,
    pub daed_repo: PathBuf,
    pub outbound_repo: PathBuf,
    pub quic_go_repo: PathBuf,
    pub service_file: PathBuf,
    pub go_mod_file: PathBuf,
}

impl Default for ProductChainRecertificationOptions {
    fn default() -> Self {
        Self {
            execute: false,
            default_path_mutation_requested: false,
            production_run_command_replacement_dry_run_requested: false,
            dae_repo: PathBuf::from("/root/project/dae"),
            daed_repo: PathBuf::from("/root/project/daed"),
            dae_wing_repo: PathBuf::from("/root/project/daed/wing"),
            outbound_repo: PathBuf::from("/root/project/outbound"),
            quic_go_repo: PathBuf::from("/root/project/quic-go"),
            service_file: PathBuf::from("install/dae.service"),
            go_mod_file: PathBuf::from("go.mod"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProductChainAdmissionEvidence {
    pub production_dataplane_admitted: bool,
    pub reload_runtime_parity_admitted: bool,
    pub matched_benchmark_recorded: bool,
    pub true_rust_default_daemon_admitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProductChainTopologyKind {
    Daed2Wing,
    StandaloneDaeWing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProductChainTopology {
    kind: ProductChainTopologyKind,
    dae_core_repo: PathBuf,
}

impl ProductChainTopology {
    fn chain_name(&self) -> &'static str {
        match self.kind {
            ProductChainTopologyKind::Daed2Wing => "daed2.0-web-wing-daecore",
            ProductChainTopologyKind::StandaloneDaeWing => "standalone-dae-wing",
        }
    }

    fn wing_repo_label(&self) -> &'static str {
        match self.kind {
            ProductChainTopologyKind::Daed2Wing => "daed-wing",
            ProductChainTopologyKind::StandaloneDaeWing => "dae-wing",
        }
    }

    fn source_contract_shape(&self) -> &'static str {
        match self.kind {
            ProductChainTopologyKind::Daed2Wing => "engine-default-direct",
            ProductChainTopologyKind::StandaloneDaeWing => "runtime-service-port",
        }
    }

    fn as_json(&self, dae_wing_repo: &Path, daed_repo: &Path) -> Value {
        json!({
            "chain": self.chain_name(),
            "daed_repo": path_string(daed_repo),
            "wing_repo": path_string(dae_wing_repo),
            "dae_core_repo": path_string(&self.dae_core_repo),
            "standalone_dae_wing_repo_used": self.kind == ProductChainTopologyKind::StandaloneDaeWing,
            "daed2_wing_repo_used": self.kind == ProductChainTopologyKind::Daed2Wing,
            "source_contract_shape": self.source_contract_shape(),
            "web_api_base_path": "/api",
        })
    }
}

pub fn product_chain_recertification_report(
    run_root: &Path,
    options: &ProductChainRecertificationOptions,
    admission: ProductChainAdmissionEvidence,
) -> Result<Value, String> {
    ensure_safe_run_root(run_root)?;
    let artifact_dir = run_root.join("run").join("product-chain-recertification");
    let manifest_file = artifact_dir.join("product-chain-recertification.json");
    if !options.execute {
        return Ok(report_value(
            options,
            &artifact_dir,
            &manifest_file,
            admission,
            None,
        ));
    }
    fs::create_dir_all(&artifact_dir).map_err(|err| {
        format!(
            "failed to create product-chain recertification artifact dir {}: {err}",
            path_string(&artifact_dir)
        )
    })?;
    let evidence = collect_evidence(options);
    let report = report_value(
        options,
        &artifact_dir,
        &manifest_file,
        admission,
        Some(evidence),
    );
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|err| format!("failed to encode product-chain recertification report: {err}"))?;
    fs::write(&manifest_file, encoded).map_err(|err| {
        format!(
            "failed to write product-chain recertification manifest {}: {err}",
            path_string(&manifest_file)
        )
    })?;
    Ok(report)
}

#[derive(Default)]
struct ProductChainEvidence {
    topology: Value,
    service: Value,
    go_mod: Value,
    repos: Vec<Value>,
    runtime_control_api: Value,
    dirty_repos: Vec<String>,
    missing_repos: Vec<String>,
    unavailable_repos: Vec<String>,
}

fn collect_evidence(options: &ProductChainRecertificationOptions) -> ProductChainEvidence {
    let topology = product_chain_topology(options);
    let service = service_contract_json(&options.service_file);
    let go_mod = go_mod_dependency_boundary_json(options, &topology);
    let runtime_control_api = runtime_control_api_source_contract_json(
        &options.dae_wing_repo,
        &options.daed_repo,
        &topology,
    );
    let repo_inputs = [
        ("dae", &options.dae_repo),
        (topology.wing_repo_label(), &options.dae_wing_repo),
        ("daed", &options.daed_repo),
        ("outbound", &options.outbound_repo),
        ("quic-go", &options.quic_go_repo),
    ];
    let mut repos = Vec::new();
    let mut dirty_repos = Vec::new();
    let mut missing_repos = Vec::new();
    let mut unavailable_repos = Vec::new();
    for (name, path) in repo_inputs {
        let repo = repo_status_json(name, path);
        if !repo["exists"].as_bool().unwrap_or(false) {
            missing_repos.push(name.to_owned());
        }
        if repo["exists"].as_bool().unwrap_or(false)
            && !repo["git_status_available"].as_bool().unwrap_or(false)
        {
            unavailable_repos.push(name.to_owned());
        }
        if repo["dirty"].as_bool().unwrap_or(false) {
            dirty_repos.push(name.to_owned());
        }
        repos.push(repo);
    }
    ProductChainEvidence {
        topology: topology.as_json(&options.dae_wing_repo, &options.daed_repo),
        service,
        go_mod,
        repos,
        runtime_control_api,
        dirty_repos,
        missing_repos,
        unavailable_repos,
    }
}

fn product_chain_topology(options: &ProductChainRecertificationOptions) -> ProductChainTopology {
    let daed_wing_repo = options.daed_repo.join("wing");
    let kind = if options.dae_wing_repo == daed_wing_repo {
        ProductChainTopologyKind::Daed2Wing
    } else {
        ProductChainTopologyKind::StandaloneDaeWing
    };
    ProductChainTopology {
        kind,
        dae_core_repo: options.dae_wing_repo.join("dae-core"),
    }
}

fn report_value(
    options: &ProductChainRecertificationOptions,
    artifact_dir: &Path,
    manifest_file: &Path,
    admission: ProductChainAdmissionEvidence,
    evidence: Option<ProductChainEvidence>,
) -> Value {
    let executed = options.execute;
    let default_path_mutation_requested = options.default_path_mutation_requested;
    let service = evidence
        .as_ref()
        .map(|evidence| evidence.service.clone())
        .unwrap_or_else(|| json!({"status": "not-executed"}));
    let topology = evidence
        .as_ref()
        .map(|evidence| evidence.topology.clone())
        .unwrap_or_else(|| {
            product_chain_topology(options).as_json(&options.dae_wing_repo, &options.daed_repo)
        });
    let go_mod = evidence
        .as_ref()
        .map(|evidence| evidence.go_mod.clone())
        .unwrap_or_else(|| json!({"status": "not-executed"}));
    let repos = evidence
        .as_ref()
        .map(|evidence| evidence.repos.clone())
        .unwrap_or_default();
    let runtime_control_api = evidence
        .as_ref()
        .map(|evidence| evidence.runtime_control_api.clone())
        .unwrap_or_else(|| json!({"status": "not-executed"}));
    let dirty_repos = evidence
        .as_ref()
        .map(|evidence| evidence.dirty_repos.clone())
        .unwrap_or_default();
    let missing_repos = evidence
        .as_ref()
        .map(|evidence| evidence.missing_repos.clone())
        .unwrap_or_default();
    let unavailable_repos = evidence
        .as_ref()
        .map(|evidence| evidence.unavailable_repos.clone())
        .unwrap_or_default();
    let service_contract_passed = service["service_contract_preserved"]
        .as_bool()
        .unwrap_or(false);
    let dependency_boundary_preserved = go_mod["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false);
    let runtime_control_api_source_contract_preserved =
        runtime_control_api["runtime_control_api_source_contract_preserved"]
            .as_bool()
            .unwrap_or(false);
    let sibling_repos_present = missing_repos.is_empty();
    let sibling_repo_status_available = unavailable_repos.is_empty();
    let clean_product_chain_baseline =
        sibling_repos_present && sibling_repo_status_available && dirty_repos.is_empty();
    let runtime_control_api_clean_baseline = runtime_control_api_clean_baseline_json(
        executed,
        clean_product_chain_baseline,
        runtime_control_api_source_contract_preserved,
        admission,
        service_contract_passed,
        dependency_boundary_preserved,
    );
    let daed_wing_runtime_control_api_regression_recorded =
        runtime_control_api_clean_baseline["recorded"]
            .as_bool()
            .unwrap_or(false);
    let recertification_clean = executed
        && admission.true_rust_default_daemon_admitted
        && service_contract_passed
        && dependency_boundary_preserved
        && clean_product_chain_baseline
        && daed_wing_runtime_control_api_regression_recorded;
    let default_path_mutation_allowed = recertification_clean && default_path_mutation_requested;
    let product_chain_switch_allowed = default_path_mutation_allowed;
    let production_run_command_replacement_plan = production_run_command_replacement_plan_json(
        options,
        default_path_mutation_allowed,
        service_contract_passed,
    );
    let remaining_blockers = remaining_blockers(
        admission,
        &dirty_repos,
        &missing_repos,
        &unavailable_repos,
        runtime_control_api_source_contract_preserved,
        daed_wing_runtime_control_api_regression_recorded,
        default_path_mutation_requested,
    );
    json!({
        "name": "product-chain-recertification",
        "evidence_class": "read-only-default-path-and-product-chain-recertification",
        "execute": executed,
        "read_only": true,
        "artifact_dir": path_string(artifact_dir),
        "manifest_file": path_string(manifest_file),
        "admission_input": {
            "production_dataplane_admitted": admission.production_dataplane_admitted,
            "reload_runtime_parity_admitted": admission.reload_runtime_parity_admitted,
            "matched_go_rust_default_daemon_benchmark_recorded": admission.matched_benchmark_recorded,
            "true_rust_default_daemon_admitted": admission.true_rust_default_daemon_admitted,
        },
        "paths": {
            "dae_repo": path_string(&options.dae_repo),
            "dae_wing_repo": path_string(&options.dae_wing_repo),
            "daed_repo": path_string(&options.daed_repo),
            "outbound_repo": path_string(&options.outbound_repo),
            "quic_go_repo": path_string(&options.quic_go_repo),
            "service_file": path_string(&options.service_file),
            "go_mod_file": path_string(&options.go_mod_file),
        },
        "product_chain_topology": topology,
        "service": service,
        "go_mod": go_mod,
        "runtime_control_api_source_contract": runtime_control_api,
        "sibling_repos": repos,
        "dirty_sibling_repos": dirty_repos,
        "missing_sibling_repos": missing_repos,
        "unavailable_sibling_repos": unavailable_repos,
        "product_chain_recertification_recorded": executed,
        "service_contract_preserved": service_contract_passed,
        "outbound_quic_go_dependency_boundary_preserved": dependency_boundary_preserved,
        "runtime_control_api_source_contract_preserved": runtime_control_api_source_contract_preserved,
        "sibling_repos_present": sibling_repos_present,
        "sibling_repo_status_available": sibling_repo_status_available,
        "clean_product_chain_baseline": clean_product_chain_baseline,
        "runtime_control_api_clean_baseline": runtime_control_api_clean_baseline,
        "daed_wing_runtime_control_api_regression_recorded": daed_wing_runtime_control_api_regression_recorded,
        "product_chain_recertification_clean": recertification_clean,
        "default_path_mutation_requested": default_path_mutation_requested,
        "production_run_command_replacement_plan": production_run_command_replacement_plan,
        "production_run_command_replaced": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "default_path_mutation_allowed": default_path_mutation_allowed,
        "default_switch_allowed": default_path_mutation_allowed,
        "product_chain_switch_allowed": product_chain_switch_allowed,
        "remaining_blockers": remaining_blockers,
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:true-rust-default-daemon-admission",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:15.5",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:install/dae.service"
        ],
    })
}

fn production_run_command_replacement_plan_json(
    options: &ProductChainRecertificationOptions,
    default_path_mutation_allowed: bool,
    service_contract_preserved: bool,
) -> Value {
    let requested = options.production_run_command_replacement_dry_run_requested;
    let go_default_path_preserved = true;
    let admitted = requested
        && default_path_mutation_allowed
        && service_contract_preserved
        && go_default_path_preserved;
    json!({
        "status": if admitted { "pass" } else if requested { "blocked" } else { "not-requested" },
        "requested": requested,
        "dry_run": true,
        "admitted": admitted,
        "default_path_mutation_allowed": default_path_mutation_allowed,
        "service_contract_preserved": service_contract_preserved,
        "go_default_path_preserved": go_default_path_preserved,
        "go_fallback_required": true,
        "service_file": path_string(&options.service_file),
        "current_exec_start_pre": "/usr/bin/dae validate -c /etc/dae/config.dae",
        "current_exec_start": "/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae",
        "current_exec_reload": "/usr/bin/dae reload $MAINPID",
        "target_run_binary": "dae-daemon-optin",
        "target_exec_start_pre": "dae-daemon-optin validate -c /etc/dae/config.dae",
        "target_exec_start": "dae-daemon-optin run --disable-timestamp -c /etc/dae/config.dae",
        "target_exec_reload": "dae-daemon-optin reload $MAINPID",
        "backup_required": true,
        "rollback_required": true,
        "post_replacement_smoke_required": true,
        "pid_progress_compatibility_required": true,
        "actual_mutation_executed": false,
        "production_run_command_replaced": false,
        "read_only": true,
        "installed_usr_bin_dae_exists": Path::new("/usr/bin/dae").exists(),
        "installed_usr_local_bin_dae_exists": Path::new("/usr/local/bin/dae").exists(),
        "evidence_class": "read-only-production-run-command-replacement-dry-run-plan",
    })
}

fn runtime_control_api_clean_baseline_json(
    executed: bool,
    clean_product_chain_baseline: bool,
    runtime_control_api_source_contract_preserved: bool,
    admission: ProductChainAdmissionEvidence,
    service_contract_preserved: bool,
    dependency_boundary_preserved: bool,
) -> Value {
    let recorded = executed
        && clean_product_chain_baseline
        && runtime_control_api_source_contract_preserved
        && admission.true_rust_default_daemon_admitted
        && service_contract_preserved
        && dependency_boundary_preserved;
    json!({
        "status": if recorded { "pass" } else { "fail" },
        "recorded": recorded,
        "execute": executed,
        "clean_product_chain_baseline": clean_product_chain_baseline,
        "runtime_control_api_source_contract_preserved": runtime_control_api_source_contract_preserved,
        "true_rust_default_daemon_admitted": admission.true_rust_default_daemon_admitted,
        "production_dataplane_admitted": admission.production_dataplane_admitted,
        "reload_runtime_parity_admitted": admission.reload_runtime_parity_admitted,
        "matched_go_rust_default_daemon_benchmark_recorded": admission.matched_benchmark_recorded,
        "service_contract_preserved": service_contract_preserved,
        "outbound_quic_go_dependency_boundary_preserved": dependency_boundary_preserved,
        "evidence_class": "read-only-daed-wing-daed-runtime-control-api-clean-baseline",
    })
}

fn service_contract_json(path: &Path) -> Value {
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "status": "fail",
            "path": path_string(path),
            "error": "service file could not be read",
            "service_contract_preserved": false,
        });
    };
    let exec_start_pre = text.contains("ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae");
    let exec_start =
        text.contains("ExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae");
    let exec_reload = text.contains("ExecReload=/usr/bin/dae reload $MAINPID");
    let uses_rust_optin = text.contains("dae-daemon-optin");
    let service_contract_preserved =
        exec_start_pre && exec_start && exec_reload && !uses_rust_optin;
    json!({
        "status": if service_contract_preserved { "pass" } else { "fail" },
        "path": path_string(path),
        "exec_start_pre_validate_preserved": exec_start_pre,
        "exec_start_go_default_run_preserved": exec_start,
        "exec_reload_pid_signal_preserved": exec_reload,
        "rust_optin_binary_referenced": uses_rust_optin,
        "service_contract_preserved": service_contract_preserved,
    })
}

fn go_mod_dependency_boundary_json(
    options: &ProductChainRecertificationOptions,
    topology: &ProductChainTopology,
) -> Value {
    let root = go_mod_file_dependency_boundary_json(
        &options.go_mod_file,
        false,
        &options.outbound_repo,
        &options.quic_go_repo,
    );
    let root_preserved = root["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false);
    if topology.kind == ProductChainTopologyKind::StandaloneDaeWing {
        return json!({
            "status": if root_preserved { "pass" } else { "fail" },
            "topology": topology.chain_name(),
            "path": path_string(&options.go_mod_file),
            "root": root,
            "outbound_quic_go_dependency_boundary_preserved": root_preserved,
        });
    }

    let wing = go_mod_file_dependency_boundary_json(
        &options.dae_wing_repo.join("go.mod"),
        true,
        &options.outbound_repo,
        &options.quic_go_repo,
    );
    let dae_core = go_mod_file_dependency_boundary_json(
        &topology.dae_core_repo.join("go.mod"),
        false,
        &options.outbound_repo,
        &options.quic_go_repo,
    );
    let wing_preserved = wing["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false)
        && wing["dae_core_replace_preserved"]
            .as_bool()
            .unwrap_or(false);
    let dae_core_preserved = dae_core["outbound_quic_go_dependency_boundary_preserved"]
        .as_bool()
        .unwrap_or(false);
    let preserved = root_preserved && wing_preserved && dae_core_preserved;
    json!({
        "status": if preserved { "pass" } else { "fail" },
        "topology": topology.chain_name(),
        "path": path_string(&options.go_mod_file),
        "root": root,
        "wing": wing,
        "dae_core": dae_core,
        "outbound_quic_go_dependency_boundary_preserved": preserved,
    })
}

fn go_mod_file_dependency_boundary_json(
    path: &Path,
    require_dae_core_replace: bool,
    outbound_repo: &Path,
    quic_go_repo: &Path,
) -> Value {
    let Ok(text) = fs::read_to_string(path) else {
        return json!({
            "status": "fail",
            "path": path_string(path),
            "error": "go.mod could not be read",
            "dae_core_replace_preserved": false,
            "outbound_quic_go_dependency_boundary_preserved": false,
        });
    };
    let dae_core_replace = text.contains("replace github.com/daeuniverse/dae => ./dae-core");
    let outbound_replace = dependency_replace_target(
        &text,
        "github.com/daeuniverse/outbound",
        "github.com/ksong008/outbound",
        outbound_repo,
    );
    let quic_go_replace = dependency_replace_target(
        &text,
        "github.com/daeuniverse/quic-go",
        "github.com/ksong008/quic-go",
        quic_go_repo,
    );
    let dae_core_replace_preserved = !require_dae_core_replace || dae_core_replace;
    let preserved =
        dae_core_replace_preserved && outbound_replace.preserved && quic_go_replace.preserved;
    json!({
        "status": if preserved { "pass" } else { "fail" },
        "path": path_string(path),
        "dae_core_replace_required": require_dae_core_replace,
        "dae_core_replace_preserved": dae_core_replace_preserved,
        "outbound_replace_preserved": outbound_replace.preserved,
        "outbound_replace_target": outbound_replace.target,
        "outbound_local_replace_preserved": outbound_replace.local_preserved,
        "outbound_remote_replace_preserved": outbound_replace.remote_preserved,
        "quic_go_replace_preserved": quic_go_replace.preserved,
        "quic_go_replace_target": quic_go_replace.target,
        "quic_go_local_replace_preserved": quic_go_replace.local_preserved,
        "quic_go_remote_replace_preserved": quic_go_replace.remote_preserved,
        "outbound_quic_go_still_required": true,
        "outbound_quic_go_dependency_boundary_preserved": preserved,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencyReplaceTarget {
    preserved: bool,
    local_preserved: bool,
    remote_preserved: bool,
    target: &'static str,
}

fn dependency_replace_target(
    text: &str,
    module: &str,
    remote_module: &str,
    local_repo: &Path,
) -> DependencyReplaceTarget {
    let remote_preserved = text.contains(&format!("replace {module} => {remote_module}"));
    let local_preserved =
        text.contains(&format!("replace {module} => {}", path_string(local_repo)));
    let target = match (local_preserved, remote_preserved) {
        (true, _) => "local",
        (false, true) => "remote",
        (false, false) => "missing",
    };
    DependencyReplaceTarget {
        preserved: local_preserved || remote_preserved,
        local_preserved,
        remote_preserved,
        target,
    }
}

fn runtime_control_api_source_contract_json(
    dae_wing_repo: &Path,
    daed_repo: &Path,
    topology: &ProductChainTopology,
) -> Value {
    let dae_wing = dae_wing_runtime_control_source_contract_json(dae_wing_repo, topology);
    let daed = daed_runtime_control_source_contract_json(daed_repo);
    let dae_wing_passed = dae_wing["source_contract_preserved"]
        .as_bool()
        .unwrap_or(false);
    let daed_passed = daed["source_contract_preserved"].as_bool().unwrap_or(false);
    json!({
        "status": if dae_wing_passed && daed_passed { "pass" } else { "fail" },
        "runtime_control_api_source_contract_recorded": true,
        "runtime_control_api_source_contract_preserved": dae_wing_passed && daed_passed,
        "product_chain_topology": topology.as_json(dae_wing_repo, daed_repo),
        "dae_wing_runtime_control_api_source_contract_preserved": dae_wing_passed,
        "daed_runtime_control_api_source_contract_preserved": daed_passed,
        "dae_wing": dae_wing,
        "daed": daed,
    })
}

fn dae_wing_runtime_control_source_contract_json(
    repo: &Path,
    topology: &ProductChainTopology,
) -> Value {
    let files = match topology.kind {
        ProductChainTopologyKind::Daed2Wing => daed2_wing_runtime_control_source_files(repo),
        ProductChainTopologyKind::StandaloneDaeWing => {
            standalone_dae_wing_runtime_control_source_files(repo)
        }
    };
    source_contract_group_json(
        repo,
        &format!("{}-runtime-control-api", topology.wing_repo_label()),
        files,
    )
}

fn daed2_wing_runtime_control_source_files(repo: &Path) -> Vec<Value> {
    vec![
        source_file_contract_json(
            repo,
            "cmd/run.go",
            &[
                ("engine_default_run", "engine.Default().Run("),
                ("restore_running_state", "orchestrator.RestoreRunningState("),
                ("control_plane_api_mount", "mux.Handle(\"/api/\""),
                (
                    "control_plane_api_strip_prefix",
                    "http.StripPrefix(\"/api\", httpapi.NewHandler())",
                ),
                ("runtime_events_api_path", "\"/api/events/runtime\""),
            ],
        ),
        source_file_contract_json(
            repo,
            "transport/httpapi/handler.go",
            &[
                (
                    "runtime_overview_endpoint",
                    "mux.HandleFunc(\"/runtime/overview\"",
                ),
                (
                    "runtime_reload_endpoint",
                    "mux.HandleFunc(\"/runtime/reload\"",
                ),
                ("runtime_stop_endpoint", "mux.HandleFunc(\"/runtime/stop\""),
                (
                    "runtime_events_endpoint",
                    "mux.HandleFunc(\"/events/runtime\"",
                ),
                (
                    "overview_calls_engine_default",
                    "engine.Default().GetRuntimeOverview(windowSec, maxPoints)",
                ),
                (
                    "reload_calls_orchestrator_run",
                    "orchestrator.Run(ctx, req.Dry)",
                ),
                (
                    "stop_calls_orchestrator_stop",
                    "orchestrator.Stop(r.Context(), timeout)",
                ),
            ],
        ),
        source_file_contract_json(
            repo,
            "orchestrator/config_run.go",
            &[
                (
                    "dry_run_reload_with_empty_config",
                    "engine.Default().ReloadContext(ctx, engine.Default().EmptyConfig())",
                ),
                ("parse_config", "engine.Default().ParseConfig("),
                (
                    "necessary_outbounds",
                    "engine.Default().NecessaryOutbounds(",
                ),
                (
                    "real_reload_with_context",
                    "engine.Default().ReloadContext(ctx, c)",
                ),
                ("stop_engine_default", "engine.Default().Stop(timeout)"),
            ],
        ),
        source_file_contract_json(
            repo,
            "engine/engine.go",
            &[
                ("default_service", "func Default() Service"),
                (
                    "reload_context",
                    "ReloadContext(ctx context.Context, conf *daeConfig.Config) error",
                ),
                (
                    "get_runtime_overview",
                    "GetRuntimeOverview(windowSec int, maxPoints int)",
                ),
                ("dae_engine_wrapper", "daeengine"),
            ],
        ),
        source_file_contract_json(
            repo,
            "dae-core/engine/runtime.go",
            &[
                ("dae_core_run", "func (e *Engine) Run("),
                (
                    "dae_core_reload_with_context",
                    "func (e *Engine) ReloadWithContext(",
                ),
                ("dae_core_stop", "func (e *Engine) Stop("),
                (
                    "dae_core_runtime_overview",
                    "func (e *Engine) GetRuntimeOverview(",
                ),
                (
                    "dae_core_http_transport",
                    "func (e *Engine) HTTPTransport()",
                ),
            ],
        ),
    ]
}

fn standalone_dae_wing_runtime_control_source_files(repo: &Path) -> Vec<Value> {
    vec![
        source_file_contract_json(
            repo,
            "cmd/run.go",
            &[
                (
                    "runtime_lifecycle_service_run",
                    "engine.DefaultRuntimeLifecycleService().Run(",
                ),
                ("restore_running_state", "orchestrator.RestoreRunningState("),
                ("control_plane_api_handler", "httpapi.NewHandler()"),
                ("api_only_mode_preserved", "apiOnly"),
            ],
        ),
        source_file_contract_json(
            repo,
            "transport/httpapi/handler.go",
            &[
                (
                    "runtime_overview_endpoint",
                    "mux.HandleFunc(\"/runtime/overview\"",
                ),
                (
                    "runtime_reload_endpoint",
                    "mux.HandleFunc(\"/runtime/reload\"",
                ),
                ("runtime_stop_endpoint", "mux.HandleFunc(\"/runtime/stop\""),
                (
                    "runtime_events_endpoint",
                    "mux.HandleFunc(\"/events/runtime\"",
                ),
                (
                    "overview_calls_runtime_status_port",
                    "GetRuntimeOverview(windowSec, maxPoints)",
                ),
                (
                    "reload_calls_orchestrator_run",
                    "orchestrator.Run(ctx, req.Dry)",
                ),
                (
                    "stop_calls_orchestrator_stop",
                    "orchestrator.Stop(r.Context(), timeout)",
                ),
            ],
        ),
        source_file_contract_json(
            repo,
            "transport/httpapi/service_port.go",
            &[
                (
                    "runtime_status_port_get_overview",
                    "GetRuntimeOverview(windowSec int, maxPoints int)",
                ),
                (
                    "runtime_access_service_provider",
                    "engine.DefaultRuntimeAccessService()",
                ),
            ],
        ),
        source_file_contract_json(
            repo,
            "orchestrator/config_run.go",
            &[
                ("runtime_lifecycle_lock", "lockRuntimeLifecycle()"),
                ("reload_with_context", "ReloadWithContext(ctx, c)"),
                (
                    "dry_run_reload_with_empty_config",
                    "ReloadWithContext(ctx, engine.DefaultConfigService().EmptyConfig())",
                ),
                (
                    "restore_running_state_entrypoint",
                    "RestoreRunningState(ctx context.Context)",
                ),
                (
                    "stop_runtime_lifecycle_service",
                    "engine.DefaultRuntimeLifecycleService().Stop(timeout)",
                ),
            ],
        ),
    ]
}

fn daed_runtime_control_source_contract_json(repo: &Path) -> Value {
    let files = vec![
        source_file_contract_json(
            repo,
            "apps/web/src/apis/mutation.ts",
            &[
                ("reload_mutation_posts_runtime_reload", "'/runtime/reload'"),
                ("stop_mutation_posts_runtime_stop", "'/runtime/stop'"),
                ("reload_invalidates_general_query", "QUERY_KEY_GENERAL"),
            ],
        ),
        source_file_contract_json(
            repo,
            "apps/web/src/apis/query.ts",
            &[
                ("runtime_overview_get", "'/runtime/overview'"),
                ("runtime_events_sse_url", "'/events/runtime'"),
                ("runtime_overview_full_event", "'runtime.overview'"),
                ("runtime_overview_delta_event", "'runtime.overview.delta'"),
                (
                    "runtime_overview_delta_merge",
                    "mergeRuntimeOverviewDelta(previousData, payload, windowSec, maxPoints)",
                ),
            ],
        ),
        source_file_contract_json(
            repo,
            "apps/web/src/apis/runtime_overview.ts",
            &[
                ("runtime_overview_adapter", "adaptRuntimeOverview"),
                (
                    "runtime_overview_delta_merge_fn",
                    "mergeRuntimeOverviewDelta",
                ),
                ("runtime_overview_sample_trim", "trimRuntimeOverviewSamples"),
            ],
        ),
        source_file_contract_json(
            repo,
            "apps/web/src/components/Header.tsx",
            &[
                ("header_uses_reload_mutation", "useReloadRuntimeMutation()"),
                ("header_uses_stop_mutation", "useStopRuntimeMutation()"),
                (
                    "header_reload_action",
                    "reloadRuntimeMutation.mutate({ dry: false })",
                ),
            ],
        ),
        source_file_contract_json(
            repo,
            "wing/transport/httpapi/handler.go",
            &[
                (
                    "backend_runtime_overview_endpoint",
                    "mux.HandleFunc(\"/runtime/overview\"",
                ),
                (
                    "backend_runtime_reload_endpoint",
                    "mux.HandleFunc(\"/runtime/reload\"",
                ),
                (
                    "backend_runtime_events_endpoint",
                    "mux.HandleFunc(\"/events/runtime\"",
                ),
            ],
        ),
    ];
    source_contract_group_json(repo, "daed-runtime-control-api", files)
}

fn source_contract_group_json(repo: &Path, name: &str, files: Vec<Value>) -> Value {
    let source_contract_preserved = files
        .iter()
        .all(|file| file["source_contract_preserved"].as_bool().unwrap_or(false));
    json!({
        "name": name,
        "repo": path_string(repo),
        "status": if source_contract_preserved { "pass" } else { "fail" },
        "source_contract_preserved": source_contract_preserved,
        "files": files,
    })
}

fn source_file_contract_json(repo: &Path, relative: &str, checks: &[(&str, &str)]) -> Value {
    let path = repo.join(relative);
    let Ok(text) = fs::read_to_string(&path) else {
        let mut check_values = Map::new();
        for (name, _) in checks {
            check_values.insert((*name).to_owned(), json!(false));
        }
        return json!({
            "relative_path": relative,
            "path": path_string(&path),
            "status": "fail",
            "readable": false,
            "checks": check_values,
            "source_contract_preserved": false,
        });
    };
    let mut check_values = Map::new();
    let mut passed = true;
    for (name, needle) in checks {
        let found = text.contains(needle);
        if !found {
            passed = false;
        }
        check_values.insert((*name).to_owned(), json!(found));
    }
    json!({
        "relative_path": relative,
        "path": path_string(&path),
        "status": if passed { "pass" } else { "fail" },
        "readable": true,
        "checks": check_values,
        "source_contract_preserved": passed,
    })
}

fn repo_status_json(name: &str, path: &Path) -> Value {
    if !path.is_dir() {
        return json!({
            "name": name,
            "path": path_string(path),
            "exists": false,
            "git_status_available": false,
            "dirty": false,
        });
    }
    let output = Command::new("git")
        .args(["status", "--short", "--branch"])
        .current_dir(path)
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let dirty = stdout
                .lines()
                .any(|line| !line.trim().is_empty() && !line.starts_with("##"));
            json!({
                "name": name,
                "path": path_string(path),
                "exists": true,
                "git_status_available": output.status.success(),
                "dirty": dirty,
                "status": if output.status.success() { "pass" } else { "fail" },
                "branch": stdout.lines().next().unwrap_or_default(),
                "stdout": stdout,
                "stderr": stderr,
            })
        }
        Err(err) => json!({
            "name": name,
            "path": path_string(path),
            "exists": true,
            "git_status_available": false,
            "dirty": false,
            "status": "fail",
            "error": err.to_string(),
        }),
    }
}

fn remaining_blockers(
    admission: ProductChainAdmissionEvidence,
    dirty_repos: &[String],
    missing_repos: &[String],
    unavailable_repos: &[String],
    runtime_control_api_source_contract_preserved: bool,
    daed_wing_runtime_control_api_regression_recorded: bool,
    default_path_mutation_requested: bool,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if !admission.true_rust_default_daemon_admitted {
        blockers.push("true Rust default daemon admission is not present in this run".to_owned());
    }
    if !default_path_mutation_requested {
        blockers.push(
            "default path mutation was not explicitly requested; service and /usr/bin/dae remain Go-default"
                .to_owned(),
        );
    }
    if !dirty_repos.is_empty() {
        blockers.push(format!(
            "product-chain baseline is dirty in sibling repos: {}",
            dirty_repos.join(", ")
        ));
    }
    if !missing_repos.is_empty() {
        blockers.push(format!(
            "product-chain sibling repos are missing: {}",
            missing_repos.join(", ")
        ));
    }
    if !unavailable_repos.is_empty() {
        blockers.push(format!(
            "product-chain sibling repo git status is unavailable: {}",
            unavailable_repos.join(", ")
        ));
    }
    if !runtime_control_api_source_contract_preserved {
        blockers.push(
            "dae-wing/daed runtime/control API source contract is incomplete or unreadable"
                .to_owned(),
        );
    }
    if !daed_wing_runtime_control_api_regression_recorded {
        blockers.push(
            "dae-wing and daed runtime/control API recertification still needs an explicit clean baseline run"
                .to_owned(),
        );
    }
    blockers
}

fn ensure_safe_run_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err(format!(
            "product-chain recertification run root must be absolute: {}",
            path_string(root)
        ));
    }
    let root_string = path_string(root);
    if !root_string.starts_with("/tmp/dae-daemon") {
        return Err(format!(
            "product-chain recertification run root must be under /tmp/dae-daemon*: {root_string}"
        ));
    }
    Ok(())
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_chain_recertification_is_read_only_by_default() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-default-{}",
            std::process::id()
        ));
        let report = product_chain_recertification_report(
            &root,
            &ProductChainRecertificationOptions::default(),
            ProductChainAdmissionEvidence::default(),
        )
        .unwrap();
        assert!(!report["execute"].as_bool().unwrap());
        assert!(
            !report["product_chain_recertification_recorded"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["default_switch_allowed"].as_bool().unwrap());
        assert!(!report["product_chain_switch_allowed"].as_bool().unwrap());
    }

    #[test]
    fn product_chain_recertification_records_service_and_go_mod_boundaries() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-record-{}",
            std::process::id()
        ));
        let fixture = root.join("fixture");
        std::fs::create_dir_all(&fixture).unwrap();
        let service = fixture.join("dae.service");
        let go_mod = fixture.join("go.mod");
        std::fs::write(
            &service,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
        std::fs::write(
            &go_mod,
            "replace github.com/daeuniverse/outbound => github.com/ksong008/outbound v0.0.0\nreplace github.com/daeuniverse/quic-go => github.com/ksong008/quic-go v0.0.0\n",
        )
        .unwrap();
        for repo in ["dae", "dae-wing", "daed", "outbound", "quic-go"] {
            let repo_dir = fixture.join(repo);
            std::fs::create_dir_all(&repo_dir).unwrap();
            assert!(
                Command::new("git")
                    .args(["init", "--quiet"])
                    .current_dir(&repo_dir)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let options = ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: false,
            production_run_command_replacement_dry_run_requested: false,
            dae_repo: fixture.join("dae"),
            dae_wing_repo: fixture.join("dae-wing"),
            daed_repo: fixture.join("daed"),
            outbound_repo: fixture.join("outbound"),
            quic_go_repo: fixture.join("quic-go"),
            service_file: service,
            go_mod_file: go_mod,
        };
        let report = product_chain_recertification_report(
            &root,
            &options,
            ProductChainAdmissionEvidence {
                true_rust_default_daemon_admitted: true,
                production_dataplane_admitted: true,
                reload_runtime_parity_admitted: true,
                matched_benchmark_recorded: true,
            },
        )
        .unwrap();
        assert!(
            report["product_chain_recertification_recorded"]
                .as_bool()
                .unwrap()
        );
        assert!(report["service_contract_preserved"].as_bool().unwrap());
        assert!(
            report["outbound_quic_go_dependency_boundary_preserved"]
                .as_bool()
                .unwrap()
        );
        assert!(report["sibling_repos_present"].as_bool().unwrap());
        assert!(report["sibling_repo_status_available"].as_bool().unwrap());
        assert!(report["clean_product_chain_baseline"].as_bool().unwrap());
        assert!(
            !report["daed_wing_runtime_control_api_regression_recorded"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !report["product_chain_recertification_clean"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["default_switch_allowed"].as_bool().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn product_chain_clean_baseline_records_runtime_control_api_regression_without_switching_default_path()
     {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-clean-api-baseline-{}",
            std::process::id()
        ));
        let artifact_dir = root.join("artifact");
        let manifest_file = artifact_dir.join("product-chain-recertification.json");
        let evidence = clean_product_chain_evidence();
        let options = ProductChainRecertificationOptions {
            execute: true,
            ..ProductChainRecertificationOptions::default()
        };
        let report = report_value(
            &options,
            &artifact_dir,
            &manifest_file,
            ProductChainAdmissionEvidence {
                true_rust_default_daemon_admitted: true,
                production_dataplane_admitted: true,
                reload_runtime_parity_admitted: true,
                matched_benchmark_recorded: true,
            },
            Some(evidence),
        );
        assert!(
            report["runtime_control_api_clean_baseline"]["recorded"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["daed_wing_runtime_control_api_regression_recorded"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["product_chain_recertification_clean"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["default_path_mutation_allowed"].as_bool().unwrap());
        assert!(!report["default_switch_allowed"].as_bool().unwrap());
        assert!(!report["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(
            report["remaining_blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|blocker| blocker.as_str().unwrap().contains("default path mutation"))
        );
        assert!(
            !report["remaining_blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|blocker| blocker.as_str().unwrap().contains("runtime/control API"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn product_chain_default_path_mutation_request_allows_switch_without_replacing_run_command() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-default-path-request-{}",
            std::process::id()
        ));
        let artifact_dir = root.join("artifact");
        let manifest_file = artifact_dir.join("product-chain-recertification.json");
        let options = ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            ..ProductChainRecertificationOptions::default()
        };
        let report = report_value(
            &options,
            &artifact_dir,
            &manifest_file,
            ProductChainAdmissionEvidence {
                true_rust_default_daemon_admitted: true,
                production_dataplane_admitted: true,
                reload_runtime_parity_admitted: true,
                matched_benchmark_recorded: true,
            },
            Some(clean_product_chain_evidence()),
        );
        assert!(report["default_path_mutation_requested"].as_bool().unwrap());
        assert!(report["default_path_mutation_allowed"].as_bool().unwrap());
        assert!(report["default_switch_allowed"].as_bool().unwrap());
        assert!(report["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(
            report["product_chain_recertification_clean"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["production_run_command_replaced"].as_bool().unwrap());
        assert!(report["read_only"].as_bool().unwrap());
        assert!(report["remaining_blockers"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn product_chain_run_command_replacement_plan_is_read_only_and_admitted_after_default_request()
    {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-run-command-plan-{}",
            std::process::id()
        ));
        let artifact_dir = root.join("artifact");
        let manifest_file = artifact_dir.join("product-chain-recertification.json");
        let options = ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: true,
            production_run_command_replacement_dry_run_requested: true,
            ..ProductChainRecertificationOptions::default()
        };
        let report = report_value(
            &options,
            &artifact_dir,
            &manifest_file,
            ProductChainAdmissionEvidence {
                true_rust_default_daemon_admitted: true,
                production_dataplane_admitted: true,
                reload_runtime_parity_admitted: true,
                matched_benchmark_recorded: true,
            },
            Some(clean_product_chain_evidence()),
        );
        let plan = &report["production_run_command_replacement_plan"];
        assert!(plan["requested"].as_bool().unwrap());
        assert!(plan["dry_run"].as_bool().unwrap());
        assert!(plan["admitted"].as_bool().unwrap());
        assert!(plan["backup_required"].as_bool().unwrap());
        assert!(plan["rollback_required"].as_bool().unwrap());
        assert!(plan["post_replacement_smoke_required"].as_bool().unwrap());
        assert!(!plan["actual_mutation_executed"].as_bool().unwrap());
        assert!(!plan["production_run_command_replaced"].as_bool().unwrap());
        assert!(plan["read_only"].as_bool().unwrap());
        assert!(!report["production_run_command_replaced"].as_bool().unwrap());
        assert!(report["read_only"].as_bool().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn product_chain_recertification_blocks_when_repo_status_is_unavailable() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-nongit-{}",
            std::process::id()
        ));
        let fixture = root.join("fixture");
        std::fs::create_dir_all(&fixture).unwrap();
        let service = fixture.join("dae.service");
        let go_mod = fixture.join("go.mod");
        std::fs::write(
            &service,
            "ExecStartPre=/usr/bin/dae validate -c /etc/dae/config.dae\nExecStart=/usr/bin/dae run --disable-timestamp -c /etc/dae/config.dae\nExecReload=/usr/bin/dae reload $MAINPID\n",
        )
        .unwrap();
        std::fs::write(
            &go_mod,
            "replace github.com/daeuniverse/outbound => github.com/ksong008/outbound v0.0.0\nreplace github.com/daeuniverse/quic-go => github.com/ksong008/quic-go v0.0.0\n",
        )
        .unwrap();
        for repo in ["dae", "dae-wing", "daed", "outbound", "quic-go"] {
            std::fs::create_dir_all(fixture.join(repo)).unwrap();
        }
        let options = ProductChainRecertificationOptions {
            execute: true,
            default_path_mutation_requested: false,
            production_run_command_replacement_dry_run_requested: false,
            dae_repo: fixture.join("dae"),
            dae_wing_repo: fixture.join("dae-wing"),
            daed_repo: fixture.join("daed"),
            outbound_repo: fixture.join("outbound"),
            quic_go_repo: fixture.join("quic-go"),
            service_file: service,
            go_mod_file: go_mod,
        };
        let report = product_chain_recertification_report(
            &root,
            &options,
            ProductChainAdmissionEvidence {
                true_rust_default_daemon_admitted: true,
                production_dataplane_admitted: true,
                reload_runtime_parity_admitted: true,
                matched_benchmark_recorded: true,
            },
        )
        .unwrap();
        assert!(report["sibling_repos_present"].as_bool().unwrap());
        assert!(!report["sibling_repo_status_available"].as_bool().unwrap());
        assert!(
            !report["unavailable_sibling_repos"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!report["clean_product_chain_baseline"].as_bool().unwrap());
        assert!(
            !report["product_chain_recertification_clean"]
                .as_bool()
                .unwrap()
        );
        assert!(!report["default_switch_allowed"].as_bool().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_control_api_source_contract_records_dae_wing_and_daed_surfaces() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-api-contract-{}",
            std::process::id()
        ));
        let dae_wing = root.join("dae-wing");
        let daed = root.join("daed");
        write_fixture_file(
            &dae_wing.join("cmd/run.go"),
            "engine.DefaultRuntimeLifecycleService().Run(\norchestrator.RestoreRunningState(\nhttpapi.NewHandler()\napiOnly\n",
        );
        write_fixture_file(
            &dae_wing.join("transport/httpapi/handler.go"),
            "mux.HandleFunc(\"/runtime/overview\"\nmux.HandleFunc(\"/runtime/reload\"\nmux.HandleFunc(\"/runtime/stop\"\nmux.HandleFunc(\"/events/runtime\"\nGetRuntimeOverview(windowSec, maxPoints)\norchestrator.Run(ctx, req.Dry)\norchestrator.Stop(r.Context(), timeout)\n",
        );
        write_fixture_file(
            &dae_wing.join("transport/httpapi/service_port.go"),
            "GetRuntimeOverview(windowSec int, maxPoints int)\nengine.DefaultRuntimeAccessService()\n",
        );
        write_fixture_file(
            &dae_wing.join("orchestrator/config_run.go"),
            "lockRuntimeLifecycle()\nReloadWithContext(ctx, c)\nReloadWithContext(ctx, engine.DefaultConfigService().EmptyConfig())\nRestoreRunningState(ctx context.Context)\nengine.DefaultRuntimeLifecycleService().Stop(timeout)\n",
        );
        write_fixture_file(
            &daed.join("apps/web/src/apis/mutation.ts"),
            "'/runtime/reload'\n'/runtime/stop'\nQUERY_KEY_GENERAL\n",
        );
        write_fixture_file(
            &daed.join("apps/web/src/apis/query.ts"),
            "'/runtime/overview'\n'/events/runtime'\n'runtime.overview'\n'runtime.overview.delta'\nmergeRuntimeOverviewDelta(previousData, payload, windowSec, maxPoints)\n",
        );
        write_fixture_file(
            &daed.join("apps/web/src/apis/runtime_overview.ts"),
            "adaptRuntimeOverview\nmergeRuntimeOverviewDelta\ntrimRuntimeOverviewSamples\n",
        );
        write_fixture_file(
            &daed.join("apps/web/src/components/Header.tsx"),
            "useReloadRuntimeMutation()\nuseStopRuntimeMutation()\nreloadRuntimeMutation.mutate({ dry: false })\n",
        );
        write_fixture_file(
            &daed.join("wing/transport/httpapi/handler.go"),
            "mux.HandleFunc(\"/runtime/overview\"\nmux.HandleFunc(\"/runtime/reload\"\nmux.HandleFunc(\"/events/runtime\"\n",
        );

        let topology = ProductChainTopology {
            kind: ProductChainTopologyKind::StandaloneDaeWing,
            dae_core_repo: dae_wing.join("dae-core"),
        };
        let report = runtime_control_api_source_contract_json(&dae_wing, &daed, &topology);
        assert!(
            report["runtime_control_api_source_contract_recorded"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["runtime_control_api_source_contract_preserved"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["dae_wing_runtime_control_api_source_contract_preserved"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["daed_runtime_control_api_source_contract_preserved"]
                .as_bool()
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_control_api_source_contract_accepts_daed2_wing_shape() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-daed2-contract-{}",
            std::process::id()
        ));
        let daed = root.join("daed");
        let wing = daed.join("wing");
        write_fixture_file(
            &daed.join("apps/web/src/apis/mutation.ts"),
            "'/runtime/reload'\n'/runtime/stop'\nQUERY_KEY_GENERAL\n",
        );
        write_fixture_file(
            &daed.join("apps/web/src/apis/query.ts"),
            "'/runtime/overview'\n'/events/runtime'\n'runtime.overview'\n'runtime.overview.delta'\nmergeRuntimeOverviewDelta(previousData, payload, windowSec, maxPoints)\n",
        );
        write_fixture_file(
            &daed.join("apps/web/src/apis/runtime_overview.ts"),
            "adaptRuntimeOverview\nmergeRuntimeOverviewDelta\ntrimRuntimeOverviewSamples\n",
        );
        write_fixture_file(
            &daed.join("apps/web/src/components/Header.tsx"),
            "useReloadRuntimeMutation()\nuseStopRuntimeMutation()\nreloadRuntimeMutation.mutate({ dry: false })\n",
        );
        write_fixture_file(
            &daed.join("wing/transport/httpapi/handler.go"),
            "mux.HandleFunc(\"/runtime/overview\"\nmux.HandleFunc(\"/runtime/reload\"\nmux.HandleFunc(\"/runtime/stop\"\nmux.HandleFunc(\"/events/runtime\"\nengine.Default().GetRuntimeOverview(windowSec, maxPoints)\norchestrator.Run(ctx, req.Dry)\norchestrator.Stop(r.Context(), timeout)\n",
        );
        write_fixture_file(
            &wing.join("cmd/run.go"),
            "engine.Default().Run(\norchestrator.RestoreRunningState(\nmux.Handle(\"/api/\"\nhttp.StripPrefix(\"/api\", httpapi.NewHandler())\n\"/api/events/runtime\"\n",
        );
        write_fixture_file(
            &wing.join("orchestrator/config_run.go"),
            "engine.Default().ReloadContext(ctx, engine.Default().EmptyConfig())\nengine.Default().ParseConfig(\nengine.Default().NecessaryOutbounds(\nengine.Default().ReloadContext(ctx, c)\nengine.Default().Stop(timeout)\n",
        );
        write_fixture_file(
            &wing.join("engine/engine.go"),
            "func Default() Service\nReloadContext(ctx context.Context, conf *daeConfig.Config) error\nGetRuntimeOverview(windowSec int, maxPoints int)\ndaeengine\n",
        );
        write_fixture_file(
            &wing.join("dae-core/engine/runtime.go"),
            "func (e *Engine) Run(\nfunc (e *Engine) ReloadWithContext(\nfunc (e *Engine) Stop(\nfunc (e *Engine) GetRuntimeOverview(\nfunc (e *Engine) HTTPTransport()\n",
        );
        assert!(!wing.join("transport/httpapi/service_port.go").exists());

        let topology = ProductChainTopology {
            kind: ProductChainTopologyKind::Daed2Wing,
            dae_core_repo: wing.join("dae-core"),
        };
        let report = runtime_control_api_source_contract_json(&wing, &daed, &topology);
        assert_eq!(
            report["product_chain_topology"]["chain"].as_str().unwrap(),
            "daed2.0-web-wing-daecore"
        );
        assert!(
            report["runtime_control_api_source_contract_preserved"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["dae_wing_runtime_control_api_source_contract_preserved"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["daed_runtime_control_api_source_contract_preserved"]
                .as_bool()
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn daed2_dependency_boundary_requires_wing_and_dae_core_replaces() {
        let root = std::env::temp_dir().join(format!(
            "dae-daemon-product-chain-daed2-boundary-{}",
            std::process::id()
        ));
        let daed = root.join("daed");
        let wing = daed.join("wing");
        let dae_go_mod = root.join("dae.go.mod");
        let outbound = root.join("outbound");
        let quic_go = root.join("quic-go");
        write_fixture_file(
            &dae_go_mod,
            &format!(
                "replace github.com/daeuniverse/outbound => {}\nreplace github.com/daeuniverse/quic-go => {}\n",
                path_string(&outbound),
                path_string(&quic_go)
            ),
        );
        write_fixture_file(
            &wing.join("go.mod"),
            &format!(
                "replace github.com/daeuniverse/dae => ./dae-core\nreplace github.com/daeuniverse/outbound => {}\nreplace github.com/daeuniverse/quic-go => {}\n",
                path_string(&outbound),
                path_string(&quic_go)
            ),
        );
        write_fixture_file(
            &wing.join("dae-core/go.mod"),
            &format!(
                "replace github.com/daeuniverse/outbound => {}\nreplace github.com/daeuniverse/quic-go => {}\n",
                path_string(&outbound),
                path_string(&quic_go)
            ),
        );
        let options = ProductChainRecertificationOptions {
            dae_wing_repo: wing.clone(),
            daed_repo: daed.clone(),
            outbound_repo: outbound,
            quic_go_repo: quic_go,
            go_mod_file: dae_go_mod,
            ..ProductChainRecertificationOptions::default()
        };
        let topology = product_chain_topology(&options);
        let report = go_mod_dependency_boundary_json(&options, &topology);
        assert_eq!(topology.kind, ProductChainTopologyKind::Daed2Wing);
        assert_eq!(
            report["topology"].as_str().unwrap(),
            "daed2.0-web-wing-daecore"
        );
        assert!(
            report["outbound_quic_go_dependency_boundary_preserved"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report["wing"]["dae_core_replace_preserved"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            report["wing"]["outbound_replace_target"].as_str().unwrap(),
            "local"
        );
        assert_eq!(
            report["wing"]["quic_go_replace_target"].as_str().unwrap(),
            "local"
        );
        assert!(
            report["dae_core"]["outbound_quic_go_dependency_boundary_preserved"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            report["dae_core"]["outbound_replace_target"]
                .as_str()
                .unwrap(),
            "local"
        );
        assert_eq!(
            report["dae_core"]["quic_go_replace_target"]
                .as_str()
                .unwrap(),
            "local"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    fn write_fixture_file(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn clean_product_chain_evidence() -> ProductChainEvidence {
        ProductChainEvidence {
            topology: json!({
                "chain": "daed2.0-web-wing-daecore",
                "daed2_wing_repo_used": true,
                "standalone_dae_wing_repo_used": false,
            }),
            service: json!({
                "status": "pass",
                "service_contract_preserved": true,
            }),
            go_mod: json!({
                "status": "pass",
                "outbound_quic_go_dependency_boundary_preserved": true,
            }),
            repos: Vec::new(),
            runtime_control_api: json!({
                "status": "pass",
                "runtime_control_api_source_contract_preserved": true,
            }),
            dirty_repos: Vec::new(),
            missing_repos: Vec::new(),
            unavailable_repos: Vec::new(),
        }
    }
}
