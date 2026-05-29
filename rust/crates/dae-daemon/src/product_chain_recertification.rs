use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

mod daed2_rehearsal;
mod dependency_boundary;
mod host_write_freeze;
mod host_write_safety;
mod local_validation;
mod readiness;
mod repo_inspection;
mod rollback_model;
mod run_command_replacement;
mod runtime_control_contract;
mod service_contract;
mod support;
mod topology;
mod typed_report;

use daed2_rehearsal::{
    attach_daed2_product_chain_switch_rehearsal,
    materialize_daed2_product_chain_switch_rehearsal_report,
};
use dependency_boundary::go_mod_dependency_boundary_json;
use host_write_freeze::{
    attach_production_host_write_plan_freeze, materialize_production_host_write_plan_freeze_report,
};
use host_write_safety::{
    production_run_command_apply_plan_blockers, production_run_command_execution_blockers,
};
use local_validation::{
    attach_local_validation_fresh_install_plan, materialize_local_validation_fresh_install_plan,
};
use readiness::{
    attach_production_replacement_readiness, materialize_production_replacement_readiness_report,
};
use repo_inspection::{expected_product_chain_branch, repo_status_json};
use run_command_replacement::{
    attach_production_run_command_replacement_artifacts,
    materialize_production_run_command_replacement_artifacts,
    production_run_command_replacement_plan_json,
};
use runtime_control_contract::runtime_control_api_source_contract_json;
use service_contract::{candidate_service_contract_report, service_contract_json};
use support::{ensure_safe_run_root, path_string};
use topology::product_chain_topology;
#[cfg(test)]
use topology::{ProductChainTopology, ProductChainTopologyKind};
use typed_report::{
    ProductChainTypedReportSummary, remaining_blockers, runtime_control_api_clean_baseline_json,
    value_string_array,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductChainRecertificationOptions {
    pub execute: bool,
    pub default_path_mutation_requested: bool,
    pub production_run_command_replacement_dry_run_requested: bool,
    pub production_run_command_replacement_execute_requested: bool,
    pub production_run_command_replacement_apply_plan_requested: bool,
    pub host_default_path_mutation_allow_requested: bool,
    pub local_validation_fresh_install_plan_requested: bool,
    pub local_validation_config_source: Option<PathBuf>,
    pub local_validation_binary_source: Option<PathBuf>,
    pub resident_default_daemon_binary_source: Option<PathBuf>,
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
            production_run_command_replacement_execute_requested: false,
            production_run_command_replacement_apply_plan_requested: false,
            host_default_path_mutation_allow_requested: false,
            local_validation_fresh_install_plan_requested: false,
            local_validation_config_source: None,
            local_validation_binary_source: None,
            resident_default_daemon_binary_source: None,
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
    pub bpf_go_fallback_retired: bool,
    pub true_rust_default_daemon_admitted: bool,
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
    let mut report = report_value(
        options,
        &artifact_dir,
        &manifest_file,
        admission,
        Some(evidence),
    );
    let production_run_command_artifacts =
        materialize_production_run_command_replacement_artifacts(options, &report, &artifact_dir)?;
    attach_production_run_command_replacement_artifacts(
        &mut report,
        production_run_command_artifacts,
    );
    let production_replacement_readiness =
        materialize_production_replacement_readiness_report(&report, &artifact_dir)?;
    attach_production_replacement_readiness(&mut report, production_replacement_readiness);
    let daed2_switch_rehearsal =
        materialize_daed2_product_chain_switch_rehearsal_report(&report, &artifact_dir)?;
    attach_daed2_product_chain_switch_rehearsal(&mut report, daed2_switch_rehearsal);
    let local_validation_fresh_install_plan =
        materialize_local_validation_fresh_install_plan(options, &report, &artifact_dir)?;
    attach_local_validation_fresh_install_plan(&mut report, local_validation_fresh_install_plan);
    let host_write_plan_freeze =
        materialize_production_host_write_plan_freeze_report(&report, &artifact_dir)?;
    attach_production_host_write_plan_freeze(&mut report, host_write_plan_freeze);
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
    branch_mismatched_repos: Vec<String>,
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
    let mut branch_mismatched_repos = Vec::new();
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
        if repo["exists"].as_bool().unwrap_or(false)
            && repo["git_status_available"].as_bool().unwrap_or(false)
            && !repo["branch_matches_expected"].as_bool().unwrap_or(false)
        {
            let actual = repo["actual_branch"].as_str().unwrap_or("unknown");
            let expected = repo["expected_branch"].as_str().unwrap_or("unknown");
            branch_mismatched_repos.push(format!("{name}:{actual}!={expected}"));
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
        branch_mismatched_repos,
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
    let branch_mismatched_repos = evidence
        .as_ref()
        .map(|evidence| evidence.branch_mismatched_repos.clone())
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
    let product_chain_branch_contract_preserved = branch_mismatched_repos.is_empty();
    let clean_product_chain_baseline = sibling_repos_present
        && sibling_repo_status_available
        && dirty_repos.is_empty()
        && product_chain_branch_contract_preserved;
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
    let resident_default_daemon_switch_gate = resident_default_daemon_switch_gate_json(options);
    let resident_default_daemon_switch_ready = resident_default_daemon_switch_gate["ready"]
        .as_bool()
        .unwrap_or(false);
    let resident_default_daemon_service_contract =
        resident_default_daemon_switch_gate["candidate_service_contract"].clone();
    let recertification_clean = executed
        && admission.bpf_go_fallback_retired
        && admission.true_rust_default_daemon_admitted
        && service_contract_passed
        && dependency_boundary_preserved
        && clean_product_chain_baseline
        && daed_wing_runtime_control_api_regression_recorded;
    let default_path_mutation_allowed = recertification_clean
        && default_path_mutation_requested
        && resident_default_daemon_switch_ready;
    let product_chain_switch_allowed = default_path_mutation_allowed;
    let go_fallback_required = !product_chain_switch_allowed;
    let go_fallback_retired = product_chain_switch_allowed;
    let go_fallback_retirement_scope = if go_fallback_retired {
        "product-chain-default-path-admission"
    } else {
        "blocked-before-product-chain-default-path-admission"
    };
    let production_run_command_replacement_plan = production_run_command_replacement_plan_json(
        options,
        artifact_dir,
        default_path_mutation_allowed,
        resident_default_daemon_switch_ready,
        service_contract_passed,
        go_fallback_required,
        go_fallback_retired,
    );
    let mut remaining_blockers = remaining_blockers(
        admission,
        &dirty_repos,
        &missing_repos,
        &unavailable_repos,
        &branch_mismatched_repos,
        runtime_control_api_source_contract_preserved,
        daed_wing_runtime_control_api_regression_recorded,
        default_path_mutation_requested,
    );
    remaining_blockers.extend(value_string_array(
        &resident_default_daemon_switch_gate["blockers"],
    ));
    remaining_blockers.extend(production_run_command_execution_blockers(
        &production_run_command_replacement_plan,
    ));
    remaining_blockers.extend(production_run_command_apply_plan_blockers(
        &production_run_command_replacement_plan,
    ));
    let typed_report = ProductChainTypedReportSummary {
        executed,
        recertification_clean,
        default_path_mutation_requested,
        default_path_mutation_allowed,
        product_chain_switch_allowed,
        resident_default_daemon_switch_ready,
        admission,
        service_contract_preserved: service_contract_passed,
        dependency_boundary_preserved,
        runtime_control_api_source_contract_preserved,
        clean_product_chain_baseline,
        product_chain_branch_contract_preserved,
        go_fallback_required,
        go_fallback_retired,
        remaining_blocker_count: remaining_blockers.len(),
    }
    .to_json();
    let expected_product_chain_branches = expected_product_chain_branches_json();
    let mut report = json!({
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
            "bpf_go_fallback_retired": admission.bpf_go_fallback_retired,
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
        "resident_default_daemon_switch_ready": resident_default_daemon_switch_ready,
        "resident_default_daemon_switch_gate": resident_default_daemon_switch_gate,
        "resident_default_daemon_service_contract": resident_default_daemon_service_contract,
        "production_run_command_replacement_plan": production_run_command_replacement_plan,
        "production_run_command_replaced": false,
        "go_default_path_preserved": true,
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
    });
    if let Value::Object(report) = &mut report {
        report.insert(
            "branch_mismatched_sibling_repos".to_owned(),
            json!(branch_mismatched_repos),
        );
        report.insert(
            "expected_product_chain_branches".to_owned(),
            expected_product_chain_branches,
        );
        report.insert(
            "product_chain_branch_contract_preserved".to_owned(),
            json!(product_chain_branch_contract_preserved),
        );
        report.insert(
            "go_fallback_required".to_owned(),
            json!(go_fallback_required),
        );
        report.insert("go_fallback_retired".to_owned(), json!(go_fallback_retired));
        report.insert(
            "go_fallback_retirement_scope".to_owned(),
            json!(go_fallback_retirement_scope),
        );
        report.insert("typed_report".to_owned(), typed_report);
    }
    report
}

fn expected_product_chain_branches_json() -> Value {
    json!({
        "dae": expected_product_chain_branch("dae"),
        "daed": expected_product_chain_branch("daed"),
        "dae_wing": expected_product_chain_branch("dae-wing"),
        "outbound": expected_product_chain_branch("outbound"),
        "quic_go": expected_product_chain_branch("quic-go"),
    })
}

fn resident_default_daemon_switch_gate_json(options: &ProductChainRecertificationOptions) -> Value {
    let requested = options.default_path_mutation_requested
        || options.production_run_command_replacement_dry_run_requested
        || options.production_run_command_replacement_execute_requested
        || options.production_run_command_replacement_apply_plan_requested
        || options.host_default_path_mutation_allow_requested
        || options.local_validation_fresh_install_plan_requested;
    let binary_source = options
        .resident_default_daemon_binary_source
        .as_deref()
        .or(options.local_validation_binary_source.as_deref());
    let binary_source_provided = binary_source.is_some();
    let binary_source_exists = binary_source.is_some_and(Path::is_file);
    let candidate_service_contract = candidate_service_contract_report(requested, binary_source);
    let resident_run_service_contract_ready =
        candidate_service_contract["resident_run_service_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let reload_command_service_contract_ready =
        candidate_service_contract["reload_command_service_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_production_dataplane_ready =
        candidate_service_contract["resident_production_dataplane_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_default_daemon_switch_declared =
        candidate_service_contract["resident_default_daemon_switch_ready"]
            .as_bool()
            .unwrap_or(false);
    let resident_dataplane_default_switch_ready =
        candidate_service_contract["resident_dataplane_default_switch_ready"]
            .as_bool()
            .unwrap_or(resident_default_daemon_switch_declared);
    let resident_dataplane_env = candidate_service_contract["resident_dataplane_env"].clone();
    let resident_dataplane_env_enabled =
        candidate_service_contract["resident_dataplane_env_enabled"]
            .as_bool()
            .unwrap_or(resident_dataplane_default_switch_ready);
    let reload_failure_rollback_supported =
        candidate_service_contract["reload_failure_rollback_supported"]
            .as_bool()
            .unwrap_or(false);
    let invalid_runtime_config_rejected_before_current_swap =
        candidate_service_contract["invalid_runtime_config_rejected_before_current_swap"]
            .as_bool()
            .unwrap_or(false);
    let reload_start_failure_attempts_previous_runtime_restore =
        candidate_service_contract["reload_start_failure_attempts_previous_runtime_restore"]
            .as_bool()
            .unwrap_or(false);
    let candidate_service_contract_passed = candidate_service_contract["passed"]
        .as_bool()
        .unwrap_or(false);
    let ready = requested
        && candidate_service_contract_passed
        && resident_run_service_contract_ready
        && reload_command_service_contract_ready
        && resident_production_dataplane_ready
        && resident_default_daemon_switch_declared
        && resident_dataplane_default_switch_ready
        && reload_failure_rollback_supported
        && invalid_runtime_config_rejected_before_current_swap
        && reload_start_failure_attempts_previous_runtime_restore;

    let mut blockers = Vec::new();
    if requested && !binary_source_provided {
        blockers.push("resident default daemon candidate binary source is not provided");
    } else if requested && !binary_source_exists {
        blockers.push("resident default daemon candidate binary source is absent");
    } else if requested {
        if !resident_run_service_contract_ready {
            blockers.push("resident run service contract is not implemented by dae-daemon-optin");
        }
        if !reload_command_service_contract_ready {
            blockers.push("reload command service contract is not implemented by dae-daemon-optin");
        }
        if !resident_production_dataplane_ready {
            blockers.push(
                "resident default service path does not admit production dataplane; dae-daemon-optin run -c ... is service-contract-only",
            );
        }
        if resident_production_dataplane_ready && !resident_default_daemon_switch_declared {
            blockers.push(
                "resident default daemon switch readiness is not explicitly declared by service-contract",
            );
        }
        if !resident_dataplane_default_switch_ready {
            blockers.push(
                "resident userspace dataplane default switch env is not enabled by service-contract",
            );
        }
        if !reload_failure_rollback_supported {
            blockers.push("resident reload failure rollback is not declared by service-contract");
        }
        if !invalid_runtime_config_rejected_before_current_swap {
            blockers.push(
                "resident reload does not declare invalid runtime config rejection before current swap",
            );
        }
        if !reload_start_failure_attempts_previous_runtime_restore {
            blockers.push(
                "resident reload does not declare previous runtime restore after start failure",
            );
        }
    }

    json!({
        "status": if ready { "pass" } else if requested { "blocked" } else { "not-requested" },
        "requested": requested,
        "ready": ready,
        "binary_source": binary_source.map(path_string),
        "binary_source_provided": binary_source_provided,
        "binary_source_exists": binary_source_exists,
        "candidate_service_contract": candidate_service_contract,
        "resident_run_service_contract_ready": resident_run_service_contract_ready,
        "reload_command_service_contract_ready": reload_command_service_contract_ready,
        "resident_production_dataplane_ready": resident_production_dataplane_ready,
        "resident_default_daemon_switch_declared": resident_default_daemon_switch_declared,
        "resident_dataplane_default_switch_ready": resident_dataplane_default_switch_ready,
        "resident_dataplane_env": resident_dataplane_env,
        "resident_dataplane_env_enabled": resident_dataplane_env_enabled,
        "reload_failure_rollback_supported": reload_failure_rollback_supported,
        "invalid_runtime_config_rejected_before_current_swap": invalid_runtime_config_rejected_before_current_swap,
        "reload_start_failure_attempts_previous_runtime_restore": reload_start_failure_attempts_previous_runtime_restore,
        "requires_no_extra_flag_run_path": "dae-daemon-optin run --disable-timestamp -c /etc/dae/config.dae",
        "blockers": blockers,
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:Rust resident default service path",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:default-path-service-runtime-contract"
        ],
    })
}

#[cfg(test)]
mod tests;
