use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use super::{ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone)]
pub(super) struct NativeOwnedEntryGateReport {
    pub(super) report: Value,
    pub(super) blockers: Vec<String>,
}

pub(super) fn native_owned_entry_gates_json(
    executed: bool,
    options: &ProductChainRecertificationOptions,
    topology: &Value,
    service: &Value,
    runtime_control_api: &Value,
) -> NativeOwnedEntryGateReport {
    if !executed {
        return NativeOwnedEntryGateReport {
            report: json!({
                "status": "not-executed",
                "product_chain_topology_locked": false,
                "default_bundle_boundary_clean": false,
                "default_runtime_selector_rust_owned": false,
                "explicit_go_rollback_only": false,
                "runtime_selector_matrix_recorded": false,
                "daed_service_contract_ready": false,
                "c0_product_chain_topology_lock": not_executed_gate("product-chain-topology-lock-v1"),
                "c1_default_bundle_boundary": not_executed_gate("default-bundle-boundary-v1"),
                "c2_default_runtime_selector": not_executed_gate("default-runtime-selector-v1"),
                "c3_daed_service_contract": not_executed_gate("daed-service-contract-v1"),
            }),
            blockers: Vec::new(),
        };
    }

    let c0 = c0_product_chain_topology_lock(options, topology);
    let c1 = c1_default_bundle_boundary(options);
    let c2 = c2_default_runtime_selector(options);
    let c3 = c3_daed_service_contract(options, service, runtime_control_api);
    let product_chain_topology_locked = c0["product_chain_topology_locked"]
        .as_bool()
        .unwrap_or(false);
    let default_bundle_boundary_clean = c1["default_bundle_boundary_clean"]
        .as_bool()
        .unwrap_or(false);
    let default_runtime_selector_rust_owned = c2["default_runtime_selector_rust_owned"]
        .as_bool()
        .unwrap_or(false);
    let explicit_go_rollback_only = c2["explicit_go_rollback_only"].as_bool().unwrap_or(false);
    let runtime_selector_matrix_recorded = c2["runtime_selector_matrix_recorded"]
        .as_bool()
        .unwrap_or(false);
    let daed_service_contract_ready = c3["daed_service_contract_ready"].as_bool().unwrap_or(false);
    let status = if product_chain_topology_locked
        && default_bundle_boundary_clean
        && default_runtime_selector_rust_owned
        && explicit_go_rollback_only
        && runtime_selector_matrix_recorded
        && daed_service_contract_ready
    {
        "pass"
    } else {
        "blocked"
    };
    let mut blockers = Vec::new();
    blockers.extend(value_string_array(&c0["blockers"]));
    blockers.extend(value_string_array(&c1["blockers"]));
    blockers.extend(value_string_array(&c2["blockers"]));
    blockers.extend(value_string_array(&c3["blockers"]));
    NativeOwnedEntryGateReport {
        report: json!({
            "status": status,
            "product_chain_topology_locked": product_chain_topology_locked,
            "default_bundle_boundary_clean": default_bundle_boundary_clean,
            "default_runtime_selector_rust_owned": default_runtime_selector_rust_owned,
            "explicit_go_rollback_only": explicit_go_rollback_only,
            "runtime_selector_matrix_recorded": runtime_selector_matrix_recorded,
            "daed_service_contract_ready": daed_service_contract_ready,
            "c0_product_chain_topology_lock": c0,
            "c1_default_bundle_boundary": c1,
            "c2_default_runtime_selector": c2,
            "c3_daed_service_contract": c3,
        }),
        blockers,
    }
}

fn not_executed_gate(name: &str) -> Value {
    json!({
        "name": name,
        "status": "not-executed",
        "blockers": [],
    })
}

fn c0_product_chain_topology_lock(
    options: &ProductChainRecertificationOptions,
    topology: &Value,
) -> Value {
    let expected_wing_repo = options.daed_repo.join("wing");
    let submodule_build_truth_recorded = options.dae_wing_repo == expected_wing_repo;
    let submodule_status = git_repo_brief_json(&options.dae_wing_repo);
    let sibling_repo = sibling_wing_repo(&options.daed_repo);
    let sibling_present = sibling_repo.is_dir();
    let sibling_status = if sibling_present {
        git_repo_brief_json(&sibling_repo)
    } else {
        json!({
            "path": path_string(&sibling_repo),
            "exists": false,
            "git_status_available": false,
            "head": Value::Null,
            "dirty": false,
        })
    };
    let submodule_head = submodule_status["head"].as_str();
    let sibling_head = sibling_status["head"].as_str();
    let heads_match = sibling_present
        && submodule_head.is_some()
        && sibling_head.is_some()
        && submodule_head == sibling_head;
    let submodule_dirty = submodule_status["dirty"].as_bool().unwrap_or(false);
    let sibling_dirty = sibling_status["dirty"].as_bool().unwrap_or(false);
    let submodule_matches_sibling_repo =
        !sibling_present || (heads_match && !submodule_dirty && !sibling_dirty);
    let product_chain_topology_locked =
        submodule_build_truth_recorded && submodule_matches_sibling_repo;

    let mut blockers = Vec::new();
    if !submodule_build_truth_recorded {
        blockers.push(format!(
            "C0 product-chain topology is not locked to daed/wing submodule: expected {}, got {}",
            path_string(&expected_wing_repo),
            path_string(&options.dae_wing_repo)
        ));
    }
    if sibling_present && !heads_match {
        blockers.push(format!(
            "C0 daed/wing submodule HEAD does not match sibling wing repo: submodule={}, sibling={}",
            submodule_head.unwrap_or("unknown"),
            sibling_head.unwrap_or("unknown")
        ));
    }
    if sibling_present && (submodule_dirty || sibling_dirty) {
        blockers.push(format!(
            "C0 daed/wing submodule or sibling wing repo is dirty: submodule_dirty={submodule_dirty}, sibling_dirty={sibling_dirty}"
        ));
    }

    json!({
        "name": "product-chain-topology-lock-v1",
        "status": if product_chain_topology_locked { "pass" } else { "blocked" },
        "chain": "daed-daex-align -> daed/wing submodule -> dae-daex-align -> outbound-daex-align -> quic-go-daex-align",
        "build_truth": "daed/wing-submodule",
        "product_chain_topology_locked": product_chain_topology_locked,
        "submodule_build_truth_recorded": submodule_build_truth_recorded,
        "expected_wing_repo": path_string(&expected_wing_repo),
        "actual_wing_repo": path_string(&options.dae_wing_repo),
        "daed2_wing_repo_used": topology["daed2_wing_repo_used"].clone(),
        "standalone_dae_wing_repo_used": topology["standalone_dae_wing_repo_used"].clone(),
        "submodule_status": submodule_status,
        "sibling_repo": path_string(&sibling_repo),
        "sibling_present": sibling_present,
        "sibling_status": sibling_status,
        "submodule_matches_sibling_repo": submodule_matches_sibling_repo,
        "quic_go_path": path_string(&options.quic_go_repo),
        "blockers": blockers,
    })
}

fn sibling_wing_repo(daed_repo: &Path) -> PathBuf {
    daed_repo
        .parent()
        .and_then(Path::parent)
        .map(|project_root| project_root.join("dae-wing-daex-align"))
        .unwrap_or_else(|| PathBuf::from("/root/project/dae-wing-daex-align"))
}

fn c1_default_bundle_boundary(options: &ProductChainRecertificationOptions) -> Value {
    let makefile = options.dae_wing_repo.join("Makefile");
    let text = fs::read_to_string(&makefile).unwrap_or_default();
    let makefile_readable = !text.is_empty();
    let default_bundle_rule = makefile_rule(&text, "bundle");
    let rust_owned_bundle_rule = makefile_rule(&text, "bundle-rust-owned");
    let hybrid_bundle_shape_recorded = text.contains("BUNDLE_TAGS ?= embedallowed")
        && default_bundle_rule.contains("rust-aya-bpf-loader-asset")
        && default_bundle_rule.contains("bundle-build")
        && !default_bundle_rule.contains("rust-daemon-embed");
    let rust_owned_candidate_bundle_shape_recorded = text
        .contains("bundle-rust-owned: BUNDLE_TAGS := embedallowed,rust_owned_daemon_embed")
        && rust_owned_bundle_rule.contains("rust-daemon-embed")
        && rust_owned_bundle_rule.contains("bundle-build")
        && text.contains("rust-daemon-embed:");
    let default_bundle_embeds_rust_owned_daemon = default_bundle_rule.contains("rust-daemon-embed")
        || text.contains("BUNDLE_TAGS ?= embedallowed,rust_owned_daemon_embed");
    let bundle_dry_run = make_dry_run_json(&options.dae_wing_repo, "bundle");
    let rust_owned_bundle_dry_run = make_dry_run_json(&options.dae_wing_repo, "bundle-rust-owned");
    let dry_runs_recorded = bundle_dry_run["passed"].as_bool().unwrap_or(false)
        && rust_owned_bundle_dry_run["passed"]
            .as_bool()
            .unwrap_or(false);
    let release_target_scan = release_target_scan_json(options);
    let release_targets_recorded = release_target_scan["recorded"].as_bool().unwrap_or(false);
    let default_bundle_boundary_clean = makefile_readable
        && hybrid_bundle_shape_recorded
        && rust_owned_candidate_bundle_shape_recorded
        && !default_bundle_embeds_rust_owned_daemon
        && dry_runs_recorded
        && release_targets_recorded;

    let mut blockers = Vec::new();
    if !makefile_readable {
        blockers.push(format!(
            "C1 wing Makefile could not be read: {}",
            path_string(&makefile)
        ));
    }
    if !hybrid_bundle_shape_recorded {
        blockers.push("C1 hybrid default bundle shape is not recorded".to_owned());
    }
    if !rust_owned_candidate_bundle_shape_recorded {
        blockers.push("C1 Rust-owned candidate bundle shape is not recorded".to_owned());
    }
    if default_bundle_embeds_rust_owned_daemon {
        blockers.push(
            "C1 default bundle embeds Rust-owned daemon asset; C9 release default switch has not admitted this yet"
                .to_owned(),
        );
    }
    if !dry_runs_recorded {
        blockers.push("C1 make -n bundle and bundle-rust-owned evidence is incomplete".to_owned());
    }
    if !release_targets_recorded {
        blockers.push("C1 release/action/Docker bundle targets are not recorded".to_owned());
    }

    json!({
        "name": "default-bundle-boundary-v1",
        "status": if default_bundle_boundary_clean { "pass" } else { "blocked" },
        "makefile": path_string(&makefile),
        "makefile_readable": makefile_readable,
        "hybrid_bundle_shape_recorded": hybrid_bundle_shape_recorded,
        "rust_owned_candidate_bundle_shape_recorded": rust_owned_candidate_bundle_shape_recorded,
        "default_bundle_embeds_rust_owned_daemon": default_bundle_embeds_rust_owned_daemon,
        "default_bundle_target": "bundle",
        "rust_owned_candidate_bundle_target": "bundle-rust-owned",
        "default_bundle_rule": default_bundle_rule,
        "rust_owned_candidate_bundle_rule": rust_owned_bundle_rule,
        "bundle_dry_run": bundle_dry_run,
        "rust_owned_bundle_dry_run": rust_owned_bundle_dry_run,
        "dry_runs_recorded": dry_runs_recorded,
        "release_target_scan": release_target_scan,
        "release_targets_recorded": release_targets_recorded,
        "default_bundle_boundary_clean": default_bundle_boundary_clean,
        "blockers": blockers,
    })
}

fn c2_default_runtime_selector(options: &ProductChainRecertificationOptions) -> Value {
    let runtime_mode = options.dae_wing_repo.join("engine/runtime_mode.go");
    let runtime_mode_text = fs::read_to_string(&runtime_mode).unwrap_or_default();
    let tests = options
        .dae_wing_repo
        .join("engine/rust_owned_service_test.go");
    let tests_text = fs::read_to_string(&tests).unwrap_or_default();
    let runtime_mode_readable = !runtime_mode_text.is_empty();
    let runtime_mode_default_rust_owned = runtime_mode_text.contains("runtimeModeDefault")
        && runtime_mode_text.contains("= runtimeModeRustOwned")
        && runtime_mode_text.contains("return runtimeModeDefault");
    let auto_selects_rust_owned = runtime_mode_text.contains("case \"auto\":")
        && runtime_mode_text.contains("return runtimeModeDefault");
    let explicit_go_rollback_only = runtime_mode_text.contains("runtimeModeGo")
        && runtime_mode_text.contains("case \"go\", \"native\", \"dae-go\", \"go-native\":")
        && runtime_mode_text.contains("return runtimeModeGo");
    let runtime_selector_matrix_recorded = tests_text
        .contains("TestNewDefaultServiceUsesRustOwnedRuntimeByDefault")
        && tests_text.contains("TestNewDefaultServiceUsesRustOwnedRuntimeForAuto")
        && tests_text.contains("TestNewDefaultServiceAllowsExplicitRustOwnedRuntime")
        && tests_text.contains("TestNewDefaultServiceAllowsExplicitGoRollback")
        && tests_text.contains("DAED_RUNTIME_MODE");
    let default_runtime_selector_rust_owned =
        runtime_mode_readable && runtime_mode_default_rust_owned && auto_selects_rust_owned;
    let ready = default_runtime_selector_rust_owned
        && explicit_go_rollback_only
        && runtime_selector_matrix_recorded;

    let mut blockers = Vec::new();
    if !runtime_mode_readable {
        blockers.push(format!(
            "C2 runtime selector source could not be read: {}",
            path_string(&runtime_mode)
        ));
    }
    if !default_runtime_selector_rust_owned {
        blockers.push("C2 no-env/auto runtime selector does not default to Rust-owned".to_owned());
    }
    if !explicit_go_rollback_only {
        blockers.push("C2 Go runtime rollback is not explicit-only".to_owned());
    }
    if !runtime_selector_matrix_recorded {
        blockers.push("C2 runtime selector matrix tests are not recorded".to_owned());
    }

    json!({
        "name": "default-runtime-selector-v1",
        "status": if ready { "pass" } else { "blocked" },
        "runtime_mode_file": path_string(&runtime_mode),
        "runtime_mode_readable": runtime_mode_readable,
        "default_runtime_selector_rust_owned": default_runtime_selector_rust_owned,
        "no_env_default_rust_owned": runtime_mode_default_rust_owned,
        "auto_selects_rust_owned": auto_selects_rust_owned,
        "explicit_go_rollback_only": explicit_go_rollback_only,
        "runtime_selector_matrix_file": path_string(&tests),
        "runtime_selector_matrix_recorded": runtime_selector_matrix_recorded,
        "matrix": [
            "no DAED_RUNTIME -> rust-owned",
            "DAED_RUNTIME=auto -> rust-owned",
            "DAED_RUNTIME=rust-owned -> rust-owned",
            "DAED_RUNTIME=go -> explicit Go rollback",
            "DAED_RUNTIME_MODE follows the same aliases"
        ],
        "blockers": blockers,
    })
}

fn c3_daed_service_contract(
    options: &ProductChainRecertificationOptions,
    service: &Value,
    runtime_control_api: &Value,
) -> Value {
    let daed_service_contract_preserved = service["daed_service_contract_preserved"]
        .as_bool()
        .unwrap_or(false);
    let package_hooks = package_hooks_json(&options.daed_repo);
    let package_hooks_ready = package_hooks["package_hooks_ready"]
        .as_bool()
        .unwrap_or(false);
    let runtime_control_api_ready =
        runtime_control_api["runtime_control_api_source_contract_preserved"]
            .as_bool()
            .unwrap_or(false);
    let daed_service_contract_ready =
        daed_service_contract_preserved && package_hooks_ready && runtime_control_api_ready;

    let mut blockers = Vec::new();
    if !daed_service_contract_preserved {
        blockers.push(
            "C3 install/daed.service does not preserve /usr/bin/daed run -c /etc/daed/ contract"
                .to_owned(),
        );
    }
    if !package_hooks_ready {
        blockers.push("C3 daed package after-install/remove hooks are incomplete".to_owned());
    }
    if !runtime_control_api_ready {
        blockers
            .push("C3 daed Web/API runtime overview/reload/stop contract is incomplete".to_owned());
    }

    json!({
        "name": "daed-service-contract-v1",
        "status": if daed_service_contract_ready { "pass" } else { "blocked" },
        "daed_service_contract_ready": daed_service_contract_ready,
        "service": service,
        "package_hooks": package_hooks,
        "runtime_control_api_source_contract_preserved": runtime_control_api_ready,
        "runtime_api_paths": [
            "/api/runtime/overview",
            "/api/runtime/reload",
            "/api/runtime/stop"
        ],
        "blockers": blockers,
    })
}

fn makefile_rule(text: &str, target: &str) -> String {
    let prefix = format!("{target}:");
    text.lines()
        .filter(|line| !line.contains(":="))
        .find(|line| line.trim_start().starts_with(&prefix))
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn make_dry_run_json(repo: &Path, target: &str) -> Value {
    if !repo.is_dir() {
        return json!({
            "target": target,
            "executed": false,
            "passed": false,
            "stdout": "",
            "stderr": "wing repo does not exist",
        });
    }
    match Command::new("make")
        .args(["-n", target, "WEB_DIST=webrender/web"])
        .current_dir(repo)
        .output()
    {
        Ok(output) => json!({
            "target": target,
            "executed": true,
            "passed": output.status.success(),
            "exit_code": output.status.code(),
            "stdout": bounded_output(&output.stdout),
            "stderr": bounded_output(&output.stderr),
        }),
        Err(err) => json!({
            "target": target,
            "executed": true,
            "passed": false,
            "exit_code": Value::Null,
            "stdout": "",
            "stderr": err.to_string(),
        }),
    }
}

fn release_target_scan_json(options: &ProductChainRecertificationOptions) -> Value {
    let files = [
        options
            .daed_repo
            .join(".github/workflows/publish-packages.yml"),
        options.daed_repo.join("Dockerfile"),
        options.daed_repo.join("publish.Dockerfile"),
        options.daed_repo.join("package.json"),
        options.dae_wing_repo.join("Makefile"),
    ];
    let entries: Vec<Value> = files
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path).unwrap_or_default();
            json!({
                "path": path_string(path),
                "exists": path.is_file(),
                "make_bundle": text.contains("make bundle") || text.contains(" bundle"),
                "make_bundle_rust_owned": text.contains("bundle-rust-owned"),
                "docker_daed_run_contract": text.contains("daed\", \"run\", \"-c\", \"/etc/daed") || text.contains("daed run -c /etc/daed"),
            })
        })
        .collect();
    json!({
        "recorded": entries.iter().any(|entry| entry["exists"].as_bool().unwrap_or(false)),
        "files": entries,
    })
}

fn package_hooks_json(daed_repo: &Path) -> Value {
    let after_install = daed_repo.join("install/package_after_install.sh");
    let after_remove = daed_repo.join("install/package_after_remove.sh");
    let after_install_text = fs::read_to_string(&after_install).unwrap_or_default();
    let after_remove_text = fs::read_to_string(&after_remove).unwrap_or_default();
    let after_install_daemon_reload = after_install_text.contains("systemctl daemon-reload");
    let after_install_restarts_daed = after_install_text.contains("systemctl restart daed.service")
        || after_install_text.contains("systemctl restart daed");
    let after_install_checks_active_daed = after_install_text.contains("systemctl is-active daed");
    let after_remove_daemon_reload = after_remove_text.contains("systemctl daemon-reload");
    let package_hooks_ready = after_install_daemon_reload
        && after_install_restarts_daed
        && after_install_checks_active_daed
        && after_remove_daemon_reload;
    json!({
        "package_hooks_ready": package_hooks_ready,
        "after_install": {
            "path": path_string(&after_install),
            "exists": after_install.is_file(),
            "daemon_reload": after_install_daemon_reload,
            "checks_active_daed": after_install_checks_active_daed,
            "restarts_daed_service": after_install_restarts_daed,
        },
        "after_remove": {
            "path": path_string(&after_remove),
            "exists": after_remove.is_file(),
            "daemon_reload": after_remove_daemon_reload,
        },
    })
}

fn git_repo_brief_json(path: &Path) -> Value {
    if !path.is_dir() {
        return json!({
            "path": path_string(path),
            "exists": false,
            "git_status_available": false,
            "head": Value::Null,
            "dirty": false,
        });
    }
    let status = Command::new("git")
        .args(["status", "--short", "--branch"])
        .current_dir(path)
        .output();
    let head = git_stdout(path, &["rev-parse", "HEAD"]);
    match status {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let dirty = stdout
                .lines()
                .any(|line| !line.trim().is_empty() && !line.starts_with("##"));
            json!({
                "path": path_string(path),
                "exists": true,
                "git_status_available": output.status.success(),
                "head": head,
                "dirty": dirty,
                "branch": stdout.lines().next().unwrap_or_default(),
                "stdout": stdout,
                "stderr": String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
        Err(err) => json!({
            "path": path_string(path),
            "exists": true,
            "git_status_available": false,
            "head": head,
            "dirty": false,
            "error": err.to_string(),
        }),
    }
}

fn git_stdout(path: &Path, args: &[&str]) -> Value {
    let Ok(output) = Command::new("git").args(args).current_dir(path).output() else {
        return Value::Null;
    };
    if !output.status.success() {
        return Value::Null;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        Value::Null
    } else {
        json!(text)
    }
}

fn bounded_output(bytes: &[u8]) -> String {
    const MAX_BYTES: usize = 4000;
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BYTES)]).into_owned()
}

fn value_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
