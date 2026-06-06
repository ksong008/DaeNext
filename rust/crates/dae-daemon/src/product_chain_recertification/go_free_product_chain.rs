use std::fs;

use serde_json::{Map, Value, json};

use super::{ProductChainRecertificationOptions, path_string};

#[derive(Debug, Clone)]
pub(super) struct GoFreeProductChainGateReport {
    pub(super) report: Value,
}

pub(super) fn default_product_package_scan_json(
    options: &ProductChainRecertificationOptions,
) -> Value {
    let makefile = options.daed_repo.join("Makefile");
    let dockerfile = options.daed_repo.join("Dockerfile");
    let publish_dockerfile = options.daed_repo.join("publish.Dockerfile");
    let integration_workflow = options.daed_repo.join(".github/workflows/daed2.0.yml");
    let release_workflow = options
        .daed_repo
        .join(".github/workflows/release-please.yml");
    let linux_test_workflow = options
        .daed_repo
        .join(".github/workflows/test-linux-amd64v3.yml");

    let makefile_text = read_text(&makefile);
    let dockerfile_text = read_text(&dockerfile);
    let publish_dockerfile_text = read_text(&publish_dockerfile);
    let integration_text = read_text(&integration_workflow);
    let release_text = read_text(&release_workflow);
    let linux_test_text = read_text(&linux_test_workflow);

    let make_default_rust_native = makefile_text.contains("daed: daed-rust-native")
        && makefile_text.contains("cargo build $(RUST_DAED_BUILD_ARGS)")
        && makefile_text.contains("daed-go-rollback:");
    let make_go_rollback_explicit = makefile_text.contains("daed-go-rollback:")
        && makefile_text.contains("$(MAKE) OUTPUT=../$(OUTPUT)")
        && makefile_text.contains(" bundle");
    let make_default_uses_wing_bundle =
        makefile_rule(&makefile_text, "daed").contains("bundle") && !make_default_rust_native;
    let rust_native_rule = makefile_rule(&makefile_text, "daed-rust-native");
    let default_build_uses_go_bpf_generator = rust_native_rule.contains("$(DAE_CORE_BPF_OBJECT)")
        || rust_native_rule.contains("make ebpf")
        || rust_native_rule.contains("$(MAKE) ebpf");
    let explicit_legacy_bpf_generator_present = makefile_text.contains("$(DAE_CORE_BPF_OBJECT):")
        && makefile_text.contains("cd wing/dae-core")
        && makefile_text.contains("$(MAKE) ebpf");

    let docker_default_rust_native = dockerfile_text.contains("FROM rust:")
        && dockerfile_text.contains("daed-rust-native")
        && dockerfile_text.contains("/usr/share/daed/web")
        && dockerfile_text.contains("daed-docker-entrypoint");
    let docker_default_uses_wing_bundle = dockerfile_text.contains("WORKDIR /build/wing")
        || dockerfile_text.contains("make APPNAME=daed") && dockerfile_text.contains(" bundle");

    let publish_docker_default_rust_native = publish_dockerfile_text.contains("FROM rust:")
        && publish_dockerfile_text.contains("daed-rust-native")
        && publish_dockerfile_text.contains("/usr/share/daed/web")
        && publish_dockerfile_text.contains("daed-docker-entrypoint");
    let publish_docker_default_uses_wing_bundle = publish_dockerfile_text
        .contains("WORKDIR /build/wing")
        || publish_dockerfile_text.contains("make APPNAME=daed")
            && publish_dockerfile_text.contains(" bundle");

    let integration_default_rust_native = integration_text.contains("Build Rust native daed")
        && integration_text.contains("DAED_SKIP_WEB_BUILD")
        && integration_text.contains("make")
        && !integration_text.contains("working-directory: wing")
        && !integration_text.contains("make bundle");
    let release_default_rust_native = release_text.contains("DAED_SKIP_WEB_BUILD")
        && release_text.contains("RUSTFLAGS")
        && release_text.contains("./web=/usr/share/daed/web")
        && !release_text.contains("make bundle");
    let release_source_archive_uses_wing_vendor = release_text.contains("Download wing vendor")
        && release_text.contains("working-directory: wing");
    let linux_test_default_rust_native = linux_test_text.contains("Build Rust native daed")
        && linux_test_text.contains("DAED_SKIP_WEB_BUILD")
        && linux_test_text.contains("make")
        && !linux_test_text.contains("working-directory: wing")
        && !linux_test_text.contains("make bundle");

    let go_product_shell_retired_from_default_package = make_default_rust_native
        && make_go_rollback_explicit
        && !make_default_uses_wing_bundle
        && docker_default_rust_native
        && !docker_default_uses_wing_bundle
        && publish_docker_default_rust_native
        && !publish_docker_default_uses_wing_bundle
        && integration_default_rust_native
        && release_default_rust_native
        && linux_test_default_rust_native
        && !default_build_uses_go_bpf_generator;
    let default_product_package_go_free =
        go_product_shell_retired_from_default_package && !default_build_uses_go_bpf_generator;
    let mut blockers = Vec::new();
    if !make_default_rust_native {
        blockers.push("C10 daed Makefile default target is not Rust native".to_owned());
    }
    if !make_go_rollback_explicit {
        blockers.push("C10 Go rollback bundle target is not explicit".to_owned());
    }
    if make_default_uses_wing_bundle {
        blockers.push("C10 daed Makefile default target still uses wing bundle".to_owned());
    }
    if !docker_default_rust_native || docker_default_uses_wing_bundle {
        blockers.push("C10 Dockerfile default image path is not Rust native".to_owned());
    }
    if !publish_docker_default_rust_native || publish_docker_default_uses_wing_bundle {
        blockers.push("C10 publish Dockerfile default image path is not Rust native".to_owned());
    }
    if !integration_default_rust_native {
        blockers.push("C10 integration workflow default build path is not Rust native".to_owned());
    }
    if !release_default_rust_native {
        blockers
            .push("C10 release workflow default build/package path is not Rust native".to_owned());
    }
    if !linux_test_default_rust_native {
        blockers.push("C10 linux test workflow default build path is not Rust native".to_owned());
    }
    if default_build_uses_go_bpf_generator {
        blockers.push(
            "C10 default package build still depends on Go-generated kernel BPF object".to_owned(),
        );
    }

    json!({
        "name": "default-product-package-scan",
        "status": if default_product_package_go_free { "pass" } else { "blocked" },
        "default_product_package_go_free": default_product_package_go_free,
        "go_product_shell_retired_from_default_package": go_product_shell_retired_from_default_package,
        "default_build_uses_go_bpf_generator": default_build_uses_go_bpf_generator,
        "explicit_legacy_bpf_generator_present": explicit_legacy_bpf_generator_present,
        "makefile": {
            "path": path_string(&makefile),
            "exists": makefile.is_file(),
            "default_rust_native": make_default_rust_native,
            "go_rollback_explicit": make_go_rollback_explicit,
            "default_uses_wing_bundle": make_default_uses_wing_bundle,
        },
        "dockerfile": {
            "path": path_string(&dockerfile),
            "exists": dockerfile.is_file(),
            "default_rust_native": docker_default_rust_native,
            "default_uses_wing_bundle": docker_default_uses_wing_bundle,
        },
        "publish_dockerfile": {
            "path": path_string(&publish_dockerfile),
            "exists": publish_dockerfile.is_file(),
            "default_rust_native": publish_docker_default_rust_native,
            "default_uses_wing_bundle": publish_docker_default_uses_wing_bundle,
        },
        "workflows": {
            "integration": {
                "path": path_string(&integration_workflow),
                "exists": integration_workflow.is_file(),
                "default_rust_native": integration_default_rust_native,
            },
            "release": {
                "path": path_string(&release_workflow),
                "exists": release_workflow.is_file(),
                "default_rust_native": release_default_rust_native,
                "source_archive_uses_wing_vendor": release_source_archive_uses_wing_vendor,
            },
            "linux_test": {
                "path": path_string(&linux_test_workflow),
                "exists": linux_test_workflow.is_file(),
                "default_rust_native": linux_test_default_rust_native,
            },
        },
        "blockers": blockers,
    })
}

pub(super) fn go_free_product_chain_gate_json(
    executed: bool,
    release_default_switch_gate: &Value,
    resident_default_daemon_switch_gate: &Value,
    dependency_boundary_preserved: bool,
    product_chain_branch_contract_preserved: bool,
    default_product_package_scan: &Value,
) -> GoFreeProductChainGateReport {
    if !executed {
        return GoFreeProductChainGateReport {
            report: json!({
                "name": "go-free-product-chain",
                "status": "not-executed",
                "requested": false,
                "go_free_product_chain_ready": false,
                "go_free_product_chain_admission_ready": false,
                "blockers": [],
            }),
        };
    }

    let requested = true;
    let release_default_switch_ready = release_default_switch_gate["release_default_switch_ready"]
        .as_bool()
        .unwrap_or(false);
    let resident_live_adapter_matrix_ready =
        release_default_switch_gate["resident_live_adapter_matrix_ready"]
            .as_bool()
            .unwrap_or(false);
    let candidate_service_contract =
        resident_default_daemon_switch_gate["candidate_service_contract"].clone();
    let candidate_executed = candidate_service_contract["executed"]
        .as_bool()
        .unwrap_or(false);
    let candidate_passed = candidate_service_contract["passed"]
        .as_bool()
        .unwrap_or(false);
    let contract_ready = candidate_service_contract["go_free_product_chain_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let default_package_go_free = candidate_service_contract["default_product_package_go_free"]
        .as_bool()
        .unwrap_or(false);
    let product_shell_retired =
        candidate_service_contract["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);
    let orchestration_retired =
        candidate_service_contract["go_orchestration_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);
    let control_runtime_api_service_release_retired = candidate_service_contract
        ["go_control_runtime_api_service_release_retired_from_default_package"]
        .as_bool()
        .unwrap_or(false);
    let outbound_dependency_retired =
        candidate_service_contract["go_outbound_dependency_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);
    let compat_oracle_boundary_ready =
        candidate_service_contract["go_compat_oracle_boundary_ready"]
            .as_bool()
            .unwrap_or(false);
    let rust_product_binary_ready =
        candidate_service_contract["rust_product_binary_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let rust_product_lifecycle_ready =
        candidate_service_contract["rust_product_lifecycle_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let rust_product_web_api_package_release_ready =
        candidate_service_contract["rust_product_web_api_package_release_contract_ready"]
            .as_bool()
            .unwrap_or(false);
    let live_host_contract_ready = candidate_service_contract["go_free_live_host_contract_ready"]
        .as_bool()
        .unwrap_or(false);
    let rollback_model_ready = candidate_service_contract["go_free_rollback_model_ready"]
        .as_bool()
        .unwrap_or(false);
    let typed_report_ready = candidate_service_contract["go_free_product_chain_typed_report_ready"]
        .as_bool()
        .unwrap_or(false);
    let candidate_go_free_ready = candidate_service_contract["go_free_product_chain_ready"]
        .as_bool()
        .unwrap_or(false);
    let expanded_source_matrix_c10_ready =
        candidate_service_contract["expanded_source_matrix_c10_ready"]
            .as_bool()
            .unwrap_or(false);
    let default_product_package_scan_ready =
        default_product_package_scan["default_product_package_go_free"]
            .as_bool()
            .unwrap_or(false);
    let scanned_product_shell_retired =
        default_product_package_scan["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap_or(false);

    let go_free_product_chain_admission_ready = requested
        && release_default_switch_ready
        && resident_live_adapter_matrix_ready
        && candidate_executed
        && candidate_passed
        && contract_ready
        && dependency_boundary_preserved
        && product_chain_branch_contract_preserved
        && default_package_go_free
        && product_shell_retired
        && orchestration_retired
        && control_runtime_api_service_release_retired
        && outbound_dependency_retired
        && compat_oracle_boundary_ready
        && rust_product_binary_ready
        && rust_product_lifecycle_ready
        && rust_product_web_api_package_release_ready
        && live_host_contract_ready
        && rollback_model_ready
        && typed_report_ready
        && expanded_source_matrix_c10_ready
        && default_product_package_scan_ready;
    let go_free_product_chain_ready =
        go_free_product_chain_admission_ready && candidate_go_free_ready;

    let mut blockers = Vec::new();
    if !release_default_switch_ready {
        blockers.push("C10 requires C9 release default switch readiness".to_owned());
    }
    if !resident_live_adapter_matrix_ready {
        blockers.push("C10 requires resident live adapter matrix readiness".to_owned());
    }
    if !candidate_executed {
        blockers.push("C10 candidate service-contract was not executed".to_owned());
    }
    if candidate_executed && !candidate_passed {
        blockers.push("C10 candidate service-contract command did not pass".to_owned());
    }
    if !contract_ready {
        blockers.push("C10 go-free product-chain contract is not declared".to_owned());
    }
    if !dependency_boundary_preserved {
        blockers.push("C10 dependency boundary is not preserved".to_owned());
    }
    if !product_chain_branch_contract_preserved {
        blockers.push("C10 product-chain branch contract is not preserved".to_owned());
    }
    if !default_package_go_free {
        blockers.push("C10 default product package is not declared go-free".to_owned());
    }
    if !default_product_package_scan_ready {
        blockers.push("C10 default product package source scan is not go-free".to_owned());
    }
    if !product_shell_retired {
        blockers.push("C10 Go product shell is not retired from default package".to_owned());
    }
    if !scanned_product_shell_retired {
        blockers.push("C10 source scan still finds Go product shell on a default path".to_owned());
    }
    if !orchestration_retired {
        blockers.push("C10 Go orchestration is not retired from default package".to_owned());
    }
    if !control_runtime_api_service_release_retired {
        blockers.push(
            "C10 Go control/runtime/API/service/release default path is not retired".to_owned(),
        );
    }
    if !outbound_dependency_retired {
        blockers.push("C10 Go outbound dependency is not retired from default package".to_owned());
    }
    if !compat_oracle_boundary_ready {
        blockers.push("C10 Go compat/oracle boundary is not ready".to_owned());
    }
    if !rust_product_binary_ready {
        blockers.push("C10 Rust product binary contract is not ready".to_owned());
    }
    if !rust_product_lifecycle_ready {
        blockers.push("C10 Rust product run/reload/stop contract is not ready".to_owned());
    }
    if !rust_product_web_api_package_release_ready {
        blockers.push("C10 Rust product Web/API/package/release contract is not ready".to_owned());
    }
    if !live_host_contract_ready {
        blockers.push("C10 final go-free live host contract is not ready".to_owned());
    }
    if !rollback_model_ready {
        blockers.push("C10 final go-free rollback model is not ready".to_owned());
    }
    if !typed_report_ready {
        blockers.push("C10 typed report is not ready".to_owned());
    }
    if !candidate_go_free_ready {
        blockers.push("C10 candidate does not declare go-free product-chain readiness".to_owned());
    }
    if !expanded_source_matrix_c10_ready {
        blockers
            .push("C10 expanded source matrix is not ready for final go-free release".to_owned());
    }
    blockers.extend(
        default_product_package_scan["blockers"]
            .as_array()
            .into_iter()
            .flat_map(|items| items.iter())
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );

    let mut report = Map::new();
    report.insert("name".to_owned(), json!("go-free-product-chain"));
    report.insert(
        "status".to_owned(),
        json!(if go_free_product_chain_ready {
            "pass"
        } else {
            "blocked"
        }),
    );
    report.insert("requested".to_owned(), json!(requested));
    report.insert(
        "go_free_product_chain_admission_ready".to_owned(),
        json!(go_free_product_chain_admission_ready),
    );
    report.insert(
        "go_free_product_chain_ready".to_owned(),
        json!(go_free_product_chain_ready),
    );
    report.insert(
        "release_default_switch_ready".to_owned(),
        json!(release_default_switch_ready),
    );
    report.insert(
        "resident_live_adapter_matrix_ready".to_owned(),
        json!(resident_live_adapter_matrix_ready),
    );
    report.insert(
        "candidate_service_contract".to_owned(),
        candidate_service_contract.clone(),
    );
    report.insert(
        "go_free_product_chain_contract_ready".to_owned(),
        json!(contract_ready),
    );
    report.insert(
        "default_product_package_go_free".to_owned(),
        json!(default_package_go_free),
    );
    report.insert(
        "default_product_package_scan_ready".to_owned(),
        json!(default_product_package_scan_ready),
    );
    report.insert(
        "default_product_package_scan".to_owned(),
        default_product_package_scan.clone(),
    );
    report.insert(
        "go_product_shell_retired_from_default_package".to_owned(),
        json!(product_shell_retired),
    );
    report.insert(
        "go_orchestration_retired_from_default_package".to_owned(),
        json!(orchestration_retired),
    );
    report.insert(
        "go_control_runtime_api_service_release_retired_from_default_package".to_owned(),
        json!(control_runtime_api_service_release_retired),
    );
    report.insert(
        "go_outbound_dependency_retired_from_default_package".to_owned(),
        json!(outbound_dependency_retired),
    );
    report.insert(
        "go_compat_oracle_boundary_ready".to_owned(),
        json!(compat_oracle_boundary_ready),
    );
    report.insert(
        "rust_product_binary_contract_ready".to_owned(),
        json!(rust_product_binary_ready),
    );
    report.insert(
        "rust_product_lifecycle_contract_ready".to_owned(),
        json!(rust_product_lifecycle_ready),
    );
    report.insert(
        "rust_product_web_api_package_release_contract_ready".to_owned(),
        json!(rust_product_web_api_package_release_ready),
    );
    report.insert(
        "go_free_live_host_contract_ready".to_owned(),
        json!(live_host_contract_ready),
    );
    report.insert(
        "go_free_rollback_model_ready".to_owned(),
        json!(rollback_model_ready),
    );
    report.insert(
        "go_free_product_chain_typed_report_ready".to_owned(),
        json!(typed_report_ready),
    );
    report.insert(
        "candidate_go_free_product_chain_ready".to_owned(),
        json!(candidate_go_free_ready),
    );
    report.insert(
        "expanded_source_matrix_c10_ready".to_owned(),
        json!(expanded_source_matrix_c10_ready),
    );
    report.insert(
        "expanded_source_matrix_typed_report".to_owned(),
        candidate_service_contract["expanded_source_matrix_typed_report"].clone(),
    );
    report.insert(
        "dependency_boundary_preserved".to_owned(),
        json!(dependency_boundary_preserved),
    );
    report.insert(
        "product_chain_branch_contract_preserved".to_owned(),
        json!(product_chain_branch_contract_preserved),
    );
    report.insert(
        "report_schema".to_owned(),
        candidate_service_contract["go_free_product_chain_report_schema"].clone(),
    );
    report.insert(
        "default_dependency_policy".to_owned(),
        candidate_service_contract["go_free_product_chain_default_dependency_policy"].clone(),
    );
    report.insert(
        "retained_go_scope".to_owned(),
        candidate_service_contract["go_free_product_chain_retained_go_scope"].clone(),
    );
    report.insert(
        "surface".to_owned(),
        candidate_service_contract["go_free_product_chain_surface"].clone(),
    );
    report.insert(
        "typed_report".to_owned(),
        candidate_service_contract["go_free_product_chain_typed_report"].clone(),
    );
    report.insert("blockers".to_owned(), json!(blockers.clone()));

    GoFreeProductChainGateReport {
        report: Value::Object(report),
    }
}

pub(super) fn attach_go_free_product_chain_gate_from_report(report: &mut Value) {
    let default_product_package_scan = report
        .get("default_product_package_scan")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "name": "default-product-package-scan",
                "status": "not-recorded",
                "default_product_package_go_free": false,
                "go_product_shell_retired_from_default_package": false,
                "blockers": ["C10 default product package source scan is not recorded"],
            })
        });
    let gate = go_free_product_chain_gate_json(
        report["execute"].as_bool().unwrap_or(false),
        &report["release_default_switch_gate"],
        &report["resident_default_daemon_switch_gate"],
        report["outbound_quic_go_dependency_boundary_preserved"]
            .as_bool()
            .unwrap_or(false),
        report["product_chain_branch_contract_preserved"]
            .as_bool()
            .unwrap_or(false),
        &default_product_package_scan,
    )
    .report;
    upsert_go_free_product_chain_gate(report, gate);
}

fn read_text(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
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

pub(super) fn upsert_go_free_product_chain_gate(report: &mut Value, gate: Value) {
    let Some(report_object) = report.as_object_mut() else {
        return;
    };
    let ready = gate["go_free_product_chain_ready"]
        .as_bool()
        .unwrap_or(false);
    let admission_ready = gate["go_free_product_chain_admission_ready"]
        .as_bool()
        .unwrap_or(false);
    report_object.insert("go_free_product_chain_ready".to_owned(), json!(ready));
    report_object.insert(
        "go_free_product_chain_admission_ready".to_owned(),
        json!(admission_ready),
    );
    report_object.insert("go_free_product_chain_gate".to_owned(), gate.clone());
    report_object.insert("c10_go_free_product_chain".to_owned(), gate);
    if let Some(typed_report) = report_object
        .get_mut("typed_report")
        .and_then(Value::as_object_mut)
    {
        typed_report.insert("go_free_product_chain_ready".to_owned(), json!(ready));
        typed_report.insert(
            "go_free_product_chain_admission_ready".to_owned(),
            json!(admission_ready),
        );
    }
}
