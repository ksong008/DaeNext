use super::*;

#[test]
fn default_product_package_scan_accepts_rust_native_release_path() {
    let root = package_scan_fixture_root("rust-native-release");
    let options = write_default_package_scan_fixture(&root, false);
    let scan = go_free_product_chain::default_product_package_scan_json(&options);

    assert_eq!(scan["status"].as_str().unwrap(), "pass");
    assert!(scan["default_product_package_go_free"].as_bool().unwrap());
    assert!(
        scan["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !scan["workflows"]["release"]["source_archive_uses_wing_vendor"]
            .as_bool()
            .unwrap()
    );
    assert!(scan["blockers"].as_array().unwrap().is_empty());
}

#[test]
fn default_product_package_scan_rejects_release_source_go_vendor() {
    let root = package_scan_fixture_root("go-vendor-release");
    let options = write_default_package_scan_fixture(&root, true);
    let scan = go_free_product_chain::default_product_package_scan_json(&options);

    assert_eq!(scan["status"].as_str().unwrap(), "blocked");
    assert!(!scan["default_product_package_go_free"].as_bool().unwrap());
    assert!(
        !scan["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap()
    );
    assert!(
        scan["workflows"]["release"]["source_archive_uses_wing_vendor"]
            .as_bool()
            .unwrap()
    );
    assert!(
        scan["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| { blocker.as_str().unwrap().contains("vendors Go modules") })
    );
}

#[test]
fn go_free_product_chain_gate_blocks_current_candidate_until_go_paths_retire() {
    let mut candidate_service_contract = candidate_service_contract_value(true);
    candidate_service_contract["executed"] = json!(true);
    candidate_service_contract["passed"] = json!(true);
    let resident_gate = json!({
        "candidate_service_contract": candidate_service_contract,
    });
    let release_gate = json!({
        "release_default_switch_ready": true,
        "resident_live_adapter_matrix_ready": true,
    });
    let default_product_package_scan = json!({
        "default_product_package_go_free": false,
        "go_product_shell_retired_from_default_package": false,
        "blockers": ["C10 default product package source scan is not go-free"],
    });
    let gate = go_free_product_chain::go_free_product_chain_gate_json(
        true,
        &release_gate,
        &resident_gate,
        true,
        true,
        &default_product_package_scan,
    )
    .report;

    assert_eq!(gate["status"].as_str().unwrap(), "blocked");
    assert!(!gate["go_free_product_chain_ready"].as_bool().unwrap());
    assert!(
        gate["go_free_product_chain_contract_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !gate["go_product_shell_retired_from_default_package"]
            .as_bool()
            .unwrap()
    );
    assert!(!gate["expanded_source_matrix_c10_ready"].as_bool().unwrap());
    assert!(
        gate["excluded_stream_wrapper_source_matrix_c10_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        gate["scoped_expanded_source_matrix_c10_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["source_matrix_c10_ready"].as_bool().unwrap());
    assert!(gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("Go product shell is not retired")
    }));
    assert!(!gate["blockers"].as_array().unwrap().iter().any(|blocker| {
        blocker
            .as_str()
            .unwrap()
            .contains("scoped source matrix is not ready")
    }));
}

#[test]
fn go_free_product_chain_gate_accepts_complete_final_contract_fixture() {
    let mut candidate_service_contract = candidate_service_contract_value(true);
    candidate_service_contract["executed"] = json!(true);
    candidate_service_contract["passed"] = json!(true);
    for key in [
        "default_product_package_go_free",
        "go_product_shell_retired_from_default_package",
        "go_orchestration_retired_from_default_package",
        "go_control_runtime_api_service_release_retired_from_default_package",
        "go_outbound_dependency_retired_from_default_package",
        "go_compat_oracle_boundary_ready",
        "rust_product_binary_contract_ready",
        "rust_product_lifecycle_contract_ready",
        "rust_product_web_api_package_release_contract_ready",
        "go_free_live_host_contract_ready",
        "go_free_rollback_model_ready",
        "go_free_product_chain_typed_report_ready",
        "go_free_product_chain_ready",
        "expanded_source_matrix_complete",
        "expanded_source_matrix_release_gate_ready",
        "expanded_source_matrix_c10_ready",
    ] {
        candidate_service_contract[key] = json!(true);
    }
    candidate_service_contract["expanded_source_matrix_typed_report"] = json!({
        "schema": "expanded-source-matrix-typed-report",
        "status": "pass",
        "expanded_source_matrix_complete": true,
        "release_gate_ready": true,
        "c10_ready": true,
        "stage_report_schema": false,
    });
    let resident_gate = json!({
        "candidate_service_contract": candidate_service_contract,
    });
    let release_gate = json!({
        "release_default_switch_ready": true,
        "resident_live_adapter_matrix_ready": true,
    });
    let default_product_package_scan = json!({
        "default_product_package_go_free": true,
        "go_product_shell_retired_from_default_package": true,
        "blockers": [],
    });
    let gate = go_free_product_chain::go_free_product_chain_gate_json(
        true,
        &release_gate,
        &resident_gate,
        true,
        true,
        &default_product_package_scan,
    )
    .report;

    assert_eq!(gate["status"].as_str().unwrap(), "pass");
    assert!(
        gate["go_free_product_chain_admission_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(gate["go_free_product_chain_ready"].as_bool().unwrap());
    assert!(gate["expanded_source_matrix_c10_ready"].as_bool().unwrap());
    assert!(gate["source_matrix_c10_ready"].as_bool().unwrap());
    assert!(gate["blockers"].as_array().unwrap().is_empty());
}

fn package_scan_fixture_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "dae-daemon-package-scan-{name}-{}",
        std::process::id()
    ))
}

fn write_default_package_scan_fixture(
    root: &Path,
    release_source_go_vendor: bool,
) -> ProductChainRecertificationOptions {
    let daed = root.join("daed");
    write_fixture_file(
        &daed.join("Makefile"),
        r#"
daed: daed-rust-native

daed-rust-native:
	cargo build $(RUST_DAED_BUILD_ARGS)

daed-go-rollback:
	$(MAKE) OUTPUT=../$(OUTPUT) bundle
"#,
    );
    write_fixture_file(
        &daed.join("Dockerfile"),
        r#"
FROM rust:1-bookworm AS build-daed
RUN DAED_SKIP_WEB_BUILD=1 make APPNAME=daed OUTPUT=/build/daed daed-rust-native
FROM debian:bookworm-slim
RUN mkdir -p /usr/share/daed/web
COPY install/docker-entrypoint.sh /usr/local/bin/daed-docker-entrypoint
"#,
    );
    write_fixture_file(
        &daed.join("publish.Dockerfile"),
        r#"
FROM rust:1-bookworm AS build
RUN DAED_SKIP_WEB_BUILD=1 make APPNAME=daed OUTPUT=/build/daed daed-rust-native
FROM debian:bookworm-slim
RUN mkdir -p /usr/share/daed/web
COPY install/docker-entrypoint.sh /usr/local/bin/daed-docker-entrypoint
"#,
    );
    write_fixture_file(
        &daed.join(".github/workflows/daed2.0.yml"),
        r#"
steps:
  - name: Build Rust native daed
    env:
      DAED_SKIP_WEB_BUILD: 1
    run: make
"#,
    );
    write_fixture_file(
        &daed.join(".github/workflows/test-linux-amd64v3.yml"),
        r#"
steps:
  - name: Build Rust native daed
    env:
      DAED_SKIP_WEB_BUILD: 1
    run: make
"#,
    );
    let release_vendor_step = if release_source_go_vendor {
        r#"
  - name: Download wing vendor
    run: |
      go mod download -modcacherw
    working-directory: wing
"#
    } else {
        r#"
  - name: Verify Rust native source archive inputs
    run: |
      git submodule update --init --recursive
      test -f Makefile
"#
    };
    write_fixture_file(
        &daed.join(".github/workflows/release-please.yml"),
        &format!(
            r#"
env:
  RUSTFLAGS: -C target-cpu=x86-64
steps:
{release_vendor_step}
  - name: make
    run: |
      export DAED_SKIP_WEB_BUILD=1
      make
      fpm ./web=/usr/share/daed/web
"#
        ),
    );

    ProductChainRecertificationOptions {
        daed_repo: daed,
        ..ProductChainRecertificationOptions::default()
    }
}
