use super::*;

#[test]
fn product_chain_report_records_c0_c3_native_owned_entry_gates() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c0-c3-{}",
        std::process::id()
    ));
    let fixture = root.join("fixture");
    let daed = fixture.join("daed");
    let wing = daed.join("wing");
    let dae = fixture.join("dae");
    let outbound = fixture.join("outbound");
    let quic_go = fixture.join("quic-go");
    write_c0_c3_fixture(&dae, &daed, &wing, &outbound, &quic_go);

    let options = ProductChainRecertificationOptions {
        execute: true,
        dae_repo: dae.clone(),
        dae_wing_repo: wing.clone(),
        daed_repo: daed.clone(),
        outbound_repo: outbound.clone(),
        quic_go_repo: quic_go.clone(),
        service_file: daed.join("install/daed.service"),
        go_mod_file: dae.join("go.mod"),
        ..ProductChainRecertificationOptions::default()
    };
    let report = product_chain_recertification_report(
        &root,
        &options,
        ProductChainAdmissionEvidence::default(),
    )
    .unwrap();

    assert!(report["product_chain_topology_locked"].as_bool().unwrap());
    assert!(report["default_bundle_boundary_clean"].as_bool().unwrap());
    assert!(
        report["default_runtime_selector_rust_owned"]
            .as_bool()
            .unwrap()
    );
    assert!(report["explicit_go_rollback_only"].as_bool().unwrap());
    assert!(
        report["runtime_selector_matrix_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(report["daed_service_contract_ready"].as_bool().unwrap());
    assert!(report["c0_c3_entry_gates_clean"].as_bool().unwrap());
    assert_eq!(
        report["c0_product_chain_topology_lock"]["build_truth"]
            .as_str()
            .unwrap(),
        "daed/wing-submodule"
    );
    assert_eq!(
        report["c3_daed_service_contract"]["runtime_api_paths"][0]
            .as_str()
            .unwrap(),
        "/api/runtime/overview"
    );
    assert!(
        report["typed_report"]["product_chain_topology_locked"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["typed_report"]["daed_service_contract_ready"]
            .as_bool()
            .unwrap()
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn product_chain_topology_lock_blocks_sibling_wing_substitution() {
    let root = std::env::temp_dir().join(format!(
        "dae-daemon-product-chain-c0-block-{}",
        std::process::id()
    ));
    let fixture = root.join("fixture");
    let daed = fixture.join("daed");
    let wing = fixture.join("dae-wing");
    let dae = fixture.join("dae");
    let outbound = fixture.join("outbound");
    let quic_go = fixture.join("quic-go");
    write_c0_c3_fixture(&dae, &daed, &daed.join("wing"), &outbound, &quic_go);
    std::fs::create_dir_all(&wing).unwrap();
    init_fixture_repo(&wing, expected_product_chain_branch("dae-wing"));

    let options = ProductChainRecertificationOptions {
        execute: true,
        dae_repo: dae.clone(),
        dae_wing_repo: wing,
        daed_repo: daed.clone(),
        outbound_repo: outbound,
        quic_go_repo: quic_go,
        service_file: daed.join("install/daed.service"),
        go_mod_file: dae.join("go.mod"),
        ..ProductChainRecertificationOptions::default()
    };
    let report = product_chain_recertification_report(
        &root,
        &options,
        ProductChainAdmissionEvidence::default(),
    )
    .unwrap();

    assert!(!report["product_chain_topology_locked"].as_bool().unwrap());
    assert!(
        !report["c0_product_chain_topology_lock"]["submodule_build_truth_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        report["remaining_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker
                .as_str()
                .unwrap()
                .contains("not locked to daed/wing submodule"))
    );
    let _ = std::fs::remove_dir_all(root);
}

fn write_c0_c3_fixture(dae: &Path, daed: &Path, wing: &Path, outbound: &Path, quic_go: &Path) {
    for (repo, branch) in [
        (dae, expected_product_chain_branch("dae")),
        (daed, expected_product_chain_branch("daed")),
        (wing, expected_product_chain_branch("daed-wing")),
        (outbound, expected_product_chain_branch("outbound")),
        (quic_go, expected_product_chain_branch("quic-go")),
    ] {
        init_fixture_repo(repo, branch);
    }
    write_fixture_file(
        &dae.join("go.mod"),
        &format!(
            "module github.com/daeuniverse/dae\n\
             replace github.com/daeuniverse/outbound => {}\n\
             replace github.com/daeuniverse/quic-go => {}\n",
            path_string(outbound),
            path_string(quic_go)
        ),
    );
    write_fixture_file(
        &wing.join("go.mod"),
        &format!(
            "module github.com/daeuniverse/dae-wing\n\
             replace github.com/daeuniverse/dae => ./dae-core\n\
             replace github.com/daeuniverse/outbound => {}\n\
             replace github.com/daeuniverse/quic-go => {}\n",
            path_string(outbound),
            path_string(quic_go)
        ),
    );
    write_fixture_file(
        &wing.join("dae-core/go.mod"),
        &format!(
            "module github.com/daeuniverse/dae\n\
             replace github.com/daeuniverse/outbound => {}\n\
             replace github.com/daeuniverse/quic-go => {}\n",
            path_string(outbound),
            path_string(quic_go)
        ),
    );
    write_fixture_file(
        &wing.join("Makefile"),
        "BUNDLE_TAGS ?= embedallowed\n\
         bundle: deps rust-aya-bpf-loader-asset bundle-build\n\
         bundle-rust-owned: BUNDLE_TAGS := embedallowed,rust_owned_daemon_embed\n\
         bundle-rust-owned: deps rust-aya-bpf-loader-asset rust-daemon-embed bundle-build\n\
         deps:\n\
         rust-aya-bpf-loader-asset:\n\
         rust-daemon-embed:\n\
         bundle-build:\n",
    );
    write_fixture_file(
        &wing.join("engine/runtime_mode.go"),
        "package engine\n\
         const (\n\
          runtimeModeGo = \"go\"\n\
          runtimeModeRustOwned = \"rust-owned\"\n\
          runtimeModeDefault = runtimeModeRustOwned\n\
         )\n\
         func selectedRuntimeMode() string { return runtimeModeDefault }\n\
         func normalizeRuntimeMode(raw string) string {\n\
          switch raw {\n\
          case \"auto\":\n\
           return runtimeModeDefault\n\
          case \"go\", \"native\", \"dae-go\", \"go-native\":\n\
           return runtimeModeGo\n\
          }\n\
          return runtimeModeRustOwned\n\
         }\n",
    );
    write_fixture_file(
        &wing.join("engine/rust_owned_service_test.go"),
        "package engine\n\
         func TestNewDefaultServiceUsesRustOwnedRuntimeByDefault() {}\n\
         func TestNewDefaultServiceUsesRustOwnedRuntimeForAuto() {}\n\
         func TestNewDefaultServiceAllowsExplicitRustOwnedRuntime() {}\n\
         func TestNewDefaultServiceAllowsExplicitGoRollback() { _ = \"DAED_RUNTIME_MODE\" }\n",
    );
    write_fixture_file(
        &daed.join("install/daed.service"),
        "[Service]\n\
         Type=simple\n\
         User=root\n\
         ExecStart=/usr/bin/daed run -c /etc/daed/\n\
         ExecReload=/bin/kill -HUP $MAINPID\n",
    );
    write_fixture_file(
        &daed.join("install/package_after_install.sh"),
        "systemctl daemon-reload\n\
         if [ \"$(systemctl is-active daed)\" == 'active' ]; then\n\
             systemctl restart daed.service\n\
         fi\n",
    );
    write_fixture_file(
        &daed.join("install/package_after_remove.sh"),
        "systemctl daemon-reload\n",
    );
    write_runtime_control_fixture(daed, wing);
}

fn write_runtime_control_fixture(daed: &Path, wing: &Path) {
    write_fixture_file(
        &wing.join("cmd/run.go"),
        "engine.Default().Run(\n\
         orchestrator.RestoreRunningState(\n\
         mux.Handle(\"/api/\"\n\
         http.StripPrefix(\"/api\", httpapi.NewHandler())\n\
         \"/api/events/runtime\"\n",
    );
    write_fixture_file(
        &wing.join("transport/httpapi/handler.go"),
        "mux.HandleFunc(\"/runtime/overview\"\n\
         mux.HandleFunc(\"/runtime/reload\"\n\
         mux.HandleFunc(\"/runtime/stop\"\n\
         mux.HandleFunc(\"/events/runtime\"\n\
         engine.Default().GetRuntimeOverview(windowSec, maxPoints)\n\
         orchestrator.Run(ctx, req.Dry)\n\
         orchestrator.Stop(r.Context(), timeout)\n",
    );
    write_fixture_file(
        &wing.join("orchestrator/config_run.go"),
        "engine.Default().ReloadContext(ctx, engine.Default().EmptyConfig())\n\
         engine.Default().ParseConfig(\n\
         engine.Default().NecessaryOutbounds(\n\
         engine.Default().ReloadContext(ctx, c)\n\
         engine.Default().Stop(timeout)\n",
    );
    write_fixture_file(
        &wing.join("engine/engine.go"),
        "func Default() Service\n\
         ReloadContext(ctx context.Context, conf *daeConfig.Config) error\n\
         GetRuntimeOverview(windowSec int, maxPoints int)\n\
         daeengine\n",
    );
    write_fixture_file(
        &wing.join("dae-core/engine/runtime.go"),
        "func (e *Engine) Run(\n\
         func (e *Engine) ReloadWithContext(\n\
         func (e *Engine) Stop(\n\
         func (e *Engine) GetRuntimeOverview(\n\
         func (e *Engine) HTTPTransport()\n",
    );
    write_fixture_file(
        &daed.join("apps/web/src/apis/mutation.ts"),
        "'/runtime/reload'\n'/runtime/stop'\nQUERY_KEY_GENERAL\n",
    );
    write_fixture_file(
        &daed.join("apps/web/src/apis/query.ts"),
        "'/runtime/overview'\n\
         '/events/runtime'\n\
         'runtime.overview'\n\
         'runtime.overview.delta'\n\
         mergeRuntimeOverviewDelta(previousData, payload, windowSec, maxPoints)\n",
    );
    write_fixture_file(
        &daed.join("apps/web/src/apis/runtime_overview.ts"),
        "adaptRuntimeOverview\nmergeRuntimeOverviewDelta\ntrimRuntimeOverviewSamples\n",
    );
    write_fixture_file(
        &daed.join("apps/web/src/components/Header.tsx"),
        "useReloadRuntimeMutation()\n\
         useStopRuntimeMutation()\n\
         reloadRuntimeMutation.mutate({ dry: false })\n",
    );
}
