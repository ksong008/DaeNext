use super::*;

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
