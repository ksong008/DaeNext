use std::fs;
use std::path::Path;

use serde_json::{Map, Value, json};

use super::path_string;
use super::topology::{ProductChainTopology, ProductChainTopologyKind};

pub(super) fn runtime_control_api_source_contract_json(
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
        source_file_contract_any_json(
            repo,
            "cmd/run.go",
            &[
                (
                    "runtime_lifecycle_run",
                    &[
                        "engine.DefaultRuntimeLifecycleService().Run(",
                        "engine.Default().Run(",
                    ][..],
                ),
                (
                    "restore_running_state",
                    &["orchestrator.RestoreRunningState("][..],
                ),
                ("control_plane_api_handler", &["httpapi.NewHandler()"][..]),
                ("api_only_mode_preserved", &["apiOnly"][..]),
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
        source_contract_alternative_json(
            "runtime_status_access_provider",
            vec![
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
                    "engine/engine.go",
                    &[
                        ("engine_default_service", "func Default() Service"),
                        (
                            "reload_context",
                            "ReloadContext(ctx context.Context, conf *daeConfig.Config) error",
                        ),
                        (
                            "runtime_overview_service",
                            "GetRuntimeOverview(windowSec int, maxPoints int)",
                        ),
                        (
                            "route_aware_http_transport",
                            "HTTPTransport() http.RoundTripper",
                        ),
                    ],
                ),
            ],
        ),
        source_file_contract_any_json(
            repo,
            "orchestrator/config_run.go",
            &[
                ("runtime_lifecycle_lock", &["lockRuntimeLifecycle()"][..]),
                (
                    "reload_with_context",
                    &["ReloadWithContext(ctx, c)", "ReloadContext(ctx, c)"][..],
                ),
                (
                    "dry_run_reload_with_empty_config",
                    &[
                        "ReloadWithContext(ctx, engine.DefaultConfigService().EmptyConfig())",
                        "ReloadContext(ctx, engine.Default().EmptyConfig())",
                    ][..],
                ),
                (
                    "restore_running_state_entrypoint",
                    &["RestoreRunningState(ctx context.Context)"][..],
                ),
                (
                    "stop_runtime",
                    &[
                        "engine.DefaultRuntimeLifecycleService().Stop(timeout)",
                        "engine.Default().Stop(timeout)",
                    ][..],
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

fn source_contract_alternative_json(name: &str, variants: Vec<Value>) -> Value {
    let source_contract_preserved = variants.iter().any(|variant| {
        variant["source_contract_preserved"]
            .as_bool()
            .unwrap_or(false)
    });
    json!({
        "name": name,
        "status": if source_contract_preserved { "pass" } else { "fail" },
        "source_contract_preserved": source_contract_preserved,
        "alternatives": variants,
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

fn source_file_contract_any_json(repo: &Path, relative: &str, checks: &[(&str, &[&str])]) -> Value {
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
    for (name, needles) in checks {
        let found = needles.iter().any(|needle| text.contains(needle));
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
