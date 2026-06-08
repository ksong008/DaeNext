use super::*;
#[test]
pub(super) fn reload_bpf_ownership_matches_golden_fixture() {
    let fixture = load("control/reload_bpf_ownership/eject_inject.json");
    let steps = fixture["steps"].as_array().unwrap();
    let mut flip = CoreFlip::default();
    let mut fresh = ReloadCoreState::new(false, &mut flip);
    assert_reload_state("fresh_init", &fresh, &steps[0]);
    fresh.eject_bpf();
    assert_reload_state("after_eject", &fresh, &steps[1]);
    fresh.inject_bpf();
    assert_reload_state("after_inject", &fresh, &steps[2]);

    let mut reload = ReloadCoreState::new(true, &mut flip);
    assert_reload_state("reload_init", &reload, &steps[3]);
    reload.eject_bpf();
    assert_reload_state("reload_after_eject", &reload, &steps[4]);
}

#[test]
pub(super) fn runtime_dependency_plan_keeps_stage7_env_gates() {
    let plan = RuntimeDependencyPlan::stage7_default();
    let gates = plan.gates.iter().map(|gate| gate.name).collect::<Vec<_>>();
    assert_eq!(
        gates,
        vec![
            "root",
            "bpffs",
            "netns_permission",
            "memlock",
            "kernel_feature_version"
        ]
    );
}

#[test]
pub(super) fn reload_dns_cache_plan_restores_only_when_dns_config_is_unchanged() {
    let restore = ReloadDnsCachePlan::decide(true, true, 2);
    assert!(restore.restore_cache);
    assert!(restore.clear_domain_routing_map);
    assert_eq!(restore.snapshot_entries, 2);

    let changed = ReloadDnsCachePlan::decide(false, true, 2);
    assert!(!changed.restore_cache);
    assert!(changed.clear_domain_routing_map);

    let empty = ReloadDnsCachePlan::decide(true, false, 0);
    assert!(!empty.restore_cache);
    assert!(!empty.clear_domain_routing_map);
}

#[test]
pub(super) fn control_api_typed_report_covers_formal_surfaces_without_stage_schema() {
    let report = ControlApiTypedReport::formal_runtime_control_api();
    assert_eq!(report.schema, "control-api-typed-report");
    assert_eq!(report.status, ControlApiReportStatus::Pass);
    assert_eq!(report.status.as_str(), "pass");
    assert!(report.runtime_overview_available);
    assert!(report.reload_core_state_available);
    assert!(report.domain_routing_owner_available);
    assert!(report.runtime_dependency_plan_available);
    assert!(!report.stage_report_schema);
}

#[test]
pub(super) fn runtime_state_report_requires_all_rust_owned_surfaces_for_default_control_plane() {
    let empty = RuntimeStateReport::new();
    assert!(empty.api_compatible);
    assert!(!empty.ready_for_default_control_plane());

    let ready = RuntimeStateReport::rust_owned_control_plane();
    assert_eq!(ready.schema_version, RuntimeStateReport::SCHEMA_VERSION);
    assert!(ready.ready_for_default_control_plane());

    let mut missing_active = ready;
    missing_active.active_handoff_available = false;
    assert!(!missing_active.ready_for_default_control_plane());
}

#[test]
pub(super) fn control_plane_default_admission_keeps_c_tproxy_oracle_until_full_gate_passes() {
    let ready = RuntimeStateReport::rust_owned_control_plane();
    let admission = ControlPlaneDefaultAdmission {
        runtime: ready,
        benchmark_passed: true,
        unit_passed: true,
        integration_passed: true,
        reload_passed: true,
        host_write_passed: true,
        cleanup_passed: true,
        rollback_passed: true,
        c_tproxy_oracle_retained: true,
    };
    assert!(admission.admitted());

    let mut missing_host_write = admission;
    missing_host_write.host_write_passed = false;
    assert!(!missing_host_write.admitted());

    let mut removed_c_oracle = admission;
    removed_c_oracle.c_tproxy_oracle_retained = false;
    assert!(!removed_c_oracle.admitted());
}
