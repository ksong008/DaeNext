#[derive(Default)]
struct ProductChainEvidence {
    topology: Value,
    service: Value,
    go_mod: Value,
    repos: Vec<Value>,
    runtime_control_api: Value,
    native_owned_entry_gates: Value,
    native_owned_entry_gate_blockers: Vec<String>,
    resident_runtime_platform_gate: Value,
    resident_runtime_platform_gate_blockers: Vec<String>,
    control_plane_owner_gate: Value,
    control_plane_owner_gate_blockers: Vec<String>,
    datapath_core_gate: Value,
    datapath_core_gate_blockers: Vec<String>,
    outbound_fingerprint_underlay_gate: Value,
    outbound_fingerprint_underlay_gate_blockers: Vec<String>,
    outbound_production_matrix_gate: Value,
    outbound_production_matrix_gate_blockers: Vec<String>,
    dirty_repos: Vec<String>,
    missing_repos: Vec<String>,
    unavailable_repos: Vec<String>,
    branch_mismatched_repos: Vec<String>,
}

fn collect_evidence(
    options: &ProductChainRecertificationOptions,
    admission: ProductChainAdmissionEvidence,
) -> ProductChainEvidence {
    let topology = product_chain_topology(options);
    let service = service_contract_json(&options.service_file);
    let go_mod = go_mod_dependency_boundary_json(options, &topology);
    let runtime_control_api = runtime_control_api_source_contract_json(
        &options.dae_wing_repo,
        &options.daed_repo,
        &topology,
    );
    let native_owned_entry_gates = native_owned_entry_gates_json(
        true,
        options,
        &topology.as_json(&options.dae_wing_repo, &options.daed_repo),
        &service,
        &runtime_control_api,
    );
    let resident_default_daemon_switch_gate = resident_default_daemon_switch_gate_json(options);
    let resident_runtime_platform_gate =
        resident_runtime_platform_gate_json(true, options, &resident_default_daemon_switch_gate);
    let control_plane_owner_gate = control_plane_owner_gate_json(
        true,
        options,
        &resident_runtime_platform_gate.report,
        &resident_default_daemon_switch_gate,
        admission,
    );
    let datapath_core_gate = datapath_core_gate_json(
        true,
        options,
        &control_plane_owner_gate.report,
        &resident_default_daemon_switch_gate,
        admission,
    );
    let outbound_fingerprint_underlay_gate = outbound_fingerprint_underlay_gate_json(
        true,
        options,
        &datapath_core_gate.report,
        &resident_default_daemon_switch_gate,
        admission,
    );
    let outbound_production_matrix_gate = outbound_production_matrix_gate_json(
        true,
        options,
        &outbound_fingerprint_underlay_gate.report,
        &resident_default_daemon_switch_gate,
        admission,
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
        native_owned_entry_gates: native_owned_entry_gates.report,
        native_owned_entry_gate_blockers: native_owned_entry_gates.blockers,
        resident_runtime_platform_gate: resident_runtime_platform_gate.report,
        resident_runtime_platform_gate_blockers: resident_runtime_platform_gate.blockers,
        control_plane_owner_gate: control_plane_owner_gate.report,
        control_plane_owner_gate_blockers: control_plane_owner_gate.blockers,
        datapath_core_gate: datapath_core_gate.report,
        datapath_core_gate_blockers: datapath_core_gate.blockers,
        outbound_fingerprint_underlay_gate: outbound_fingerprint_underlay_gate.report,
        outbound_fingerprint_underlay_gate_blockers: outbound_fingerprint_underlay_gate.blockers,
        outbound_production_matrix_gate: outbound_production_matrix_gate.report,
        outbound_production_matrix_gate_blockers: outbound_production_matrix_gate.blockers,
        dirty_repos,
        missing_repos,
        unavailable_repos,
        branch_mismatched_repos,
    }
}
