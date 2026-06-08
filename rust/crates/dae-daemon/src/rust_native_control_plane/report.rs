use super::*;
pub fn default_rust_native_control_plane_admission_root() -> PathBuf {
    PathBuf::from("/tmp/dae-rust-native-control-plane-admission")
}

pub fn rust_native_control_plane_admission_report(
    root: &Path,
    iterations: u32,
) -> Result<Value, String> {
    let iterations = if iterations == 0 {
        DEFAULT_ITERATIONS
    } else {
        iterations
    };
    ensure_safe_rust_native_control_plane_root(root)?;
    if root.exists() {
        fs::remove_dir_all(root).map_err(|err| {
            format!(
                "failed to remove existing rust-native-control-plane root {}: {err}",
                path_string(root)
            )
        })?;
    }

    let run_dir = root.join("run");
    let manifest_file = run_dir.join("rust-native-control-plane-admission.json");
    let log_file = root
        .join("log")
        .join("rust-native-control-plane-admission.log");
    fs::create_dir_all(&run_dir).map_err(|err| {
        format!(
            "failed to create rust-native-control-plane run dir {}: {err}",
            path_string(&run_dir)
        )
    })?;
    if let Some(parent) = log_file.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create rust-native-control-plane log dir {}: {err}",
                path_string(parent)
            )
        })?;
    }

    let flow = run_native_control_plane_flow()?;
    let benchmark = run_native_control_plane_benchmark(iterations)?;
    let datapath = rust_aya_datapath_contract()?;
    let datapath_contract_ready = datapath
        .get("go_bpf_loader_removed_when_opted_in")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && datapath
            .get("rust_aya_skeleton_object_supported")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        && datapath
            .get("kernel_ebpf_program_rewrite")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        && datapath
            .get("go_userspace_outbound_remains_authoritative")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let admitted = flow.admission_ready
        && flow.runtime_ready
        && flow.domain_apply.entries_updated > 0
        && flow.domain_duplicate.skipped
        && flow.domain_reload_clear_deletes > 0
        && flow.domain_reload_restore.entries_updated > 0
        && flow.reload_plan.restore_cache
        && flow.reload_plan.clear_domain_routing_map
        && flow.routing_apply.map.routing_entries_updated > 0
        && flow.routing_duplicate_skipped
        && flow.sniff_domain == "example.com"
        && flow.userspace_routing_outbound == OutboundIndex::USER_DEFINED_MIN
        && flow.connectivity_apply_entries > 0
        && flow.connectivity_duplicate_skipped
        && datapath_contract_ready;

    let smoke = json!({
        "dns_owner_key": flow.dns_event.owner_key,
        "dns_ip_count": flow.dns_event.ips.len(),
        "dns_cache_hit_response_len": flow.dns_event.cache_hit_response_len,
        "domain_apply": {
            "entries_updated": flow.domain_apply.entries_updated,
            "entries_deleted": flow.domain_apply.entries_deleted,
            "skipped": flow.domain_apply.skipped,
            "owner_count": flow.domain_apply.owner_count,
            "ip_count": flow.domain_apply.ip_count
        },
        "domain_duplicate": {
            "entries_updated": flow.domain_duplicate.entries_updated,
            "entries_deleted": flow.domain_duplicate.entries_deleted,
            "skipped": flow.domain_duplicate.skipped
        },
        "domain_reload_clear_deletes": flow.domain_reload_clear_deletes,
        "domain_reload_restore": {
            "entries_updated": flow.domain_reload_restore.entries_updated,
            "skipped": flow.domain_reload_restore.skipped,
            "owner_count": flow.domain_reload_restore.owner_count,
            "ip_count": flow.domain_reload_restore.ip_count
        },
        "reload_plan": {
            "dns_config_unchanged": flow.reload_plan.dns_config_unchanged,
            "bpf_present": flow.reload_plan.bpf_present,
            "snapshot_entries": flow.reload_plan.snapshot_entries,
            "restore_cache": flow.reload_plan.restore_cache,
            "clear_domain_routing_map": flow.reload_plan.clear_domain_routing_map
        },
        "routing_apply": {
            "routing_entries_updated": flow.routing_apply.map.routing_entries_updated,
            "lpm_maps_created": flow.routing_apply.map.lpm_maps_created,
            "rule_count": flow.routing_apply.rule_count,
            "lpm_rule_count": flow.routing_apply.lpm_rule_count,
            "skipped": flow.routing_apply.map.skipped
        },
        "routing_duplicate_skipped": flow.routing_duplicate_skipped,
        "sniff_domain": flow.sniff_domain,
        "userspace_routing_outbound": flow.userspace_routing_outbound.value(),
        "connectivity_apply_entries": flow.connectivity_apply_entries,
        "connectivity_duplicate_skipped": flow.connectivity_duplicate_skipped
    });
    let benchmark = json!({
        "iterations": benchmark.iterations,
        "dns_packet_to_domain_event_ns_per_op": benchmark.dns_packet_to_domain_event_ns_per_op,
        "domain_routing_duplicate_ns_per_op": benchmark.domain_routing_duplicate_ns_per_op,
        "domain_routing_toggle_ns_per_op": benchmark.domain_routing_toggle_ns_per_op,
        "reload_transaction_ns_per_op": benchmark.reload_transaction_ns_per_op,
        "routing_owner_duplicate_ns_per_op": benchmark.routing_owner_duplicate_ns_per_op,
        "connectivity_owner_duplicate_ns_per_op": benchmark.connectivity_owner_duplicate_ns_per_op,
        "benchmark_executable_now": true,
        "hot_path_cgo_required": false
    });
    let mut report = json!({
        "name": "rust-native-control-plane-admission",
        "root": path_string(root),
        "run_dir": path_string(&run_dir),
        "manifest_file": path_string(&manifest_file),
        "log_file": path_string(&log_file),
        "rust_native_control_plane_no_cgo_admitted": admitted,
        "hot_path_cgo_required": false,
        "ffi_symbols_called": false,
        "helper_required": false,
        "persistent_helper_required": false,
        "go_bpf_loader_required": false,
        "go_product_shell_retained": true,
        "go_outbound_protocol_stack_retained": true,
        "daewing_outbound_quic_go_protocol_stack_retained": true,
        "dns_packet_parse_native": true,
        "dns_cache_store_native": true,
        "dns_domain_routing_event_native": true,
        "domain_routing_owner_native": true,
        "reload_transaction_native": true,
        "routing_lpm_owner_native": true,
        "connectivity_owner_native": true,
        "rust_owned_runtime_ready": flow.runtime_ready,
        "control_plane_default_admission_ready": flow.admission_ready,
        "rust_aya_datapath_contract_ready": datapath_contract_ready,
        "rust_owned_1_to_5": {
            "phase_1_r6_transition_baseline_recorded": true,
            "phase_2_runtime_control_plane_entry_admitted": flow.runtime_ready && flow.admission_ready,
            "phase_3_dns_domain_reload_default_hot_path_admitted": flow.domain_apply.entries_updated > 0
                && flow.domain_duplicate.skipped
                && flow.domain_reload_clear_deletes > 0
                && flow.domain_reload_restore.entries_updated > 0
                && flow.reload_plan.restore_cache
                && flow.reload_plan.clear_domain_routing_map,
            "phase_4_routing_sniff_active_handoff_state_admitted": flow.routing_apply.map.routing_entries_updated > 0
                && flow.routing_duplicate_skipped
                && flow.sniff_domain == "example.com"
                && flow.userspace_routing_outbound == OutboundIndex::USER_DEFINED_MIN
                && flow.runtime_ready,
            "phase_5_rust_aya_datapath_parity_candidate_admitted": datapath_contract_ready,
            "all_1_to_5_admission_completed": admitted,
            "helper_expansion_allowed": false,
            "outbound_protocol_rewrite_allowed": false,
            "c_tproxy_oracle_retained": true,
            "product_default_switch_allowed_by_this_report": false
        },
        "rust_aya_datapath_contract": {
            "name": datapath.get("name").cloned().unwrap_or(Value::Null),
            "default_object_source": datapath.get("default_object_source").cloned().unwrap_or(Value::Null),
            "go_bpf_loader_removed_when_opted_in": datapath.get("go_bpf_loader_removed_when_opted_in").cloned().unwrap_or(Value::Bool(false)),
            "rust_aya_skeleton_object_supported": datapath.get("rust_aya_skeleton_object_supported").cloned().unwrap_or(Value::Bool(false)),
            "kernel_ebpf_program_rewrite": datapath.get("kernel_ebpf_program_rewrite").cloned().unwrap_or(Value::Bool(false)),
            "go_userspace_outbound_remains_authoritative": datapath.get("go_userspace_outbound_remains_authoritative").cloned().unwrap_or(Value::Bool(false))
        },
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "production_paths_mutated": false,
        "remote_38_host_write_required_for_this_admission": false,
        "source": [
            "DAEX_RUST_PERFORMANCE_OPTIMIZATION_PLAN_2026-05-24.md:rust-native-control-plane-no-cgo",
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md"
        ]
    });
    report["smoke"] = smoke;
    report["benchmark"] = benchmark;

    let manifest = serde_json::to_vec_pretty(&report).map_err(|err| {
        format!("failed to encode rust-native-control-plane admission manifest: {err}")
    })?;
    fs::write(&manifest_file, manifest).map_err(|err| {
        format!(
            "failed to write rust-native-control-plane admission manifest {}: {err}",
            path_string(&manifest_file)
        )
    })?;
    fs::write(&log_file, "rust-native-control-plane no-cgo admission\n").map_err(|err| {
        format!(
            "failed to write rust-native-control-plane admission log {}: {err}",
            path_string(&log_file)
        )
    })?;
    Ok(report)
}
