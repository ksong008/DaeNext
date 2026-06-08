use super::*;
pub(super) fn expected_product_chain_branches_json() -> Value {
    json!({
        "dae": expected_product_chain_branch("dae"),
        "daed": expected_product_chain_branch("daed"),
        "dae_wing": expected_product_chain_branch("dae-wing"),
        "outbound": expected_product_chain_branch("outbound"),
        "quic_go": expected_product_chain_branch("quic-go"),
    })
}

pub(super) fn resident_default_daemon_switch_gate_json(
    options: &ProductChainRecertificationOptions,
) -> Value {
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
