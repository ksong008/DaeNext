use super::*;
pub(super) fn c3_daed_service_contract(
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
        "name": "daed-service-contract",
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

pub(super) fn package_hooks_json(daed_repo: &Path) -> Value {
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
