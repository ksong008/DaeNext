use super::*;

// Resident startup evidence keeps attach inputs and report artifacts explicit.
#[allow(clippy::too_many_arguments)]
pub(super) fn resident_cgroup_attach_evidence(
    executed_steps: &mut Vec<Value>,
    interface_attach_options: &ProductionRuntimeOwnerOptions,
    selected_native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
    wan_ifaces: &[String],
    ok: bool,
    native_param_image: &Value,
    pname_rules_required: bool,
) -> (bool, Value) {
    let cgroup_pname_evidence = json!({
        "source": "current_comm",
        "fallbackSource": "bpf_get_current_comm",
        "semantics": "non_core_task_comm",
        "coreEnabled": false,
        "nonCoreTaskCommEnabled": true,
        "currentTaskArgvEnabled": false,
        "officialArgvSemanticsImplemented": false,
        "coreStatus": "not_implemented",
        "pnameRulesRequired": pname_rules_required,
        "paramHasBpfGetCurrentTask": native_param_image
            .pointer("/param/has_bpf_get_current_task")
            .cloned()
            .unwrap_or(Value::Null),
    });
    let cgroup_link_lifecycle = json!({
        "status": "owned-by-aya-runtime",
        "attachMode": "single",
        "releaseBoundary": "resident-runtime-reset",
        "staleCleanup": "owned-link-drop",
        "programs": dae_cgroup_attach_matrix()
            .iter()
            .map(|line| json!({
                "role": format!("{:?}", line.role),
                "section": line.section,
                "programName": line.program_name,
                "programKind": line.aya_program_kind.as_str(),
                "attachMode": line.attach_mode,
                "linkLifetimeOwnedByBackend": line.link_lifetime_owned_by_backend,
            }))
            .collect::<Vec<_>>(),
    });

    if wan_ifaces.is_empty() {
        return (
            ok,
            json!({
                "status": "skipped",
                "reason": "wan_interface is not configured; pname cgroup monitor is not required",
                "wan_interfaces": wan_ifaces,
                "pname": cgroup_pname_evidence,
                "linkLifecycle": cgroup_link_lifecycle,
            }),
        );
    }

    if !ok {
        return (
            false,
            json!({
                "status": "skipped",
                "reason": "previous resident runtime step did not pass",
                "wan_interfaces": wan_ifaces,
                "pname": cgroup_pname_evidence,
                "linkLifecycle": cgroup_link_lifecycle,
            }),
        );
    }

    match native_runtime.attach_cgroup_programs(
        executed_steps,
        interface_attach_options,
        selected_native_param_object,
    ) {
        Some(true) => (
            true,
            json!({
                "status": "pass",
                "backend": "aya",
                "wan_interfaces": wan_ifaces,
                "native_attached": true,
                "pname": cgroup_pname_evidence,
                "linkLifecycle": cgroup_link_lifecycle,
            }),
        ),
        Some(false) => (
            cgroup_attach_failure_admitted_without_pname_rules(pname_rules_required),
            cgroup_attach_failure_value(
                "aya",
                wan_ifaces,
                "native Aya cgroup attach failed; non-native cgroup backend is not used by Rust resident",
                cgroup_pname_evidence,
                cgroup_link_lifecycle,
                pname_rules_required,
            ),
        ),
        None => (
            cgroup_attach_failure_admitted_without_pname_rules(pname_rules_required),
            cgroup_attach_failure_value(
                "",
                wan_ifaces,
                "wan_interface/pname requires native Aya cgroup attach; non-native cgroup backend is not used by Rust resident",
                cgroup_pname_evidence,
                cgroup_link_lifecycle,
                pname_rules_required,
            ),
        ),
    }
}

pub(super) fn resident_routing_requires_process_name(config: &Config) -> bool {
    config
        .routing
        .rules
        .iter()
        .any(|rule| rule.and_functions.iter().any(function_uses_process_name))
}

fn function_uses_process_name(function: &dae_config::Function) -> bool {
    function.name.eq_ignore_ascii_case("pname")
        || function
            .params
            .iter()
            .any(|param| param.and_functions.iter().any(function_uses_process_name))
}

fn cgroup_attach_failure_admitted_without_pname_rules(pname_rules_required: bool) -> bool {
    !pname_rules_required
}

fn cgroup_attach_failure_value(
    backend: &str,
    wan_ifaces: &[String],
    error: &str,
    pname: Value,
    link_lifecycle: Value,
    pname_rules_required: bool,
) -> Value {
    let degraded = cgroup_attach_failure_admitted_without_pname_rules(pname_rules_required);
    let backend = if backend.is_empty() {
        Value::Null
    } else {
        json!(backend)
    };
    json!({
        "status": if degraded { "degraded" } else { "fail" },
        "backend": backend,
        "wan_interfaces": wan_ifaces,
        "native_attached": false,
        "error": error,
        "pname": pname,
        "linkLifecycle": link_lifecycle,
        "pnameRulesRequired": pname_rules_required,
        "controlPlaneEscape": if degraded { "mark_fallback" } else { "unavailable" },
        "degradedReason": if degraded {
            Value::String("pname() routing rules are not configured; control-plane escape can use skb mark fallback".to_owned())
        } else {
            Value::Null
        },
    })
}
