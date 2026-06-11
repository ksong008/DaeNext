use super::*;

pub(super) fn resident_cgroup_attach_evidence(
    executed_steps: &mut Vec<Value>,
    interface_attach_options: &ProductionRuntimeOwnerOptions,
    selected_native_param_object: &Path,
    native_runtime: &mut NativeEbpfRuntimeState,
    wan_ifaces: &[String],
    ok: bool,
    native_param_image: &Value,
) -> (bool, Value) {
    let cgroup_pname_evidence = json!({
        "source": "current_comm",
        "coreEnabled": false,
        "currentTaskArgvEnabled": false,
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
            false,
            json!({
                "status": "fail",
                "backend": "aya",
                "wan_interfaces": wan_ifaces,
                "native_attached": false,
                "error": "native Aya cgroup attach failed; non-native cgroup backend is not used by Rust resident",
                "pname": cgroup_pname_evidence,
                "linkLifecycle": cgroup_link_lifecycle,
            }),
        ),
        None => (
            false,
            json!({
                "status": "fail",
                "backend": Value::Null,
                "wan_interfaces": wan_ifaces,
                "native_attached": false,
                "error": "wan_interface/pname requires native Aya cgroup attach; non-native cgroup backend is not used by Rust resident",
                "pname": cgroup_pname_evidence,
                "linkLifecycle": cgroup_link_lifecycle,
            }),
        ),
    }
}
