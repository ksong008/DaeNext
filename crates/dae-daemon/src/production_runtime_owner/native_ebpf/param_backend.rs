use super::*;
pub(crate) fn prepare_native_param_object(
    options: &ProductionRuntimeOwnerOptions,
    command_param_object: &Path,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
    dae_netns_id: u32,
) -> NativeParamObjectPreparation {
    if !options.native_ebpf_requested {
        return NativeParamObjectPreparation {
            selected_param_object: command_param_object.to_path_buf(),
            report: json!({
                "status": "skipped",
                "reason": "native eBPF backend was not requested",
                "selected_param_object": path_string(command_param_object),
                "command_param_object": path_string(command_param_object),
            }),
            load_input: None,
        };
    }
    if !options.native_ebpf_embedded_object {
        return NativeParamObjectPreparation {
            selected_param_object: command_param_object.to_path_buf(),
            report: json!({
                "status": "skipped",
                "reason": "native eBPF embedded object is not available",
                "selected_param_object": path_string(command_param_object),
                "command_param_object": path_string(command_param_object),
            }),
            load_input: None,
        };
    }
    let map_profile = selected_native_map_profile();
    let mut param = dae_ebpf_support::build_dae_param_with_protection(
        DaeParamInput {
            tproxy_port: options.tproxy_port,
            control_plane_pid: std::process::id(),
            dae0_ifindex,
            dae_netns_id,
            dae0peer_mac,
            has_bpf_get_current_task: false,
            task_struct_mm_offset: 0,
            mm_struct_arg_start_offset: 0,
        },
        options.tproxy_port_protect,
    );
    param.udp_state_idle_timeout_ns = map_profile.profile.udp_state_idle_timeout_ns();
    let redirect_generation =
        redirect_runtime_generation(param.control_plane_pid, param.dae0_ifindex);
    let selected_param_object = PathBuf::from(NATIVE_PARAM_OBJECT_IDENTITY);
    NativeParamObjectPreparation {
        selected_param_object: selected_param_object.clone(),
        report: json!({
            "status": "pass",
            "path": path_string(&selected_param_object),
            "source_object": EMBEDDED_NATIVE_OBJECT_IDENTITY,
            "source_kind": "embedded",
            "command_param_object": path_string(command_param_object),
            "rewritten_param_matches": true,
            "previous_param_was_zero": Value::Null,
            "materialized_object": false,
            "param_delivery": "aya-set-global",
            "param_global_set": true,
            "map_profile": {
                "name": map_profile.profile.name(),
                "source": map_profile.source,
                "invalidValue": map_profile.invalid_value.as_deref(),
                "maxEntriesOverrides": map_profile.profile.max_entries_overrides(),
                "udpStateIdleTimeoutNs": param.udp_state_idle_timeout_ns.to_string(),
                "udpStateSaturationPolicy": "fail-closed",
                "redirectTrackAbiVersion": REDIRECT_TRACK_ABI_VERSION,
                "redirectTrackGeneration": redirect_generation.to_string(),
                "redirectTrackMigration": "fresh-unpinned-map-per-runtime",
            },
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
                "tproxy_port_protect": param.tproxy_port_protect != 0,
                "task_struct_mm_offset": param.task_struct_mm_offset,
                "mm_struct_arg_start_offset": param.mm_struct_arg_start_offset,
                "abi_version": param.abi_version,
                "udp_state_saturation_policy": param.udp_state_saturation_policy,
                "udp_state_idle_timeout_ns": param.udp_state_idle_timeout_ns.to_string(),
                "redirect_track_abi_version": REDIRECT_TRACK_ABI_VERSION,
                "redirect_track_generation": redirect_generation.to_string(),
            },
            "location": Value::Null,
        }),
        load_input: Some(NativeEbpfLoadInput { param, map_profile }),
    }
}

pub(crate) fn native_backend_runtime_decision_for_options(
    options: &ProductionRuntimeOwnerOptions,
) -> NativeBackendRuntimeDecision {
    let admission = native_backend_admission_report(
        if options.native_ebpf_completed_a3_admission {
            NativeBackendAdmissionEvidence::completed_a3_local()
        } else {
            NativeBackendAdmissionEvidence::report_only()
        },
        !options.native_ebpf_completed_a3_admission,
    );
    native_backend_runtime_decision(NativeBackendRuntimeRequest {
        native_backend_requested: options.native_ebpf_requested,
        requested_backend: options.native_ebpf_backend,
        admission_report: admission,
        native_loader_available: cfg!(feature = "native-ebpf"),
        tc_command_available: true,
    })
}

pub(crate) fn native_backend_runtime_decision_json(report: &NativeBackendRuntimeDecision) -> Value {
    json!({
        "schema": report.schema,
        "native_backend_requested": report.native_backend_requested,
        "requested_backend": report.requested_backend.as_str(),
        "admission_admitted": report.admission_admitted,
        "native_loader_available": report.native_loader_available,
        "attempt_native_backend": report.attempt_native_backend,
        "selected_backend": attach_backend_json(report.selected_backend),
        "native_backend_candidate": attach_backend_json(report.native_backend_candidate),
        "command_backend": attach_backend_json(report.command_backend),
        "command_backend_required": report.command_backend_required,
        "actual_command_backend_required": report.command_backend_required && !report.attempt_native_backend,
        "backend_switch_used": false,
        "native_attach_required": report.native_backend_requested,
        "native_attach_admitted": report.admission_admitted && report.native_loader_available,
        "native_attach_attempted": report.attempt_native_backend,
        "restore_available": report.command_backend.is_some(),
        "command_backend_available": report.command_backend_available,
        "automatic_enable_allowed": report.automatic_enable_allowed,
        "reason": report.reason.as_str(),
    })
}

pub(crate) fn attach_backend_json(backend: Option<AttachBackend>) -> Value {
    backend
        .map(|backend| json!(backend.as_str()))
        .unwrap_or(Value::Null)
}

pub(crate) fn actual_attach_backend(
    report: &Value,
    default_backend: AttachBackend,
) -> AttachBackend {
    match report.get("backend").and_then(Value::as_str) {
        Some("tcx") => AttachBackend::Tcx,
        Some("tc_netlink") => AttachBackend::TcNetlink,
        Some("tc_command") => AttachBackend::TcCommand,
        _ => default_backend,
    }
}

pub(crate) fn attach_backend_switch_used(report: &Value) -> bool {
    report
        .get("backend_switch_used")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn native_backend_for_role(
    _role: NativeEbpfAttachRole,
    requested_backend: AttachBackend,
) -> AttachBackend {
    requested_backend
}
