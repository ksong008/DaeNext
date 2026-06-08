use super::*;
pub(crate) fn prepare_native_param_object(
    options: &ProductionRuntimeOwnerOptions,
    fallback_param_object: &Path,
    native_param_object: &Path,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
    dae_netns_id: u32,
) -> (PathBuf, Value) {
    if !options.native_ebpf_opt_in {
        return (
            fallback_param_object.to_path_buf(),
            json!({
                "status": "skipped",
                "reason": "native eBPF opt-in is disabled",
                "selected_param_object": path_string(fallback_param_object),
                "fallback_param_object": path_string(fallback_param_object),
            }),
        );
    }
    let Some(native_object) = options.native_ebpf_object.as_ref() else {
        return (
            fallback_param_object.to_path_buf(),
            json!({
                "status": "skipped",
                "reason": "native eBPF object is not configured; native attach may fail closed before tc command fallback",
                "selected_param_object": path_string(fallback_param_object),
                "fallback_param_object": path_string(fallback_param_object),
            }),
        );
    };
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: true,
    });
    match write_param_aware_object(native_object, native_param_object, param) {
        Ok(report) => (
            native_param_object.to_path_buf(),
            json!({
                "status": "pass",
                "path": path_string(native_param_object),
                "source_object": path_string(native_object),
                "fallback_param_object": path_string(fallback_param_object),
                "rewritten_param_matches": report.rewritten_param_matches,
                "previous_param_was_zero": report.previous_param_was_zero,
                "source_len": report.source_len,
                "output_len": report.output_len,
                "param": {
                    "tproxy_port": param.tproxy_port,
                    "control_plane_pid": param.control_plane_pid,
                    "dae0_ifindex": param.dae0_ifindex,
                    "dae_netns_id": param.dae_netns_id,
                    "dae0peer_mac": mac_string(param.dae0peer_mac),
                    "has_bpf_get_current_task": param.has_bpf_get_current_task,
                },
                "location": {
                    "symbol": report.location.symbol,
                    "section": report.location.section,
                    "symbol_size": report.location.symbol_size,
                    "file_offset": report.location.file_offset,
                },
            }),
        ),
        Err(err) => (
            native_param_object.to_path_buf(),
            json!({
                "status": "fail",
                "path": path_string(native_param_object),
                "source_object": path_string(native_object),
                "fallback_param_object": path_string(fallback_param_object),
                "error": err.to_string(),
            }),
        ),
    }
}

pub(crate) fn native_backend_runtime_decision(
    options: &ProductionRuntimeOwnerOptions,
) -> NativeBackendOptInDecision {
    let admission = native_backend_admission_report(
        if options.native_ebpf_completed_a3_admission {
            NativeBackendAdmissionEvidence::completed_a3_local()
        } else {
            NativeBackendAdmissionEvidence::report_only()
        },
        !options.native_ebpf_completed_a3_admission,
    );
    native_backend_opt_in_decision(NativeBackendOptInRequest {
        opt_in_enabled: options.native_ebpf_opt_in,
        requested_backend: options.native_ebpf_backend,
        admission_report: admission,
        native_loader_available: cfg!(feature = "native-ebpf"),
        tc_command_fallback_available: true,
    })
}

pub(crate) fn native_backend_opt_in_decision_json(report: &NativeBackendOptInDecision) -> Value {
    json!({
        "schema": report.schema,
        "opt_in_enabled": report.opt_in_enabled,
        "requested_backend": report.requested_backend.as_str(),
        "admission_admitted": report.admission_admitted,
        "native_loader_available": report.native_loader_available,
        "attempt_native_backend": report.attempt_native_backend,
        "selected_backend": attach_backend_json(report.selected_backend),
        "native_backend_candidate": attach_backend_json(report.native_backend_candidate),
        "fallback_backend": attach_backend_json(report.fallback_backend),
        "fallback_required": report.fallback_required,
        "fallback_preserved": report.fallback_preserved,
        "default_enable_allowed": report.default_enable_allowed,
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
        Some("tc_command_fallback") => AttachBackend::TcCommandFallback,
        _ => default_backend,
    }
}

pub(crate) fn attach_fallback_used(report: &Value) -> bool {
    report
        .get("fallback_used")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn native_backend_for_role(
    _role: NativeEbpfAttachRole,
    requested_backend: AttachBackend,
) -> AttachBackend {
    requested_backend
}
