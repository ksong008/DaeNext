use super::*;
pub(crate) fn prepare_native_param_object(
    options: &ProductionRuntimeOwnerOptions,
    fallback_param_object: &Path,
    dae0_ifindex: u32,
    dae0peer_mac: [u8; 6],
    dae_netns_id: u32,
) -> NativeParamObjectPreparation {
    if !options.native_ebpf_opt_in {
        return NativeParamObjectPreparation {
            selected_param_object: fallback_param_object.to_path_buf(),
            report: json!({
                "status": "skipped",
                "reason": "native eBPF opt-in is disabled",
                "selected_param_object": path_string(fallback_param_object),
                "fallback_param_object": path_string(fallback_param_object),
            }),
            load_input: None,
        };
    }
    let Some(source) = native_object_source(options) else {
        return NativeParamObjectPreparation {
            selected_param_object: fallback_param_object.to_path_buf(),
            report: json!({
                "status": "skipped",
                "reason": "native eBPF object is not configured; native attach may fail closed before tc command fallback",
                "selected_param_object": path_string(fallback_param_object),
                "fallback_param_object": path_string(fallback_param_object),
            }),
            load_input: None,
        };
    };
    let param = build_dae_param(DaeParamInput {
        tproxy_port: options.tproxy_port,
        control_plane_pid: std::process::id(),
        dae0_ifindex,
        dae_netns_id,
        dae0peer_mac,
        has_bpf_get_current_task: true,
    });
    let selected_param_object = PathBuf::from(NATIVE_PARAM_OBJECT_IDENTITY);
    let source_identity = source.identity();
    NativeParamObjectPreparation {
        selected_param_object: selected_param_object.clone(),
        report: json!({
            "status": "pass",
            "path": path_string(&selected_param_object),
            "source_object": path_string(&source_identity),
            "source_kind": source.kind(),
            "fallback_param_object": path_string(fallback_param_object),
            "rewritten_param_matches": true,
            "previous_param_was_zero": Value::Null,
            "materialized_object": false,
            "param_delivery": "aya-set-global",
            "param_global_set": true,
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
            },
            "location": Value::Null,
        }),
        load_input: Some(NativeEbpfLoadInput { source, param }),
    }
}

fn native_object_source(options: &ProductionRuntimeOwnerOptions) -> Option<NativeEbpfObjectSource> {
    if options.native_ebpf_embedded_object {
        return Some(NativeEbpfObjectSource::Embedded);
    }
    options
        .native_ebpf_object
        .as_ref()
        .map(|path| NativeEbpfObjectSource::File(path.clone()))
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
        "fallback_required_legacy": true,
        "actual_fallback_required": report.fallback_required && !report.attempt_native_backend,
        "fallback_used": false,
        "native_attach_required": report.opt_in_enabled,
        "native_attach_admitted": report.admission_admitted && report.native_loader_available,
        "native_attach_attempted": report.attempt_native_backend,
        "rollback_available": report.fallback_backend.is_some(),
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
