use super::*;
pub(super) fn ebpf_backend_capability_json(
    report: &EbpfBackendCapabilityReport,
    options: &ProductionRuntimeOwnerOptions,
) -> Value {
    let go_bpf_fallback_retired = options.native_ebpf_completed_a3_admission;
    let native_admission = native_backend_admission_report(
        if go_bpf_fallback_retired {
            NativeBackendAdmissionEvidence::completed_a3_local()
        } else {
            NativeBackendAdmissionEvidence::report_only()
        },
        !go_bpf_fallback_retired,
    );
    let native_opt_in = native_backend_runtime_decision(options);
    let kernel_program = kernel_program_feasibility_report();
    let kernel_program_evidence = KernelProgramParityEvidence::from_feasibility(&kernel_program);
    let kernel_program_parity = kernel_program_parity_admission_report(kernel_program_evidence);
    let tproxy_dataplane_admission = tproxy_dataplane_admission_report(kernel_program_evidence);
    let trace_core_sideload_gate = trace_core_sideload_gate_report();
    let trace_diagnostic_gate = trace_diagnostic_gate_report(&trace_core_sideload_gate);
    let fallback_retirement_gate = kernel_program_fallback_retirement_gate_report(
        &tproxy_dataplane_admission,
        &trace_diagnostic_gate,
        KernelProgramFallbackRetirementEvidence {
            explicit_user_approval: options.fallback_retirement_explicit_user_approval,
            product_chain_recertified: options.fallback_retirement_product_chain_recertified,
        },
    );
    json!({
        "schema": "ebpf-backend-capability-report",
        "report_only": report.report_only,
        "aya_userspace_available": report.aya_userspace_available,
        "tc_netlink_available": report.tc_netlink_available,
        "tcx_supported": report.tcx_supported,
        "tcx_available": report.tcx_available,
        "selected_backend": attach_backend_value(report.selected_backend),
        "command_fallback_used": report.command_fallback_used,
        "fallback_reason": report.fallback_reason,
        "kernel_version_source": "not-probed-report-only",
        "attach_backend": {
            "requested": report.attach_plan.requested.as_str(),
            "attempt_order": report
                .attach_plan
                .attempt_order
                .iter()
                .map(|backend| backend.as_str())
                .collect::<Vec<_>>(),
            "selected": attach_backend_value(report.attach_plan.selected),
            "effective_backend": "tc_command_fallback",
            "default_native_backend_enabled": false,
            "native_backend_admission_required": true,
            "tcx_optional": true,
            "tc_netlink_optional": true,
            "command_fallback_used": report.attach_plan.command_fallback_used,
            "command_fallback_required": true,
            "go_netlink_parity_fields_required": [
                "netns",
                "iface",
                "direction",
                "priority",
                "handle",
                "tcx_order",
                "tcx_query_revision",
                "tcx_program_order",
                "tcx_order_verified",
                "protocol",
                "direct_action",
                "program_name",
                "link_lifetime"
            ],
        },
        "cgroup_attach": {
            "report_only": false,
            "default_native_backend_enabled": true,
            "aya_cgroup_optional": false,
            "go_attachcgroup_fallback_required": false,
            "go_attachcgroup_fallback_retired": true,
            "fallback_retirement_scope": "control-plane-cgroup-only",
            "cgroup2_mount_source": "/proc/mounts first cgroup2",
            "programs": dae_cgroup_attach_matrix()
                .iter()
                .map(|line| json!({
                    "role": format!("{:?}", line.role),
                    "section": line.section,
                    "program_name": line.program_name,
                    "go_attach_type": line.go_attach_type,
                    "aya_program_kind": line.aya_program_kind.as_str(),
                    "attach_mode": line.attach_mode,
                    "link_lifetime_owned_by_backend": line.link_lifetime_owned_by_backend,
                }))
                .collect::<Vec<_>>(),
        },
        "native_backend_admission": native_backend_admission_json(&native_admission),
        "native_backend_opt_in": native_backend_opt_in_decision_json(&native_opt_in),
        "kernel_program_feasibility": {
            "schema": kernel_program.schema,
            "tproxy_classifier_total": kernel_program.tproxy_classifier_total,
            "rust_tproxy_classifier_covered": kernel_program.rust_tproxy_classifier_covered,
            "tproxy_cgroup_total": kernel_program.tproxy_cgroup_total,
            "rust_tproxy_cgroup_covered": kernel_program.rust_tproxy_cgroup_covered,
            "trace_kprobe_total": kernel_program.trace_kprobe_total,
            "rust_trace_kprobe_covered": kernel_program.rust_trace_kprobe_covered,
            "rust_tproxy_runtime_admitted": kernel_program.rust_tproxy_runtime_admitted,
            "trace_rust_native_admitted": kernel_program.trace_rust_native_admitted,
            "default_switch_allowed": kernel_program.default_switch_allowed,
            "formal_kernel_program_parity_stage_required": kernel_program.formal_kernel_program_parity_stage_required,
            "c_tproxy_object_fallback_required": kernel_program.c_tproxy_object_fallback_required,
            "c_trace_object_fallback_required": kernel_program.c_trace_object_fallback_required,
            "tc_command_fallback_required": kernel_program.tc_command_fallback_required,
            "go_userspace_control_plane_authoritative": kernel_program.go_userspace_control_plane_authoritative,
            "go_bpf_loader_restored_by_this_stage": kernel_program.go_bpf_loader_restored_by_this_stage,
            "go_bpf_fallback_deletion_allowed_by_this_stage": kernel_program.go_bpf_fallback_deletion_allowed_by_this_stage,
            "param_model": kernel_program.param_model,
            "tproxy_coverage": kernel_program.tproxy_coverage
                .iter()
                .map(|line| json!({
                    "surface": line.surface.as_str(),
                    "c_section": line.c_section,
                    "rust_section": line.rust_section,
                    "program_name": line.program_name,
                    "status": line.status.as_str(),
                }))
                .collect::<Vec<_>>(),
            "trace_coverage": kernel_program.trace_coverage
                .iter()
                .map(|line| json!({
                    "surface": line.surface.as_str(),
                    "c_section": line.c_section,
                    "rust_section": line.rust_section,
                    "program_name": line.program_name,
                    "status": line.status.as_str(),
                }))
                .collect::<Vec<_>>(),
        },
        "kernel_program_parity_admission": kernel_program_parity_admission_json(&kernel_program_parity),
        "tproxy_dataplane_admission": tproxy_dataplane_admission_json(&tproxy_dataplane_admission),
        "trace_diagnostic_gate": trace_diagnostic_gate_json(&trace_diagnostic_gate),
        "kernel_program_fallback_retirement_gate": kernel_program_fallback_retirement_gate_json(&fallback_retirement_gate),
        "trace_core_sideload_gate": {
            "schema": trace_core_sideload_gate.schema,
            "enabled": trace_core_sideload_gate.enabled,
            "go_trace_adoption_ready": trace_core_sideload_gate.go_trace_adoption_ready,
            "default_daemon_path": trace_core_sideload_gate.default_daemon_path,
            "rust_skb_core_read_semantics_required": trace_core_sideload_gate.rust_skb_core_read_semantics_required,
            "rust_core_relocation_required": trace_core_sideload_gate.rust_core_relocation_required,
            "c_trace_object_required": trace_core_sideload_gate.c_trace_object_required,
            "go_trace_fallback_required": trace_core_sideload_gate.go_trace_fallback_required,
            "disabled_reason": trace_core_sideload_gate.disabled_reason,
            "restore_gate": trace_core_sideload_gate.restore_gate,
        },
        "loader": {
            "default_object_loader": loader_backend_str(report.loader_contract.default_object_loader),
            "runtime_map_backend": loader_backend_str(report.loader_contract.runtime_map_backend),
            "aya_userspace_loader_planned": report.loader_contract.aya_userspace_loader_planned,
            "c_ebpf_object_fallback_required": report.loader_contract.c_ebpf_object_fallback_required,
            "go_fallback_preserved": report.loader_contract.go_fallback_preserved,
            "go_bpf_loader_fallback_retired": report.loader_contract.go_bpf_loader_fallback_retired,
            "param_rewrite_required_before_attach": report.loader_contract.param_rewrite_required_before_attach,
        },
        "scope": if options.execute && options.native_ebpf_opt_in {
            "runtime opt-in capability wiring; native attach attempts are recorded in executed_steps; default path remains unchanged"
        } else {
            "report-only capability wiring; no object load, no attach, no tproxy.c change"
        },
    })
}
