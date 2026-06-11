use super::*;

pub(super) fn ebpf_backend_capability_json(
    report: &EbpfBackendCapabilityReport,
    options: &ProductionRuntimeOwnerOptions,
) -> Value {
    let native_admission = native_backend_admission_report(
        if options.native_ebpf_completed_a3_admission {
            NativeBackendAdmissionEvidence::completed_a3_local()
        } else {
            NativeBackendAdmissionEvidence::report_only()
        },
        !options.native_ebpf_completed_a3_admission,
    );
    let native_runtime_decision = native_backend_runtime_decision_for_options(options);

    json!({
        "schema": "ebpf-backend-capability-report",
        "report_only": report.report_only,
        "aya_userspace_available": report.aya_userspace_available,
        "tc_netlink_available": report.tc_netlink_available,
        "tcx_supported": report.tcx_supported,
        "tcx_available": report.tcx_available,
        "selected_backend": attach_backend_value(report.selected_backend),
        "command_backend_used": report.command_backend_used,
        "backend_reason": report.backend_reason,
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
            "effective_backend": "tc_command",
            "native_backend_requested": options.native_ebpf_requested,
            "native_backend_admission_required": true,
            "tcx_optional": true,
            "tc_netlink_optional": true,
            "command_backend_used": report.attach_plan.command_backend_used,
            "command_backend_required": report.attach_plan.command_backend_used,
            "netlink_contract_fields": [
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
            "native_cgroup_backend_enabled": true,
            "aya_cgroup_required": true,
            "cgroup2_mount_source": "/proc/mounts first cgroup2",
            "programs": dae_cgroup_attach_matrix()
                .iter()
                .map(|line| json!({
                    "role": format!("{:?}", line.role),
                    "section": line.section,
                    "program_name": line.program_name,
                    "attach_type": line.attach_type,
                    "aya_program_kind": line.aya_program_kind.as_str(),
                    "attach_mode": line.attach_mode,
                    "link_lifetime_owned_by_backend": line.link_lifetime_owned_by_backend,
                }))
                .collect::<Vec<_>>(),
        },
        "native_backend_admission": native_backend_admission_json(&native_admission),
        "native_backend_runtime": native_backend_runtime_decision_json(&native_runtime_decision),
        "loader": {
            "primary_object_loader": loader_backend_str(report.loader_contract.primary_object_loader),
            "runtime_map_backend": loader_backend_str(report.loader_contract.runtime_map_backend),
            "aya_userspace_loader_planned": report.loader_contract.aya_userspace_loader_planned,
            "native_object_required": !report.loader_contract.aya_userspace_loader_planned,
            "command_backend_available": true,
            "param_rewrite_required_before_attach": report.loader_contract.param_rewrite_required_before_attach,
        },
        "scope": if options.execute && options.native_ebpf_requested {
            "runtime native eBPF capability wiring; attach attempts are recorded in executed_steps"
        } else {
            "report-only capability wiring; no object load and no attach"
        },
    })
}
