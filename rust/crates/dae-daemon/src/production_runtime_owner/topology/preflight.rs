use super::*;
pub(crate) fn preflight_checks(options: &ProductionRuntimeOwnerOptions) -> Vec<Value> {
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !options.execute || options.ack_root_gate,
        json!({"execute": options.execute, "ack_root_gate": options.ack_root_gate}),
        "production runtime owner root-gated smoke requires --ack-root-gate",
    );
    for tool in ["ip", "tc"] {
        push_check(
            &mut checks,
            match tool {
                "ip" => "tool-ip-available",
                _ => "tool-tc-available",
            },
            command_exists(tool),
            json!({"tool": tool}),
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        !options.execute || options.native_ebpf_embedded_object || options.source_object.exists(),
        json!({
            "path": path_string(&options.source_object),
            "native_ebpf_opt_in": options.native_ebpf_opt_in,
            "native_embedded_object": options.native_ebpf_embedded_object,
        }),
        "production runtime owner source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "native-ebpf-runtime-opt-in-contract",
        true,
        json!({
            "opt_in": options.native_ebpf_opt_in,
            "requested_backend": options.native_ebpf_backend.as_str(),
            "completed_a3_admission": options.native_ebpf_completed_a3_admission,
            "embedded_object": options.native_ebpf_embedded_object,
            "native_loader_compiled": cfg!(feature = "native-ebpf"),
            "default_enable_allowed": false,
            "tc_command_fallback_required": true,
            "go_bpf_fallback_retired": options.native_ebpf_completed_a3_admission,
            "topology_link_mode": {
                "env": netns_link_env_name(),
                "requested": options.netns_link_mode.as_str(),
                "auto_policy": "netkit_l2_scrub_none_then_legacy_netkit_l2_then_veth",
                "tcx_is_attach_backend_only": true,
            },
        }),
        "native eBPF runtime opt-in contract is invalid",
    );
    push_check(
        &mut checks,
        "native-ebpf-object-present",
        !options.execute
            || !options.native_ebpf_opt_in
            || options
                .native_ebpf_object
                .as_ref()
                .is_none_or(|path| path.is_file()),
        json!({
            "opt_in": options.native_ebpf_opt_in,
            "path": options.native_ebpf_object.as_ref().map(|path| path_string(path)),
            "embedded_object": options.native_ebpf_embedded_object,
            "fallback_object": path_string(&options.source_object),
            "required_when_configured": true,
        }),
        "configured native eBPF object is missing",
    );
    push_check(
        &mut checks,
        "production-names-free",
        !options.execute
            || (!iface_exists(PRODUCTION_HOST_IFACE)
                && !iface_exists(PRODUCTION_PEER_IFACE)
                && !netns_exists(PRODUCTION_NETNS)),
        json!({
            "host_iface": PRODUCTION_HOST_IFACE,
            "peer_iface": PRODUCTION_PEER_IFACE,
            "netns": PRODUCTION_NETNS,
        }),
        "production runtime owner names are already in use",
    );
    push_check(
        &mut checks,
        "tproxy-port-free",
        !options.execute || tproxy_port_available(options.tproxy_port),
        json!({"tproxy_port": options.tproxy_port}),
        "production runtime owner tproxy port is already in use",
    );
    checks
}
