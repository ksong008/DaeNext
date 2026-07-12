use super::*;

const PRODUCTION_NAMES_FREE_CHECK: &str = "production-names-free";

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
            "native_ebpf_requested": options.native_ebpf_requested,
            "native_embedded_object": options.native_ebpf_embedded_object,
        }),
        "production runtime owner source eBPF object is missing",
    );
    push_check(
        &mut checks,
        "native-ebpf-runtime-request-contract",
        true,
        json!({
            "native_backend_requested": options.native_ebpf_requested,
            "requested_backend": options.native_ebpf_backend.as_str(),
            "completed_a3_admission": options.native_ebpf_completed_a3_admission,
            "embedded_object": options.native_ebpf_embedded_object,
            "native_loader_compiled": cfg!(feature = "native-ebpf"),
            "automatic_enable_allowed": false,
            "tc_command_backend_required": true,
            "native_bpf_external_path_absent": true,
            "topology_link_mode": {
                "env": netns_link_env_name(),
                "requested": options.netns_link_mode.as_str(),
                "auto_policy": "netkit_l2_scrub_none_then_compat_netkit_l2_then_veth",
                "tcx_is_attach_backend_only": true,
            },
        }),
        "native eBPF runtime request contract is invalid",
    );
    push_production_names_check(&mut checks, options);
    push_check(
        &mut checks,
        "tproxy-port-free",
        !options.execute || tproxy_port_available(options.tproxy_port),
        json!({"tproxy_port": options.tproxy_port}),
        "production runtime owner tproxy port is already in use",
    );
    checks
}

pub(crate) fn preflight_blockers(checks: &[Value], include_production_names: bool) -> Vec<String> {
    checks
        .iter()
        .filter(|check| check["status"].as_str() != Some("pass"))
        .filter(|check| {
            include_production_names || check["name"].as_str() != Some(PRODUCTION_NAMES_FREE_CHECK)
        })
        .filter_map(|check| check["blocker"].as_str().map(str::to_owned))
        .collect()
}

pub(crate) fn production_names_check_failed(checks: &[Value]) -> bool {
    checks.iter().any(|check| {
        check["name"].as_str() == Some(PRODUCTION_NAMES_FREE_CHECK)
            && check["status"].as_str() != Some("pass")
    })
}

pub(crate) fn refresh_production_names_check(
    checks: &mut Vec<Value>,
    options: &ProductionRuntimeOwnerOptions,
) {
    checks.retain(|check| check["name"].as_str() != Some(PRODUCTION_NAMES_FREE_CHECK));
    push_production_names_check(checks, options);
}

fn push_production_names_check(checks: &mut Vec<Value>, options: &ProductionRuntimeOwnerOptions) {
    push_check(
        checks,
        PRODUCTION_NAMES_FREE_CHECK,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_name_blocker_can_be_deferred_without_hiding_other_failures() {
        let checks = vec![
            json!({
                "name": PRODUCTION_NAMES_FREE_CHECK,
                "status": "fail",
                "blocker": "names are in use",
            }),
            json!({
                "name": "resident-cgroup-preflight",
                "status": "fail",
                "blocker": "cgroup conflict",
            }),
        ];

        assert!(production_names_check_failed(&checks));
        assert_eq!(
            preflight_blockers(&checks, false),
            ["cgroup conflict".to_owned()]
        );
        assert_eq!(
            preflight_blockers(&checks, true),
            ["names are in use".to_owned(), "cgroup conflict".to_owned()]
        );
    }
}
