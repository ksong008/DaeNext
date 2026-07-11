use super::*;
#[test]
pub(super) fn bpf_abi_layout_matches_golden_fixture() {
    let fixture = load("ebpf/abi/layout.json");
    assert_eq!(
        TASK_COMM_LEN,
        fixture["task_comm_len"].as_u64().unwrap() as usize
    );
    assert_eq!(
        MAX_MATCH_SET_LEN,
        fixture["max_match_set_len"]["value"].as_u64().unwrap() as usize
    );
    assert_eq!(TPROXY_MARK, fixture["tproxy_mark"].as_u64().unwrap() as u32);
    assert_eq!(
        REDIRECT_TRACK_ABI_VERSION,
        fixture["redirect_track_abi_version"].as_u64().unwrap() as u8
    );

    assert_layout::<BpfDaeParam>(&fixture, "bpfDaeParam", 48, 8);
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "tproxy_port",
        offset_of!(BpfDaeParam, tproxy_port),
    );
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "dae0peer_mac",
        offset_of!(BpfDaeParam, dae0peer_mac),
    );
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "has_bpf_get_current_task",
        offset_of!(BpfDaeParam, has_bpf_get_current_task),
    );
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "task_struct_mm_offset",
        offset_of!(BpfDaeParam, task_struct_mm_offset),
    );
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "mm_struct_arg_start_offset",
        offset_of!(BpfDaeParam, mm_struct_arg_start_offset),
    );
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "abi_version",
        offset_of!(BpfDaeParam, abi_version),
    );
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "udp_state_saturation_policy",
        offset_of!(BpfDaeParam, udp_state_saturation_policy),
    );
    assert_offset(
        &fixture,
        "bpfDaeParam",
        "udp_state_idle_timeout_ns",
        offset_of!(BpfDaeParam, udp_state_idle_timeout_ns),
    );

    assert_layout::<BpfDomainRouting>(&fixture, "bpfDomainRouting", 128, 4);
    assert_layout::<BpfMatchSet>(&fixture, "bpfMatchSet", 24, 4);
    assert_offset(
        &fixture,
        "bpfMatchSet",
        "mark",
        offset_of!(BpfMatchSet, mark),
    );
    assert_layout::<BpfOutboundConnectivityQuery>(&fixture, "bpfOutboundConnectivityQuery", 3, 1);
    assert_layout::<BpfPidPname>(&fixture, "bpfPidPname", 36, 4);
    assert_layout::<BpfRedirectEntry>(&fixture, "bpfRedirectEntry", 20, 4);
    assert_offset(
        &fixture,
        "bpfRedirectEntry",
        "link_layer",
        offset_of!(BpfRedirectEntry, link_layer),
    );
    assert_offset(
        &fixture,
        "bpfRedirectEntry",
        "abi_version",
        offset_of!(BpfRedirectEntry, abi_version),
    );
    assert_layout::<BpfRedirectKey>(&fixture, "bpfRedirectKey", 48, 8);
    assert_offset(
        &fixture,
        "bpfRedirectKey",
        "sport",
        offset_of!(BpfRedirectKey, sport),
    );
    assert_offset(
        &fixture,
        "bpfRedirectKey",
        "l4proto",
        offset_of!(BpfRedirectKey, l4proto),
    );
    assert_offset(
        &fixture,
        "bpfRedirectKey",
        "generation",
        offset_of!(BpfRedirectKey, generation),
    );
    assert_layout::<BpfRoutingResult>(&fixture, "bpfRoutingResult", 36, 4);
    assert_offset(
        &fixture,
        "bpfRoutingResult",
        "outbound",
        offset_of!(BpfRoutingResult, outbound),
    );
    assert_layout::<BpfTuplesKey>(&fixture, "bpfTuplesKey", 40, 2);
    assert_layout::<BpfUdpConnState>(&fixture, "bpfUdpConnState", 24, 8);
    assert_layout::<BpfUdpStateMetrics>(&fixture, "bpfUdpStateMetrics", 56, 8);
}

#[cfg(feature = "aya-loader")]
#[test]
pub(super) fn aya_trace_config_layout_matches_ebpf_tracing_config() {
    assert_eq!(size_of::<AyaTraceConfig>(), 6);
    assert_eq!(align_of::<AyaTraceConfig>(), 2);
    assert_eq!(offset_of!(AyaTraceConfig, port), 0);
    assert_eq!(offset_of!(AyaTraceConfig, l4_proto), 2);
    assert_eq!(offset_of!(AyaTraceConfig, ip_version), 4);
    assert_eq!(offset_of!(AyaTraceConfig, pad), 5);
}

#[test]
pub(super) fn map_catalog_matches_golden_fixture() {
    let fixture = load("ebpf/maps/catalog.json");
    let maps = fixture["maps"].as_array().unwrap();
    assert_eq!(map_catalog().len(), maps.len());
    for (got, expected) in map_catalog().iter().zip(maps) {
        assert_eq!(got.name, expected["name"].as_str().unwrap());
        assert_eq!(got.map_type, expected["type"].as_str().unwrap());
        assert_eq!(got.key_size, expected["key_size"].as_u64().unwrap() as u32);
        assert_eq!(
            got.value_size,
            expected["value_size"].as_u64().unwrap() as u32
        );
        assert_eq!(
            got.max_entries,
            expected["max_entries"].as_u64().unwrap() as u32
        );
        assert_eq!(got.flags, expected["flags"].as_u64().unwrap() as u32);
        assert_eq!(got.pinning, expected["pinning"].as_str().unwrap());
    }
    let pinned = fixture["pinned_reuse"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(pinned_reuse_maps(), pinned.as_slice());
    assert_eq!(
        pinned_map_action("use pinned map routing_tuples_map: field mismatch"),
        PinnedMapAction::DeleteAndRetry {
            map_name: "routing_tuples_map".to_owned()
        }
    );
    assert_eq!(
        pinned_map_action("other loader error"),
        PinnedMapAction::ReturnError
    );
}

#[test]
pub(super) fn runtime_map_profiles_are_ordered_and_cover_only_catalogued_maps() {
    assert_eq!(RuntimeMapProfile::default(), RuntimeMapProfile::Balanced);
    assert_eq!(
        RuntimeMapProfile::parse("low_memory"),
        Some(RuntimeMapProfile::LowMemory)
    );
    assert_eq!(
        RuntimeMapProfile::parse("standard"),
        Some(RuntimeMapProfile::Balanced)
    );
    assert_eq!(
        RuntimeMapProfile::parse("high-performance"),
        Some(RuntimeMapProfile::HighPerformance)
    );
    assert_eq!(RuntimeMapProfile::parse("invalid"), None);

    let low = RuntimeMapProfile::LowMemory.max_entries_overrides();
    let balanced = RuntimeMapProfile::Balanced.max_entries_overrides();
    let high = RuntimeMapProfile::HighPerformance.max_entries_overrides();
    assert_eq!(low.len(), balanced.len());
    assert_eq!(balanced.len(), high.len());
    for (name, low_capacity) in low {
        let balanced_capacity = profile_capacity(balanced, name);
        let high_capacity = profile_capacity(high, name);
        let catalog_capacity = map_catalog()
            .iter()
            .find(|spec| spec.name == *name)
            .map(|spec| spec.max_entries)
            .unwrap_or_else(|| panic!("profile map {name} is absent from the map catalog"));
        assert!(0 < *low_capacity && *low_capacity <= balanced_capacity);
        assert!(balanced_capacity <= high_capacity);
        assert_eq!(high_capacity, catalog_capacity);
    }
    assert!(
        RuntimeMapProfile::LowMemory.udp_state_idle_timeout_ns()
            < RuntimeMapProfile::Balanced.udp_state_idle_timeout_ns()
    );
    assert!(
        RuntimeMapProfile::Balanced.udp_state_idle_timeout_ns()
            < RuntimeMapProfile::HighPerformance.udp_state_idle_timeout_ns()
    );
    assert_eq!(
        RuntimeMapProfile::HighPerformance.udp_state_idle_timeout_ns(),
        UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT
    );
    assert!(!map_catalog().iter().any(|spec| spec.name == "fast_sock"));
    assert!(
        !map_catalog()
            .iter()
            .any(|spec| spec.name == "tgid_pname_map")
    );
}

fn profile_capacity(profile: &[(&str, u32)], name: &str) -> u32 {
    profile
        .iter()
        .find_map(|(candidate, capacity)| (*candidate == name).then_some(*capacity))
        .unwrap_or_else(|| panic!("map profile is missing {name}"))
}

#[test]
pub(super) fn ebpf_runtime_contracts_keep_abi_maps_and_loader_boundaries_explicit() {
    let abi = bpf_abi_contract();
    assert_eq!(abi.dae_param_size, size_of::<BpfDaeParam>());
    assert_eq!(abi.dae_param_abi_version, BPF_DAE_PARAM_ABI_VERSION);
    assert_eq!(abi.redirect_track_abi_version, REDIRECT_TRACK_ABI_VERSION);
    assert_eq!(abi.task_comm_len, TASK_COMM_LEN);
    assert_eq!(abi.max_match_set_len, MAX_MATCH_SET_LEN);
    assert_eq!(abi.tproxy_mark, TPROXY_MARK);

    let loader = loader_contract();
    assert_eq!(loader.primary_object_loader, LoaderBackend::AyaUserspace);
    assert_eq!(loader.runtime_map_backend, LoaderBackend::RustSyscallMaps);
    assert!(!loader.aya_userspace_loader_planned);
    assert!(!loader.external_ebpf_object_required);
    assert!(!loader.external_loader_dependency_present);
    assert!(loader.native_bpf_loader_product_ready);
    assert!(loader.param_rewrite_required_before_attach);

    let maps = runtime_map_contract();
    assert_eq!(maps.len(), map_catalog().len());
    let listen = maps
        .iter()
        .find(|entry| entry.spec.name == "listen_socket_map")
        .unwrap();
    assert_eq!(listen.role, RuntimeMapRole::SocketHandoff);
    assert!(!listen.reusable_pin);

    for name in pinned_reuse_maps() {
        let entry = maps.iter().find(|entry| entry.spec.name == *name).unwrap();
        assert_eq!(entry.role, RuntimeMapRole::PinnedReuse);
        assert!(entry.reusable_pin);
        assert!(entry.spec.pinned_by_name());
    }
    let lpm_array = maps
        .iter()
        .find(|entry| entry.spec.name == "lpm_array_map")
        .unwrap();
    assert_eq!(lpm_array.role, RuntimeMapRole::InnerMapCatalog);
    assert!(!lpm_array.reusable_pin);
    assert!(lpm_array.spec.pinned_by_name());
    let redirect_track = maps
        .iter()
        .find(|entry| entry.spec.name == "redirect_track")
        .unwrap();
    assert_eq!(redirect_track.role, RuntimeMapRole::Tracking);
    assert!(!redirect_track.reusable_pin);
    assert!(!redirect_track.spec.pinned_by_name());
    assert_eq!(
        redirect_track.spec.key_size,
        size_of::<BpfRedirectKey>() as u32
    );
    assert_eq!(MAP_USAGE_WARNING_RATIO, 0.70);
    assert_eq!(MAP_USAGE_PRESSURE_RATIO, 0.90);
}

#[test]
pub(super) fn redirect_generation_changes_with_process_or_runtime_interface_identity() {
    let baseline = redirect_runtime_generation(11, 22);
    assert_ne!(baseline, redirect_runtime_generation(12, 22));
    assert_ne!(baseline, redirect_runtime_generation(11, 23));
    assert_eq!(baseline, (11_u64 << 32) | 22);
}

#[test]
pub(super) fn attach_backend_plan_keeps_command_backend_until_native_attach_is_available() {
    let command_plan = plan_attach_backend(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability::tc_command_only(),
    );
    assert!(command_plan.tcx_supported);
    assert_eq!(
        command_plan.attempt_order,
        vec![
            AttachBackend::Tcx,
            AttachBackend::TcNetlink,
            AttachBackend::TcCommand,
        ]
    );
    assert_eq!(command_plan.selected, Some(AttachBackend::TcCommand));
    assert!(command_plan.command_backend_used);

    let native_tcx = plan_attach_backend(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability {
            tcx: true,
            tc_netlink: true,
            tc_command: true,
        },
    );
    assert_eq!(native_tcx.selected, Some(AttachBackend::Tcx));
    assert!(!native_tcx.command_backend_used);
}

#[test]
pub(super) fn report_only_backend_capability_uses_command_backend() {
    let report = report_only_ebpf_backend_capability(Some(Version::new(6, 6, 0)));
    assert!(report.report_only);
    assert_eq!(report.aya_userspace_available, cfg!(feature = "aya-loader"));
    assert!(!report.tc_netlink_available);
    assert!(report.tcx_supported);
    assert!(!report.tcx_available);
    assert_eq!(report.selected_backend, Some(AttachBackend::TcCommand));
    assert!(report.command_backend_used);
    assert_eq!(report.backend_reason, Some("native_backends_report_only"));
    assert_eq!(
        report.attach_plan.attempt_order,
        vec![
            AttachBackend::Tcx,
            AttachBackend::TcNetlink,
            AttachBackend::TcCommand,
        ]
    );
    assert_eq!(
        report.loader_contract.primary_object_loader.as_str(),
        "aya_userspace"
    );
    assert_eq!(
        report.loader_contract.runtime_map_backend.as_str(),
        "rust_syscall_maps"
    );
    assert_eq!(AttachBackend::Tcx.as_str(), "tcx");
}
