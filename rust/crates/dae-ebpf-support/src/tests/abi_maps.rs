#[test]
fn bpf_abi_layout_matches_golden_fixture() {
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

    assert_layout::<BpfDaeParam>(&fixture, "bpfDaeParam", 24, 4);
    assert_offset::<BpfDaeParam>(
        &fixture,
        "bpfDaeParam",
        "tproxy_port",
        offset_of!(BpfDaeParam, tproxy_port),
    );
    assert_offset::<BpfDaeParam>(
        &fixture,
        "bpfDaeParam",
        "dae0peer_mac",
        offset_of!(BpfDaeParam, dae0peer_mac),
    );
    assert_offset::<BpfDaeParam>(
        &fixture,
        "bpfDaeParam",
        "has_bpf_get_current_task",
        offset_of!(BpfDaeParam, has_bpf_get_current_task),
    );

    assert_layout::<BpfDomainRouting>(&fixture, "bpfDomainRouting", 128, 4);
    assert_layout::<BpfMatchSet>(&fixture, "bpfMatchSet", 24, 4);
    assert_offset::<BpfMatchSet>(
        &fixture,
        "bpfMatchSet",
        "mark",
        offset_of!(BpfMatchSet, mark),
    );
    assert_layout::<BpfOutboundConnectivityQuery>(&fixture, "bpfOutboundConnectivityQuery", 3, 1);
    assert_layout::<BpfPidPname>(&fixture, "bpfPidPname", 20, 4);
    assert_layout::<BpfRedirectEntry>(&fixture, "bpfRedirectEntry", 20, 4);
    assert_layout::<BpfRedirectTuple>(&fixture, "bpfRedirectTuple", 32, 1);
    assert_layout::<BpfRoutingResult>(&fixture, "bpfRoutingResult", 36, 4);
    assert_offset::<BpfRoutingResult>(
        &fixture,
        "bpfRoutingResult",
        "outbound",
        offset_of!(BpfRoutingResult, outbound),
    );
    assert_layout::<BpfTuplesKey>(&fixture, "bpfTuplesKey", 40, 2);
    assert_layout::<BpfUdpConnState>(&fixture, "bpfUdpConnState", 24, 8);
}

#[test]
fn map_catalog_matches_golden_fixture() {
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
fn ebpf_runtime_contracts_keep_abi_maps_and_loader_boundaries_explicit() {
    let abi = bpf_abi_contract();
    assert_eq!(abi.dae_param_size, size_of::<BpfDaeParam>());
    assert_eq!(abi.task_comm_len, TASK_COMM_LEN);
    assert_eq!(abi.max_match_set_len, MAX_MATCH_SET_LEN);
    assert_eq!(abi.tproxy_mark, TPROXY_MARK);

    let loader = loader_contract();
    assert_eq!(loader.default_object_loader, LoaderBackend::TcCommandObject);
    assert_eq!(loader.runtime_map_backend, LoaderBackend::RustSyscallMaps);
    assert!(loader.aya_userspace_loader_planned);
    assert!(loader.c_ebpf_object_fallback_required);
    assert!(!loader.go_fallback_preserved);
    assert!(loader.go_bpf_loader_fallback_retired);
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
}

#[test]
fn attach_backend_plan_keeps_command_fallback_until_native_attach_is_available() {
    let fallback = plan_attach_backend(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability::command_fallback_only(),
    );
    assert!(fallback.tcx_supported);
    assert_eq!(
        fallback.attempt_order,
        vec![
            AttachBackend::Tcx,
            AttachBackend::TcNetlink,
            AttachBackend::TcCommandFallback,
        ]
    );
    assert_eq!(fallback.selected, Some(AttachBackend::TcCommandFallback));
    assert!(fallback.command_fallback_used);

    let native_tcx = plan_attach_backend(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability {
            tcx: true,
            tc_netlink: true,
            tc_command_fallback: true,
        },
    );
    assert_eq!(native_tcx.selected, Some(AttachBackend::Tcx));
    assert!(!native_tcx.command_fallback_used);
}

#[test]
fn report_only_backend_capability_keeps_default_command_fallback() {
    let report = report_only_ebpf_backend_capability(Some(Version::new(6, 6, 0)));
    assert!(report.report_only);
    assert_eq!(report.aya_userspace_available, cfg!(feature = "aya-loader"));
    assert!(!report.tc_netlink_available);
    assert!(report.tcx_supported);
    assert!(!report.tcx_available);
    assert_eq!(
        report.selected_backend,
        Some(AttachBackend::TcCommandFallback)
    );
    assert!(report.command_fallback_used);
    assert_eq!(report.fallback_reason, Some("native_backends_report_only"));
    assert_eq!(
        report.attach_plan.attempt_order,
        vec![
            AttachBackend::Tcx,
            AttachBackend::TcNetlink,
            AttachBackend::TcCommandFallback,
        ]
    );
    assert_eq!(
        report.loader_contract.default_object_loader.as_str(),
        "tc_command_object"
    );
    assert_eq!(
        report.loader_contract.runtime_map_backend.as_str(),
        "rust_syscall_maps"
    );
    assert_eq!(AttachBackend::Tcx.as_str(), "tcx");
}
