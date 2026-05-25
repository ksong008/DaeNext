use std::mem::{align_of, offset_of, size_of};
use std::path::PathBuf;

use serde_json::Value;

use crate::*;

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
    assert!(loader.go_fallback_preserved);
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
fn tc_attach_contract_generates_existing_command_fallback_shape() {
    let peer = TcBpfAttachSpec::new(
        TcAttachTarget::netns("daens", "dae0peer", TcAttachDirection::Ingress),
        "49491",
        "/tmp/bpf_bpfel.param.o",
        "tc/dae0peer_ingress",
    );
    let add = peer.filter_add_command();
    assert_eq!(add.program, "ip");
    assert_eq!(
        add.args,
        vec![
            "netns",
            "exec",
            "daens",
            "tc",
            "filter",
            "add",
            "dev",
            "dae0peer",
            "ingress",
            "pref",
            "49491",
            "bpf",
            "da",
            "obj",
            "/tmp/bpf_bpfel.param.o",
            "sec",
            "tc/dae0peer_ingress",
        ]
    );
    assert_eq!(
        peer.filter_show_command(true).args,
        vec![
            "netns", "exec", "daens", "tc", "-s", "filter", "show", "dev", "dae0peer", "ingress",
        ]
    );
    assert_eq!(
        peer.filter_del_command().args,
        vec![
            "netns", "exec", "daens", "tc", "filter", "del", "dev", "dae0peer", "ingress", "pref",
            "49491",
        ]
    );

    let host = TcAttachTarget::host("dae0", TcAttachDirection::Ingress);
    assert_eq!(host.clsact_qdisc_add_command().program, "tc");
    assert_eq!(
        host.clsact_qdisc_add_command().args,
        vec!["qdisc", "add", "dev", "dae0", "clsact"]
    );
}

#[test]
fn kernel_feature_gates_match_golden_fixture() {
    let fixture = load("ebpf/kernel_features/basic.json");
    for feature in fixture["features"].as_array().unwrap() {
        let version = match feature["name"].as_str().unwrap() {
            "basic" => BASIC_FEATURE_VERSION,
            "checksum" => CHECKSUM_FEATURE_VERSION,
            "sk_assign" => SK_ASSIGN_FEATURE_VERSION,
            "bpf_timer" => BPF_TIMER_FEATURE_VERSION,
            "bpf_loop" => BPF_LOOP_FEATURE_VERSION,
            other => panic!("unexpected feature {other}"),
        };
        assert_eq!(version.go_string(), feature["version"].as_str().unwrap());
        assert_eq!(
            version.kernel_code(),
            feature["kernel_code"].as_u64().unwrap() as u32
        );
    }

    for scenario in fixture["scenarios"].as_array().unwrap() {
        let version = parse_go_version(scenario["version"].as_str().unwrap());
        let report = FeatureGateReport::new(
            version,
            scenario["lan_configured"].as_bool().unwrap(),
            scenario["wan_configured"].as_bool().unwrap(),
        );
        let expected_missing = scenario["missing"]
            .as_array()
            .map(|items| items.iter().map(|value| value.as_str().unwrap()).collect())
            .unwrap_or_else(Vec::new);
        assert_eq!(report.missing, expected_missing);
        assert_eq!(report.allowed(), scenario["allowed"].as_bool().unwrap());
    }
}

#[test]
fn connectivity_dryrun_matches_golden_fixture() {
    let fixture = load("control/outbound_connectivity/dryrun.json");
    let mut map = ConnectivityMap::default();
    for event in fixture["events"].as_array().unwrap() {
        let key = ConnectivityKey {
            outbound: event["key"]["outbound"].as_u64().unwrap() as u8,
            l4proto: event["key"]["l4proto"].as_u64().unwrap() as u8,
            ipversion: event["key"]["ipversion"].as_u64().unwrap() as u8,
        };
        let written = map.record(ConnectivityEvent {
            key,
            alive: event["value"].as_u64().unwrap() == 1,
            is_init: event["name"].as_str().unwrap().contains("_init_"),
            dryrun: event["name"].as_str().unwrap().starts_with("dryrun_"),
        });
        assert_eq!(written, event["written"].as_bool().unwrap());
        assert_eq!(map.len(), event["state_len"].as_u64().unwrap() as usize);
        if written {
            assert_eq!(map.get(key), Some(event["value"].as_u64().unwrap() as u32));
        }
    }
}

#[test]
fn dae_param_packs_big_endian_tproxy_port() {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });
    assert_eq!(param.tproxy_port, u32::from(12345u16.to_be()));
    assert_eq!(param.control_plane_pid, 77);
    assert_eq!(param.dae0peer_mac, [1, 2, 3, 4, 5, 6]);
    assert_eq!(param.has_bpf_get_current_task, 1);
}

#[test]
fn param_aware_loader_gate_requires_real_loader_and_runtime_values() {
    let input = DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    };
    let payload = build_dae_param_payload(input);
    assert_eq!(payload.symbol, DAE_PARAM_SYMBOL);
    assert_eq!(payload.rust_layout_size, size_of::<BpfDaeParam>());
    assert_eq!(payload.tproxy_port_big_endian, u32::from(12345u16.to_be()));
    assert!(dae_param_runtime_values_present(&payload));
    assert!(!direct_tc_object_loader_rewrites_param());
    assert!(!param_aware_load_admitted(
        false,
        true,
        Some(DAE_PARAM_SYMBOL_SIZE),
        &payload
    ));
    assert!(param_aware_load_admitted(
        true,
        true,
        Some(DAE_PARAM_SYMBOL_SIZE),
        &payload
    ));

    let zero_netns = build_dae_param_payload(DaeParamInput {
        dae_netns_id: 0,
        ..input
    });
    assert!(!dae_param_runtime_values_present(&zero_netns));
}

#[test]
fn dae_param_requirements_match_memo_fields() {
    let fields = dae_param_requirements()
        .iter()
        .map(|requirement| requirement.field)
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![
            "tproxy_port",
            "control_plane_pid",
            "dae0_ifindex",
            "dae_netns_id",
            "dae0peer_mac",
            "has_bpf_get_current_task",
        ]
    );
}

#[test]
fn param_object_rewriter_updates_real_dae_object_param_symbol() {
    let root = dae_golden::repo_root_from_manifest().unwrap();
    let source = root.join("control/bpf_bpfel.o");
    let output = temp_path("dae-stage41-param-object-test.o");
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });

    let location = locate_param_symbol_in_object(&source).unwrap();
    assert_eq!(location.symbol, DAE_PARAM_SYMBOL);
    assert_eq!(location.section, ".rodata");
    assert_eq!(location.symbol_size, DAE_PARAM_SYMBOL_SIZE as u64);
    assert_eq!(
        read_param_from_object(&source).unwrap(),
        BpfDaeParam::default()
    );

    let report = write_param_aware_object(&source, &output, param).unwrap();
    assert_eq!(report.location, location);
    assert_eq!(report.source_len, report.output_len);
    assert!(report.previous_param_was_zero);
    assert!(report.rewritten_param_matches);
    assert_eq!(read_param_from_object(&output).unwrap(), param);
    let _ = std::fs::remove_file(output);
}

#[test]
fn param_object_bytes_roundtrip_layout() {
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
    });
    let bytes = param_to_object_bytes(param);
    assert_eq!(&bytes[0..4], &u32::from(12345u16.to_be()).to_le_bytes());
    assert_eq!(&bytes[16..22], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(bytes[22], 1);
    assert_eq!(param_from_object_bytes(&bytes).unwrap(), param);
}

fn load(path: &str) -> Value {
    dae_golden::load_json(path).unwrap()
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}-{name}", std::process::id()))
}

fn assert_layout<T>(fixture: &Value, name: &str, expected_size: usize, expected_align: usize) {
    let item = fixture_struct(fixture, name);
    assert_eq!(size_of::<T>(), expected_size);
    assert_eq!(align_of::<T>(), expected_align);
    assert_eq!(item["size"].as_u64().unwrap() as usize, size_of::<T>());
    assert_eq!(item["align"].as_u64().unwrap() as usize, align_of::<T>());
}

fn assert_offset<T>(fixture: &Value, struct_name: &str, field_name: &str, offset: usize) {
    let item = fixture_struct(fixture, struct_name);
    let offsets = item["offsets"].as_array().unwrap();
    let expected = offsets
        .iter()
        .find(|entry| entry["field"].as_str().unwrap() == field_name)
        .unwrap();
    assert_eq!(expected["offset"].as_u64().unwrap() as usize, offset);
}

fn fixture_struct<'a>(fixture: &'a Value, name: &str) -> &'a Value {
    fixture["structs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"].as_str().unwrap() == name)
        .unwrap()
}

fn parse_go_version(input: &str) -> Version {
    let trimmed = input.trim_start_matches('v');
    let parts = trimmed
        .split('.')
        .map(|part| part.parse::<u16>().unwrap())
        .collect::<Vec<_>>();
    Version::new(parts[0], parts[1], parts.get(2).copied().unwrap_or(0))
}
