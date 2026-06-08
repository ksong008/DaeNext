use super::*;
#[test]
pub(super) fn dae_param_packs_big_endian_tproxy_port() {
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
pub(super) fn param_aware_loader_gate_requires_real_loader_and_runtime_values() {
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
pub(super) fn dae_param_requirements_match_memo_fields() {
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
pub(super) fn param_object_rewriter_updates_real_dae_object_param_symbol() {
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
pub(super) fn param_object_bytes_roundtrip_layout() {
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
