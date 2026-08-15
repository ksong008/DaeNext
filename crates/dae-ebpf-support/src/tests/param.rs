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
        task_struct_mm_offset: 2640,
        mm_struct_arg_start_offset: 696,
    });
    assert_eq!(param.tproxy_port, u32::from(12345u16.to_be()));
    assert_eq!(param.control_plane_pid, 77);
    assert_eq!(param.dae0peer_mac, [1, 2, 3, 4, 5, 6]);
    assert_eq!(param.has_bpf_get_current_task, 1);
    assert_eq!(param.task_struct_mm_offset, 2640);
    assert_eq!(param.mm_struct_arg_start_offset, 696);
    assert_eq!(param.abi_version, BPF_DAE_PARAM_ABI_VERSION);
    assert_eq!(
        param.udp_state_saturation_policy,
        UDP_STATE_SATURATION_POLICY_FAIL_CLOSED
    );
    assert_eq!(
        param.udp_state_idle_timeout_ns,
        UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT
    );
}

#[test]
pub(super) fn tproxy_protection_flag_uses_abi_stable_padding_byte() {
    let input = DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: false,
        task_struct_mm_offset: 0,
        mm_struct_arg_start_offset: 0,
    };
    let protected = build_dae_param_with_protection(input, true);
    let unprotected = build_dae_param_with_protection(input, false);
    assert_eq!(protected.tproxy_port_protect, 1);
    assert_eq!(unprotected.tproxy_port_protect, 0);
    assert_eq!(
        std::mem::size_of_val(&protected),
        std::mem::size_of::<BpfDaeParam>()
    );
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
        task_struct_mm_offset: 2640,
        mm_struct_arg_start_offset: 696,
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
            "task_struct_mm_offset",
            "mm_struct_arg_start_offset",
            "abi_version",
            "udp_state_saturation_policy",
            "udp_state_idle_timeout_ns",
        ]
    );
}

#[test]
pub(super) fn param_object_rewriter_updates_real_dae_object_param_symbol() {
    let root = dae_golden::repo_root_from_manifest().unwrap();
    let source = root.join("control/bpf_bpfel.o");
    if !source.is_file() {
        eprintln!(
            "skip param object rewrite fixture test: {} is not present",
            source.display()
        );
        return;
    }
    let output = temp_path("dae-fixture-param-object-test.o");
    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12345,
        control_plane_pid: 77,
        dae0_ifindex: 8,
        dae_netns_id: 9,
        dae0peer_mac: [1, 2, 3, 4, 5, 6],
        has_bpf_get_current_task: true,
        task_struct_mm_offset: 2640,
        mm_struct_arg_start_offset: 696,
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
        task_struct_mm_offset: 2640,
        mm_struct_arg_start_offset: 696,
    });
    let bytes = param_to_object_bytes(param);
    assert_eq!(&bytes[0..4], &u32::from(12345u16.to_be()).to_le_bytes());
    assert_eq!(&bytes[16..22], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(bytes[22], 1);
    assert_eq!(&bytes[24..28], &2640u32.to_le_bytes());
    assert_eq!(&bytes[28..32], &696u32.to_le_bytes());
    assert_eq!(&bytes[32..36], &BPF_DAE_PARAM_ABI_VERSION.to_le_bytes());
    assert_eq!(
        &bytes[36..40],
        &UDP_STATE_SATURATION_POLICY_FAIL_CLOSED.to_le_bytes()
    );
    assert_eq!(
        &bytes[40..48],
        &UDP_STATE_IDLE_TIMEOUT_NS_DEFAULT.to_le_bytes()
    );
    assert_eq!(param_from_object_bytes(&bytes).unwrap(), param);
}
