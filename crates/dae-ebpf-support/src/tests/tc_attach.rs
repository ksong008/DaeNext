use super::*;
#[test]
pub(super) fn tc_attach_backend_report_uses_command_backend_when_native_not_requested() {
    let peer = TcBpfAttachSpec::new(
        TcAttachTarget::netns("daens", "dae0peer", TcAttachDirection::Ingress),
        "49491",
        "/tmp/bpf_bpfel.param.o",
        "tc/dae0peer_ingress",
    );
    let native = peer.native_attach_spec("dae_dae0peer_ingress", 0, tc_handle(0x2022, 0b010));
    let report = peer.attach_backend_report(
        AttachBackend::Auto,
        Some(Version::new(6, 6, 0)),
        AttachBackendAvailability {
            tcx: true,
            tc_netlink: true,
            tc_command: true,
        },
        false,
        native,
    );

    assert_eq!(report.plan.selected, Some(AttachBackend::Tcx));
    assert_eq!(report.effective_backend, Some(AttachBackend::TcCommand));
    assert!(report.native_backend_capable);
    assert!(!report.native_backend_requested);
    assert!(report.command_backend_required);
    assert!(report.tcx_attempted);
    assert!(report.tc_netlink_attempted);
    assert!(report.command_backend_attempted);
    assert_eq!(report.native_spec.priority, 0);
    assert_eq!(report.native_spec.handle, 0x2022_0002);
    assert_eq!(report.native_spec.tcx_order, TcxAttachOrder::First);
    assert_eq!(report.native_spec.protocol, ETH_P_ALL);
    assert!(report.native_spec.direct_action);
    assert!(report.native_spec.clsact_required);
    assert!(report.native_spec.netns_enter_required);
    assert_eq!(report.command_backend_spec, peer.filter_add_command());
    assert_eq!(
        report.cleanup_command_backend_spec,
        peer.filter_del_command()
    );
    assert_eq!(
        report.show_command_backend_spec,
        peer.filter_show_command(true)
    );
}

#[test]
pub(super) fn dae_tc_attach_matrix_matches_native_control_plane_core_values() {
    let matrix = dae_tc_attach_matrix(DaeTcAttachMatrixInput {
        object: "/tmp/bpf_bpfel.param.o".to_owned(),
        lan_iface: "lan0".to_owned(),
        wan_iface: "wan0".to_owned(),
        host_iface: "dae0".to_owned(),
        peer_iface: "dae0peer".to_owned(),
        peer_netns: "daens".to_owned(),
        section_prefix: TcAttachSectionPrefix::Tc,
        link_layer: TcAttachLayer::L2,
        flip: 0,
        is_reload: false,
    });
    assert_eq!(matrix.len(), 6);

    let lan_ingress = attach_line(&matrix, DaeTcAttachRole::LanIngress);
    assert_eq!(lan_ingress.filter_name, "dae_lan_ingress_l2");
    assert_eq!(lan_ingress.native.program_name, "tproxy_lan_ingress_l2");
    assert_eq!(lan_ingress.native.section, "tc/lan_ingress_l2");
    assert_eq!(lan_ingress.native.target.iface, "lan0");
    assert_eq!(
        lan_ingress.native.target.direction,
        TcAttachDirection::Ingress
    );
    assert_eq!(lan_ingress.native.priority, 2);
    assert_eq!(lan_ingress.native.handle, tc_handle(0x2023, 0b100));
    assert_eq!(lan_ingress.native.tcx_order, TcxAttachOrder::Last);
    assert_eq!(
        lan_ingress.stale_cleanup_handle_on_fresh_start,
        Some(tc_handle(0x2023, 0b101))
    );

    let lan_egress = attach_line(&matrix, DaeTcAttachRole::LanEgress);
    assert_eq!(lan_egress.filter_name, "dae_lan_egress_l2");
    assert_eq!(lan_egress.native.program_name, "tproxy_lan_egress_l2");
    assert_eq!(lan_egress.native.section, "tc/lan_egress_l2");
    assert_eq!(
        lan_egress.native.target.direction,
        TcAttachDirection::Egress
    );
    assert_eq!(lan_egress.native.priority, 1);
    assert_eq!(lan_egress.native.handle, tc_handle(0x2023, 0b010));
    assert_eq!(lan_egress.native.tcx_order, TcxAttachOrder::First);

    let wan_ingress = attach_line(&matrix, DaeTcAttachRole::WanIngress);
    assert_eq!(wan_ingress.filter_name, "dae_wan_ingress_l2");
    assert_eq!(wan_ingress.native.program_name, "tproxy_wan_ingress_l2");
    assert_eq!(wan_ingress.native.section, "tc/wan_ingress_l2");
    assert_eq!(wan_ingress.native.target.iface, "wan0");
    assert_eq!(
        wan_ingress.native.target.direction,
        TcAttachDirection::Ingress
    );
    assert_eq!(wan_ingress.native.priority, 1);
    assert_eq!(wan_ingress.native.handle, tc_handle(0x2023, 0b010));
    assert_eq!(wan_ingress.native.tcx_order, TcxAttachOrder::First);

    let wan_egress = attach_line(&matrix, DaeTcAttachRole::WanEgress);
    assert_eq!(wan_egress.filter_name, "dae_wan_egress_l2");
    assert_eq!(wan_egress.native.program_name, "tproxy_wan_egress_l2");
    assert_eq!(wan_egress.native.section, "tc/wan_egress_l2");
    assert_eq!(
        wan_egress.native.target.direction,
        TcAttachDirection::Egress
    );
    assert_eq!(wan_egress.native.priority, 2);
    assert_eq!(wan_egress.native.handle, tc_handle(0x2023, 0b100));
    assert_eq!(wan_egress.native.tcx_order, TcxAttachOrder::Last);

    let peer = attach_line(&matrix, DaeTcAttachRole::Dae0peerIngress);
    assert_eq!(peer.filter_name, "dae_dae0peer_ingress");
    assert_eq!(peer.native.program_name, "tproxy_dae0peer_ingress");
    assert_eq!(peer.native.section, "tc/dae0peer_ingress");
    assert_eq!(peer.native.target.iface, "dae0peer");
    assert_eq!(peer.native.target.netns.as_deref(), Some("daens"));
    assert_eq!(peer.native.priority, 0);
    assert_eq!(peer.native.handle, tc_handle(0x2022, 0b010));
    assert_eq!(peer.native.tcx_order, TcxAttachOrder::First);
    assert_eq!(peer.stale_cleanup_handle_on_fresh_start, None);

    let host = attach_line(&matrix, DaeTcAttachRole::Dae0Ingress);
    assert_eq!(host.filter_name, "dae_dae0_ingress");
    assert_eq!(host.native.program_name, "tproxy_dae0_ingress");
    assert_eq!(host.native.section, "tc/dae0_ingress");
    assert_eq!(host.native.target.iface, "dae0");
    assert_eq!(host.native.target.netns, None);
    assert_eq!(host.native.priority, 0);
    assert_eq!(host.native.handle, tc_handle(0x2022, 0b010));
    assert_eq!(host.native.tcx_order, TcxAttachOrder::First);
    assert_eq!(
        host.stale_cleanup_handle_on_fresh_start,
        Some(tc_handle(0x2022, 0b011))
    );
}

#[test]
pub(super) fn dae_tc_attach_matrix_supports_l3_and_aya_classifier_sections() {
    let matrix = dae_tc_attach_matrix(DaeTcAttachMatrixInput {
        object: "/tmp/dae-aya-bpf_bpfel.o".to_owned(),
        lan_iface: "lan0".to_owned(),
        wan_iface: "wan0".to_owned(),
        host_iface: "dae0".to_owned(),
        peer_iface: "dae0peer".to_owned(),
        peer_netns: "daens".to_owned(),
        section_prefix: TcAttachSectionPrefix::Classifier,
        link_layer: TcAttachLayer::L3,
        flip: 1,
        is_reload: true,
    });

    let lan_ingress = attach_line(&matrix, DaeTcAttachRole::LanIngress);
    assert_eq!(lan_ingress.native.section, "classifier/lan_ingress_l3");
    assert_eq!(lan_ingress.native.program_name, "tproxy_lan_ingress_l3");
    assert_eq!(lan_ingress.native.handle, tc_handle(0x2023, 0b101));
    assert_eq!(lan_ingress.stale_cleanup_handle_on_fresh_start, None);

    let wan_ingress = attach_line(&matrix, DaeTcAttachRole::WanIngress);
    assert_eq!(wan_ingress.native.section, "classifier/wan_ingress_l3");
    assert_eq!(wan_ingress.native.program_name, "tproxy_wan_ingress_l3");
    assert_eq!(wan_ingress.native.handle, tc_handle(0x2023, 0b011));

    let wan_egress = attach_line(&matrix, DaeTcAttachRole::WanEgress);
    assert_eq!(wan_egress.native.section, "classifier/wan_egress_l3");
    assert_eq!(wan_egress.native.program_name, "tproxy_wan_egress_l3");
    assert_eq!(wan_egress.native.handle, tc_handle(0x2023, 0b101));

    let peer = attach_line(&matrix, DaeTcAttachRole::Dae0peerIngress);
    assert_eq!(peer.native.section, "classifier/dae0peer_ingress");
    assert_eq!(peer.native.program_name, "tproxy_dae0peer_ingress");
    assert_eq!(peer.native.handle, tc_handle(0x2022, 0b011));
    assert!(
        matrix
            .iter()
            .all(|line| line.stale_cleanup_handle_on_fresh_start.is_none())
    );
}

pub(super) fn attach_line(matrix: &[DaeTcAttachLine], role: DaeTcAttachRole) -> &DaeTcAttachLine {
    matrix
        .iter()
        .find(|line| line.role == role)
        .unwrap_or_else(|| panic!("missing attach line: {role:?}"))
}

#[test]
pub(super) fn tc_attach_contract_generates_existing_command_backend_shape() {
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
