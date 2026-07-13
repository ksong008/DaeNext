use super::*;

fn tc_binding(order: &str) -> ResidentTcBinding {
    ResidentTcBinding {
        role: ResidentDatapathBindingRole::WanIngress,
        backend: ResidentTcBindingBackend::Tcx,
        interface: "wan-fixture0".to_owned(),
        ifindex: 17,
        netns: None,
        direction: dae_ebpf_support::TcAttachDirection::Ingress,
        program_id: 42,
        program_name: "fixture_ingress".to_owned(),
        program_tag: "0011223344556677".to_owned(),
        priority: 1,
        handle: 0x2023_0002,
        tcx_order: order.to_owned(),
        tcx_anchor_relation: None,
        tcx_anchor_program_id: None,
        foreign_program_order_before: vec![7, 9],
    }
}

#[test]
fn registry_parses_exact_tc_and_cgroup_identity_from_attach_reports() {
    let steps = vec![
        json!({
            "name": "attach-resident-wan-ingress-native-ebpf-program-wan-fixture0",
            "status": "pass",
            "role": "wan_ingress",
            "native_attach": {
                "backend": "tcx",
                "program_id": 42,
                "program_name": "fixture_ingress",
                "program_tag": "0011223344556677",
                "iface": "wan-fixture0",
                "ifindex": 17,
                "netns": null,
                "direction": "ingress",
                "priority": 1,
                "handle": 539164674,
                "tcx_order": "first",
                "tcx_anchor": { "relation": "before", "program_id": 7 },
                "tcx_pre_program_order": [
                    { "id": 7, "name": "foreign-a", "tag": "a" },
                    { "id": 9, "name": "foreign-b", "tag": "b" }
                ],
                "attached": true,
                "detached": false
            }
        }),
        json!({
            "name": "attach-native-ebpf-cgroup-programs",
            "status": "pass",
            "preflight": {
                "lines": [{
                    "role": "Connect4",
                    "attachType": 10,
                    "existingPrograms": [{ "id": 81 }]
                }]
            },
            "programs": [{
                "role": "Connect4",
                "cgroup_path": "/sys/fs/cgroup",
                "program_id": 82,
                "program_tag": "0011223344556677",
                "program_name": "fixture_connect4",
                "section": "cgroup/connect4",
                "attach_type": 10,
                "attach_mode": "bpf-link-multi",
                "attached": true,
                "detached": false
            }]
        }),
    ];

    let registry = ResidentDatapathBindingRegistry::from_startup_steps(23, &steps).unwrap();
    let value = registry.to_value();

    assert_eq!(value["generation"], 23);
    assert_eq!(value["bindingCount"], 2);
    assert_eq!(value["tcBindings"][0]["role"], "wan-ingress");
    assert_eq!(value["tcBindings"][0]["programId"], 42);
    assert_eq!(value["tcBindings"][0]["ifindex"], 17);
    assert_eq!(
        value["tcBindings"][0]["foreignProgramOrderBefore"],
        json!([7, 9])
    );
    assert_eq!(value["cgroupBindings"][0]["programId"], 82);
    assert_eq!(
        value["cgroupBindings"][0]["foreignProgramIdsBefore"],
        json!([81])
    );
}

#[test]
fn registry_rejects_attach_reports_without_kernel_identity() {
    let steps = vec![json!({
        "status": "pass",
        "role": "wan_ingress",
        "native_attach": {
            "backend": "tcx",
            "program_name": "fixture_ingress",
            "program_tag": "0011223344556677",
            "iface": "wan-fixture0",
            "ifindex": 17,
            "direction": "ingress",
            "priority": 1,
            "handle": 1,
            "tcx_order": "first",
            "attached": true,
            "detached": false
        }
    })];

    let err = ResidentDatapathBindingRegistry::from_startup_steps(1, &steps).unwrap_err();
    assert!(err.contains("program_id"), "{err}");
}

#[test]
fn tcx_and_tc_netlink_identity_checks_are_exact() {
    let first = tc_binding("first");
    assert!(observe::tcx_requested_order_matches(&first, 0, 3));
    assert!(!observe::tcx_requested_order_matches(&first, 1, 3));

    let mut last = tc_binding("last");
    last.tcx_anchor_relation = Some("after".to_owned());
    last.tcx_anchor_program_id = Some(7);
    assert!(observe::tcx_requested_order_matches(&last, 2, 3));
    assert!(observe::tcx_anchor_matches(&last, 2, &[7, 9, 42]));
    assert!(!observe::tcx_anchor_matches(&last, 0, &[42, 7, 9]));

    assert!(observe::tc_output_matches_binding(
        "filter protocol all pref 1 bpf chain 0 handle 0x20230002 direct-action id 42 tag 0011223344556677",
        &first,
    ));
    assert!(!observe::tc_output_matches_binding(
        "filter protocol all pref 1 bpf chain 0 handle 0x20230002 direct-action id 41 tag 0011223344556677",
        &first,
    ));
    assert!(!observe::tc_output_matches_binding(
        "filter protocol all pref 1 bpf chain 0 handle 0x20230002 direct-action id 42 tag ffeeddccbbaa0099",
        &first,
    ));
    assert!(!observe::tc_output_matches_binding(
        "filter protocol all pref 1 bpf chain 0 handle 0x20230002\nfilter protocol all pref 1 bpf chain 0 direct-action id 42 tag 0011223344556677",
        &first,
    ));

    assert!(observe::ordered_subsequence(&[7, 9], &[7, 9]));
    assert!(observe::ordered_subsequence(&[7, 9], &[3, 7, 8, 9, 11]));
    assert!(!observe::ordered_subsequence(&[7, 9], &[9, 7]));
    assert!(!observe::ordered_subsequence(&[7, 9], &[7]));
}
