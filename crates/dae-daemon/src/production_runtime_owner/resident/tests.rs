#[cfg(test)]
mod tests {
    use super::super::*;
    use dae_config::{Config, DynamicFunctionValue, Function, Global, Routing, RoutingRule};
    use serde_json::json;

    #[test]
    fn resident_interface_attach_auto_keeps_tcx_candidate_for_same_lan_wan_iface() {
        let options = ProductionRuntimeOwnerOptions {
            native_ebpf_requested: true,
            native_ebpf_backend: AttachBackend::Auto,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let (effective, policy) = resident_interface_attach_options(
            &options,
            &["enp1s0".to_owned()],
            &["enp1s0".to_owned()],
        );
        assert_eq!(effective.native_ebpf_backend, AttachBackend::Auto);
        assert_eq!(policy["effective_backend"], json!("auto"));
        assert_eq!(policy["auto_downgraded"], json!(false));
        assert_eq!(policy["same_interface_multi_role"], json!(true));
        assert_eq!(policy["auto_tcx_multi_role_admitted"], json!(true));
        assert_eq!(
            policy["auto_same_interface_tc_netlink_required"],
            json!(false)
        );
        assert_eq!(policy["overlapping_interfaces"], json!(["enp1s0"]));
        assert_eq!(
            policy["dae0_dae0peer_attach_backend_unchanged"],
            json!(true)
        );
        assert_eq!(
            policy["same_interface_tc_netlink_applies_to_all_tc_roles"],
            json!(false)
        );
        assert_eq!(policy["dae0_dae0peer_link_layer_unchanged"], json!(true));
        assert_eq!(
            policy["same_interface_tcx_order_policy"],
            json!(
                "ingress: wan_ingress before lan_ingress; egress: lan_egress before wan_egress; tc-netlink backend switch keeps native priority/handle"
            )
        );
        assert_eq!(
            policy["role_attach_plan"]["tcPriorityOrdering"][0]["roles"][0]["role"],
            json!("wan_ingress")
        );
        assert_eq!(
            policy["role_attach_plan"]["tcPriorityOrdering"][1]["roles"][0]["role"],
            json!("lan_egress")
        );
    }

    #[test]
    fn resident_interface_attach_auto_keeps_backend_for_split_lan_wan_ifaces() {
        let options = ProductionRuntimeOwnerOptions {
            native_ebpf_requested: true,
            native_ebpf_backend: AttachBackend::Auto,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let (effective, policy) = resident_interface_attach_options(
            &options,
            &["daerust0".to_owned()],
            &["ens3".to_owned()],
        );
        assert_eq!(effective.native_ebpf_backend, AttachBackend::Auto);
        assert_eq!(policy["auto_downgraded"], json!(false));
        assert_eq!(
            policy["auto_same_interface_tc_netlink_required"],
            json!(false)
        );
        assert_eq!(
            policy["same_interface_tc_netlink_applies_to_all_tc_roles"],
            json!(false)
        );
        assert_eq!(policy["overlapping_interfaces"], json!([]));
    }

    #[test]
    fn resident_interface_attach_honors_explicit_tcx_on_same_lan_wan_iface() {
        let options = ProductionRuntimeOwnerOptions {
            native_ebpf_requested: true,
            native_ebpf_backend: AttachBackend::Tcx,
            ..ProductionRuntimeOwnerOptions::default()
        };
        let (effective, policy) = resident_interface_attach_options(
            &options,
            &["enp1s0".to_owned()],
            &["enp1s0".to_owned()],
        );
        assert_eq!(effective.native_ebpf_backend, AttachBackend::Tcx);
        assert_eq!(policy["auto_downgraded"], json!(false));
        assert_eq!(policy["auto_tcx_multi_role_admitted"], json!(false));
        assert_eq!(
            policy["same_interface_tc_netlink_applies_to_all_tc_roles"],
            json!(false)
        );
        assert_eq!(policy["explicit_tcx_same_interface"], json!(true));
    }

    #[test]
    fn resident_summary_reports_actual_tcx_backend_instead_of_auto_plan() {
        let report = json!({
            "resident_interface_backend_policy": {"effective_backend": "auto"},
            "resident_wan_attach": [{
                "directions": [
                    {"backend": "tcx"},
                    {"backend": "tcx"}
                ]
            }],
            "resident_lan_attach": [{
                "backend": "tcx",
                "egress": {"backend": "tcx"}
            }]
        });

        assert_eq!(
            actual_resident_attach_backend(&report).as_deref(),
            Some("tcx")
        );
    }

    #[test]
    fn resident_routing_tuple_map_name_matches_kernel_visible_name() {
        assert!(kernel_visible_map_name_matches(
            "routing_tuples_map",
            ROUTING_TUPLES_MAP_NAME
        ));
        assert!(kernel_visible_map_name_matches(
            "routing_tuples_",
            ROUTING_TUPLES_MAP_NAME
        ));
        assert!(!kernel_visible_map_name_matches(
            "routing_map",
            ROUTING_TUPLES_MAP_NAME
        ));
    }

    #[test]
    fn startup_evidence_carries_reusable_map_capacity_and_cgroup_contracts() {
        let report = json!({
            "status": "pass",
            "resident_reusable_maps": [{
                "name": "routing_tuples_map",
                "status": "pass",
                "id": 7,
                "source": "native-runtime",
                "capacity": {
                    "id": 7,
                    "entries": 1,
                    "maxEntries": 131072,
                    "usageRatio": 0.00001,
                    "nearCapacity": false
                }
            }],
            "resident_cgroup_attach": {
                "pname": {
                    "source": "current_comm",
                    "coreEnabled": false,
                    "currentTaskArgvEnabled": false,
                    "officialArgvSemanticsImplemented": false
                },
                "linkLifecycle": {
                    "status": "owned-by-aya-runtime",
                    "releaseBoundary": "resident-runtime-reset"
                }
            },
            "resident_interface_monitor": {
                "status": "pass",
                "reattachImplemented": false,
                "startupLazyBindAllowed": false,
                "interfaces": []
            },
            "executed_steps": [],
            "resident_lan_routing": []
        });
        let evidence = startup_evidence_from_report(&report);
        assert_eq!(
            evidence["mapCapacity"][0]["name"],
            json!("routing_tuples_map")
        );
        assert_eq!(evidence["cgroupPname"]["source"], json!("current_comm"));
        assert_eq!(evidence["cgroupPname"]["coreEnabled"], json!(false));
        assert_eq!(
            evidence["cgroupLinkLifecycle"]["releaseBoundary"],
            json!("resident-runtime-reset")
        );
        assert_eq!(
            evidence["residentInterfaceState"]["reattachImplemented"],
            json!(false)
        );
    }

    #[test]
    fn resident_routing_process_name_requirement_detects_pname_rules() {
        let mut config = minimal_resident_config();
        assert!(!resident_routing_requires_process_name(&config));
        config.routing.rules.push(RoutingRule {
            and_functions: vec![Function {
                name: "pname".to_owned(),
                not: false,
                params: Vec::new(),
            }],
            outbound: Function {
                name: "direct".to_owned(),
                not: false,
                params: Vec::new(),
            },
        });
        assert!(resident_routing_requires_process_name(&config));
    }

    #[cfg(feature = "native-ebpf")]
    #[test]
    fn resident_native_backend_defaults_to_auto() {
        assert_eq!(default_native_backend(), AttachBackend::Auto);
    }

    fn minimal_resident_config() -> Config {
        Config {
            global: Global::default(),
            subscription: Vec::new(),
            node: Vec::new(),
            group: Vec::new(),
            routing: Routing {
                rules: Vec::new(),
                fallback: DynamicFunctionValue::String("direct".to_owned()),
            },
            dns: Default::default(),
        }
    }
}
