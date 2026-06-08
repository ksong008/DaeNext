#[cfg(test)]
mod stage7_gate_tests {
    use serde_json::json;

    use super::super::*;

    #[test]
    fn stage7_release_gate_blocks_product_chain_switch_without_live_matrix() {
        let production_runtime_owner = json!({
            "datapath_outbound_ebpf_deep_area": {
                "fixed_queue_completed": true,
                "datapath_native_assets_recorded": true,
                "go_bpf_loader_restored": false,
                "aya_loader_direction_preserved": true
            }
        });
        let gate = release_product_chain_live_gate_json(
            true,
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
            &production_runtime_owner,
        );

        assert!(
            !gate["default_daemon_live_matrix_complete"]
                .as_bool()
                .unwrap()
        );
        assert!(!gate["release_gate_open"].as_bool().unwrap());
        assert!(!gate["default_switch_allowed"].as_bool().unwrap());
        assert!(!gate["product_chain_switch_allowed"].as_bool().unwrap());
        assert!(
            gate["go_runtime_outbound_fallback_required"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !gate["go_runtime_outbound_fallback_deletion_allowed"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn stage7_release_gate_blocks_without_resident_dataplane_default_switch() {
        let production_runtime_owner = json!({
            "datapath_outbound_ebpf_deep_area": {
                "fixed_queue_completed": true,
                "datapath_native_assets_recorded": true,
                "go_bpf_loader_restored": false,
                "aya_loader_direction_preserved": true
            }
        });
        let gate = release_product_chain_live_gate_json(
            true,
            true,
            true,
            true,
            false,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            &production_runtime_owner,
        );

        assert!(
            !gate["resident_dataplane_default_switch_ready"]
                .as_bool()
                .unwrap()
        );
        assert!(!gate["true_rust_default_daemon_admitted"].as_bool().unwrap());
        assert!(!gate["release_gate_open"].as_bool().unwrap());
        assert!(
            gate["remaining_blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|blocker| blocker
                    .as_str()
                    .unwrap()
                    .contains("resident userspace dataplane default switch env"))
        );
    }

    #[test]
    fn stage7_live_matrix_records_resident_dataplane_default_switch_row() {
        let matrix = default_daemon_live_matrix_json(
            true, true, true, true, true, true, true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, true, true, true, true, true, true, false,
        );

        assert!(!matrix["matrix_complete"].as_bool().unwrap());
        assert!(
            matrix["remaining_rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| {
                    row.as_str().unwrap() == "resident-userspace-dataplane-default-switch"
                })
        );
    }
}
