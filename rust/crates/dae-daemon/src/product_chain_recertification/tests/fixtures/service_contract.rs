use super::*;
pub(crate) fn candidate_service_contract_value(resident_dataplane_ready: bool) -> Value {
    let mut report = serde_json::Map::new();
    insert_resident_runtime_contract(&mut report, resident_dataplane_ready);
    insert_control_plane_owner_contract(&mut report);
    insert_datapath_core_contract(&mut report);
    insert_outbound_fingerprint_underlay_contract(&mut report);
    insert_outbound_matrix_and_source_contract(&mut report);
    insert_resident_live_adapter_contract(&mut report);
    insert_release_default_switch_contract(&mut report);
    insert_go_free_product_chain_contract(&mut report);
    Value::Object(report)
}
