use super::*;
pub(crate) fn resident_live_adapter_matrix_contract() -> ResidentLiveAdapterMatrixContract {
    let entries = resident_live_adapter_matrix_entries();
    let evidence = resident_live_matrix_evidence_from_env();
    let planner_admission_ready = entries.iter().all(|entry| entry.planner_admitted);
    let tcp_live_adapter_ready = entries.iter().all(|entry| entry.tcp_path_ready());
    let udp_live_adapter_ready = entries.iter().all(|entry| entry.udp_path_ready());
    let transport_underlay_ready = entries.iter().all(|entry| entry.transport_underlay);
    let route_group_connectivity_ready = entries.iter().all(|entry| entry.route_group_connectivity);
    let selected_node_fail_closed_ready =
        entries.iter().all(|entry| entry.selected_node_fail_closed);
    let fingerprint_underlay_ready = entries.iter().all(|entry| entry.fingerprint_underlay);
    let native_executor_matrix_ready = entries.iter().all(|entry| entry.native_executor_ready);
    let wired_matrix_ready = !entries.is_empty() && entries.iter().all(|entry| entry.wired_ready());
    let remote_live_matrix_ready = !entries.is_empty()
        && entries
            .iter()
            .all(|entry| resident_live_adapter_entry_remote_live_matrix_ready(entry, &evidence));
    let matrix_ready = wired_matrix_ready && remote_live_matrix_ready;

    ResidentLiveAdapterMatrixContract {
        schema: "resident-live-adapter-matrix",
        entries,
        planner_admission_ready,
        tcp_live_adapter_ready,
        udp_live_adapter_ready,
        transport_underlay_ready,
        route_group_connectivity_ready,
        selected_node_fail_closed_ready,
        fingerprint_underlay_ready,
        native_executor_matrix_ready,
        wired_matrix_ready,
        remote_live_matrix_ready,
        matrix_ready,
    }
}
