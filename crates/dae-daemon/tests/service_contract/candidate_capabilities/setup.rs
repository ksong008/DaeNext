use super::*;
pub(crate) fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_daed-contract-runner")
}

pub(crate) fn candidate_service_contract_report() -> Value {
    let output = Command::new(binary())
        .arg("service-contract")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    report
}

#[test]
pub(crate) fn candidate_reports_resident_service_and_dataplane_capabilities() {
    let report = candidate_service_contract_report();
    assert_resident_and_control_plane_contract(&report);
    assert_datapath_and_outbound_underlay_contract(&report);
    assert_source_stream_packet_and_transport_contract(&report);
    assert_live_release_and_final_native_contract(&report);
    assert_resident_dataplane_enabled_contract();
}
