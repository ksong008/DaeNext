use super::*;

#[test]
fn stage163_bpf_owner_handoff_fixture_matches() {
    let fixture =
        load("engine/runtime_stage163/bpf_owner_transfer_listener_map_handoff_queue_gate.json");
    let output = run_with_args([
        "runtime",
        "stage163-bpf-owner-transfer-listener-map-handoff-queue-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["owner_transfer_handoff_queue_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(
        json["listen_socket_map_handoff_queue_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(!json["production_tc_attach_smoke_passed"].as_bool().unwrap());
}

#[test]
fn stage163_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage163-bpf-owner-transfer-listener-map-handoff-queue-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage163 argument"));
}
