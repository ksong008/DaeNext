use super::*;

#[test]
fn stage155_product_chain_blocker_review_fixture_matches() {
    let fixture =
        load("engine/runtime_stage155/product_chain_default_switch_blocker_review_gate.json");
    let output = run_with_args([
        "runtime",
        "stage155-product-chain-default-switch-blocker-review-gate",
    ]);
    assert_eq!(output.exit_code, 0, "{}", output.stdout);
    assert_eq!(output.stderr, "");
    let json: Value = serde_json::from_str(&output.stdout).unwrap();

    assert_eq!(json, fixture);
    assert!(json["blocked"].as_bool().unwrap());
    assert!(
        json["product_chain_blocker_review_recorded"]
            .as_bool()
            .unwrap()
    );
    assert!(json["benchmark_blocker_carried"].as_bool().unwrap());
    assert!(!json["default_switch_allowed"].as_bool().unwrap());
    assert!(!json["product_chain_switch_allowed"].as_bool().unwrap());
}

#[test]
fn stage155_runtime_rejects_bad_args() {
    let output = run_with_args([
        "runtime",
        "stage155-product-chain-default-switch-blocker-review-gate",
        "--bad",
    ]);
    assert_ne!(output.exit_code, 0);
    assert!(output.stderr.contains("unsupported stage155 argument"));
}
