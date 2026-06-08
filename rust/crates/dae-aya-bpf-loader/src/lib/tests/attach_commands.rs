use std::path::PathBuf;

use serde_json::{Value, json};

use crate::*;
#[test]
pub(super) fn cgroup_monitor_contract_declares_pinned_link_lifetime() {
    let output = run_with_args(["cgroup-monitor", "contract"]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-cgroup-pname-monitor-attach-contract"
    );
    assert!(
        json["go_pname_routing_semantics_remain_authoritative"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["attach_matrix"].as_array().unwrap().len(), 6);
}
