use serde_json::Value;

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
        json["native_pname_routing_semantics_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        json["pname_source"].as_str().unwrap(),
        "bpf_get_current_comm"
    );
    assert_eq!(
        json["pname_semantics"].as_str().unwrap(),
        "non_core_task_comm"
    );
    assert!(!json["core_enabled"].as_bool().unwrap());
    assert!(
        !json["official_argv_semantics_implemented"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["attach_matrix"].as_array().unwrap().len(), 6);
}
