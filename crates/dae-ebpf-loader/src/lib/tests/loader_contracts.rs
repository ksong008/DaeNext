use serde_json::Value;

use crate::*;
#[test]
pub(super) fn contract_declares_loader_only_scope() {
    let output = run_with_args(["bpf-loader", "contract"]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-ebpf-loader-native-runtime-contract"
    );
    assert_eq!(json["binary"].as_str().unwrap(), "dae-ebpf-loader");
    assert!(json["native_userspace_outbound_ready"].as_bool().unwrap());
    assert!(json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
    assert_eq!(
        json["default_object_source"].as_str().unwrap(),
        "rust-aya-loader"
    );
    assert!(json["rust_aya_loader_object_supported"].as_bool().unwrap());
    let maps = json["maps"].as_array().unwrap();
    let expected_maps = dae_ebpf_support::map_catalog();
    assert_eq!(maps.len(), expected_maps.len());
    assert_eq!(
        maps.iter()
            .map(|map| map["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        expected_maps.iter().map(|map| map.name).collect::<Vec<_>>()
    );
    assert_eq!(json["tc_programs"].as_array().unwrap().len(), 6);
    assert_eq!(json["cgroup_programs"].as_array().unwrap().len(), 6);
    assert_eq!(
        json["supported_object_sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["rust-aya-loader"]
    );
}

#[test]
pub(super) fn load_pin_requires_full_param_set() {
    let output = run_with_args(["bpf-loader", "load-pin", "--pin-root", "/tmp/dae"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--tproxy-port"));
}
