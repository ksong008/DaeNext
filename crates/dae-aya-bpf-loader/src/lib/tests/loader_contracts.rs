use std::path::PathBuf;

use serde_json::Value;

use crate::*;
#[test]
pub(super) fn contract_declares_loader_only_scope() {
    let output = run_with_args(["bpf-loader", "contract"]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-aya-bpf-loader-native-runtime-contract"
    );
    assert_eq!(json["binary"].as_str().unwrap(), "dae-aya-bpf-loader");
    assert!(json["native_userspace_outbound_ready"].as_bool().unwrap());
    assert!(json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
    assert_eq!(
        json["default_object_source"].as_str().unwrap(),
        "rust-aya-skeleton"
    );
    assert!(
        json["rust_aya_skeleton_object_supported"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(json["maps"].as_array().unwrap().len(), 13);
    assert_eq!(json["tc_programs"].as_array().unwrap().len(), 6);
    assert_eq!(json["cgroup_programs"].as_array().unwrap().len(), 6);
    assert_eq!(
        json["supported_object_sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["external-aya-object", "rust-aya-skeleton"]
    );
}

#[test]
pub(super) fn load_pin_requires_full_param_set() {
    let output = run_with_args(["bpf-loader", "load-pin", "--pin-root", "/tmp/dae"]);
    assert_eq!(output.exit_code, 2);
    assert!(output.stderr.contains("--tproxy-port"));
}

#[test]
pub(super) fn load_pin_accepts_explicit_rust_skeleton_source() {
    let options = parse_load_pin_options(&[
        "--object-source=rust-aya-skeleton".to_owned(),
        "--object=/tmp/dae-ebpf-program".to_owned(),
        "--pin-root=/tmp/dae".to_owned(),
        "--tproxy-port=12345".to_owned(),
        "--control-plane-pid=7".to_owned(),
        "--dae0-ifindex=8".to_owned(),
        "--dae-netns-id=9".to_owned(),
        "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
        "--has-bpf-get-current-task=true".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        options.object_source,
        Some(BpfObjectSource::RustAyaSkeleton)
    );
    assert_eq!(options.object, Some(PathBuf::from("/tmp/dae-ebpf-program")));

    let options = parse_load_pin_options(&[
        "--object-source=rust-aya-skeleton".to_owned(),
        "--pin-root=/tmp/dae".to_owned(),
        "--tproxy-port=12345".to_owned(),
        "--control-plane-pid=7".to_owned(),
        "--dae0-ifindex=8".to_owned(),
        "--dae-netns-id=9".to_owned(),
        "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
        "--has-bpf-get-current-task=true".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        options.object_source,
        Some(BpfObjectSource::RustAyaSkeleton)
    );
    assert_eq!(options.object, None);

    let err = parse_load_pin_options(&[
        "--object-source=external-aya-object".to_owned(),
        "--pin-root=/tmp/dae".to_owned(),
        "--tproxy-port=12345".to_owned(),
        "--control-plane-pid=7".to_owned(),
        "--dae0-ifindex=8".to_owned(),
        "--dae-netns-id=9".to_owned(),
        "--dae0peer-mac=02:00:00:00:00:01".to_owned(),
        "--has-bpf-get-current-task=true".to_owned(),
    ])
    .unwrap_err();
    assert!(err.contains("external-aya-object requires --object"));
}
