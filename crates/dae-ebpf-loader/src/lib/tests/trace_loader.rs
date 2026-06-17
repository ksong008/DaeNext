use std::path::PathBuf;

use serde_json::Value;

use crate::*;
#[test]
pub(super) fn trace_loader_contract_declares_audit_scope() {
    let output = run_with_args(["trace-loader", "contract"]);
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    let json: Value = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(
        json["name"].as_str().unwrap(),
        "rust-aya-trace-loader-contract"
    );
    assert!(!json["core_sideload_enabled"].as_bool().unwrap());
    assert!(!json["native_trace_pinning_ready"].as_bool().unwrap());
    assert!(!json["production_daemon_path"].as_bool().unwrap());
    assert!(!json["kernel_ebpf_program_rewrite"].as_bool().unwrap());
    assert_eq!(
        json["audit_smokes"]["attach_ringbuf"].as_str().unwrap(),
        "disabled"
    );
    assert!(
        json["disabled_reason"]
            .as_str()
            .unwrap()
            .contains("excluded from the production runtime path")
    );
}

#[test]
pub(super) fn trace_loader_core_sideload_commands_are_disabled() {
    let output = run_with_args([
        "trace-loader",
        "load-pin",
        "--object",
        "/tmp/trace.o",
        "--pin-root",
        "/sys/fs/bpf/trace",
        "--ip-version",
        "4",
        "--l4-proto",
        "6",
        "--port",
        "443",
        "--ringbuf-size",
        "65536",
    ]);
    assert_eq!(output.exit_code, 1);
    assert!(
        output
            .stderr
            .contains("excluded from the production runtime path")
    );

    let output = run_with_args([
        "trace-loader",
        "attach-ringbuf-smoke",
        "--object",
        "/tmp/trace.o",
        "--target",
        "ip_rcv_core",
    ]);
    assert_eq!(output.exit_code, 1);
    assert!(
        output
            .stderr
            .contains("excluded from the production runtime path")
    );
}

#[test]
pub(super) fn trace_attach_ringbuf_smoke_options_parse_explicit_target_and_defaults() {
    let options = parse_trace_attach_ringbuf_smoke_options(&[
        "--object=/tmp/trace.o".to_owned(),
        "--target=ip_rcv_core".to_owned(),
    ])
    .unwrap();
    assert_eq!(options.object, PathBuf::from("/tmp/trace.o"));
    assert_eq!(options.target, "ip_rcv_core");
    assert_eq!(options.program_name, "kprobe_skb_1");
    assert_eq!(options.ip_version, 4);
    assert_eq!(options.l4_proto, 6);
    assert_eq!(options.port, 443);
    assert_eq!(options.ringbuf_size, 65_536);
    assert_eq!(options.trigger, TraceLoaderAttachSmokeTrigger::LoopbackUdp);
    assert_eq!(options.trigger_count, 4);
    assert_eq!(options.poll_attempts, 50);

    let explicit = parse_trace_attach_ringbuf_smoke_options(&[
        "--object".to_owned(),
        "/tmp/trace.o".to_owned(),
        "--target".to_owned(),
        "security_file_open".to_owned(),
        "--program-name".to_owned(),
        "kprobe_skb_1".to_owned(),
        "--trigger".to_owned(),
        "open-proc-self-stat".to_owned(),
        "--trigger-count".to_owned(),
        "2".to_owned(),
        "--poll-attempts".to_owned(),
        "3".to_owned(),
    ])
    .unwrap();
    assert_eq!(explicit.target, "security_file_open");
    assert_eq!(
        explicit.trigger,
        TraceLoaderAttachSmokeTrigger::OpenProcSelfStat
    );
    assert_eq!(explicit.trigger_count, 2);
    assert_eq!(explicit.poll_attempts, 3);

    let err = parse_trace_attach_ringbuf_smoke_options(&[
        "--object=/tmp/trace.o".to_owned(),
        "--trigger=bad".to_owned(),
    ])
    .unwrap_err();
    assert!(err.contains("bad trace attach smoke trigger"));
}
