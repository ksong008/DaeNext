use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use dae_ebpf_support::{
    DAE_PARAM_SYMBOL, DAE_PARAM_SYMBOL_SIZE, DaeParamInput, build_dae_param,
    build_dae_param_payload, locate_param_symbol_in_object, read_param_from_object,
    write_param_aware_object,
};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_SOURCE_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE41_OUTPUT: &str = "/tmp/dae-stage41-candidate/bpf_bpfel.param.o";
const DEFAULT_STAGE42_ROOT: &str = "/tmp/dae-stage42-candidate";
const DEFAULT_STAGE42_IFACE: &str = "dae42p0";
const DEFAULT_STAGE42_SECTION: &str = "tc/dae0_ingress";
const STAGE42_FILTER_PREF: &str = "49420";

const DEFAULT_TPROXY_PORT: u16 = 12345;
const DEFAULT_CONTROL_PLANE_PID: u32 = 77;
const DEFAULT_DAE0_IFINDEX: u32 = 8;
const DEFAULT_DAE_NETNS_ID: u32 = 9;
const DEFAULT_DAE0PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 41];

pub(crate) fn run_stage41_param_object_image_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage41Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage41_report(&opts);
    output_with_required_admission(
        report,
        opts.require_admission,
        "param_object_image_admitted",
    )
}

pub(crate) fn run_stage42_param_object_load_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage42Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage42_report(&opts);
    output_with_execution_status(
        report,
        opts.execute_smoke,
        "param_object_tc_attach_smoke_passed",
    )
}

pub(crate) fn run_stage43_production_param_listener_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage43_report())
}

pub(crate) fn run_stage44_active_tcp_tproxy_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage44_report())
}

pub(crate) fn run_stage45_active_udp_tproxy_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage45_report())
}

pub(crate) fn run_stage46_active_dns_tproxy_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage46_report())
}

pub(crate) fn run_stage47_outbound_true_dataplane_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage47_report())
}

pub(crate) fn run_stage48_true_daemon_benchmark_admission(args: &[String]) -> RunnerOutput {
    static_report_command(args, stage48_report())
}

fn output_with_required_admission(
    report: Value,
    require_admission: bool,
    pass_key: &str,
) -> RunnerOutput {
    let passed = report[pass_key].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if require_admission && !passed {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

fn output_with_execution_status(report: Value, executed: bool, pass_key: &str) -> RunnerOutput {
    let passed = report[pass_key].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if executed && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

fn static_report_command(args: &[String], report: Value) -> RunnerOutput {
    if let Some(arg) = args.first() {
        return RunnerOutput::usage(format!("unsupported runtime stage41-48 argument: {arg}"));
    }
    RunnerOutput::ok(format!("{report}\n"))
}

#[derive(Debug, Clone)]
struct ParamOptions {
    tproxy_port: u16,
    control_plane_pid: u32,
    dae0_ifindex: u32,
    dae_netns_id: u32,
    dae0peer_mac: [u8; 6],
    has_bpf_get_current_task: bool,
}

impl Default for ParamOptions {
    fn default() -> Self {
        Self {
            tproxy_port: DEFAULT_TPROXY_PORT,
            control_plane_pid: DEFAULT_CONTROL_PLANE_PID,
            dae0_ifindex: DEFAULT_DAE0_IFINDEX,
            dae_netns_id: DEFAULT_DAE_NETNS_ID,
            dae0peer_mac: DEFAULT_DAE0PEER_MAC,
            has_bpf_get_current_task: true,
        }
    }
}

impl ParamOptions {
    fn input(&self) -> DaeParamInput {
        DaeParamInput {
            tproxy_port: self.tproxy_port,
            control_plane_pid: self.control_plane_pid,
            dae0_ifindex: self.dae0_ifindex,
            dae_netns_id: self.dae_netns_id,
            dae0peer_mac: self.dae0peer_mac,
            has_bpf_get_current_task: self.has_bpf_get_current_task,
        }
    }
}

#[derive(Debug, Clone)]
struct Stage41Options {
    source_object: PathBuf,
    output_object: PathBuf,
    write_image: bool,
    require_admission: bool,
    param: ParamOptions,
}

impl Default for Stage41Options {
    fn default() -> Self {
        Self {
            source_object: PathBuf::from(DEFAULT_SOURCE_OBJECT),
            output_object: PathBuf::from(DEFAULT_STAGE41_OUTPUT),
            write_image: false,
            require_admission: false,
            param: ParamOptions::default(),
        }
    }
}

impl Stage41Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        parse_common_args(args, "stage41", |flag, value| match flag {
            "--object" => {
                opts.source_object = PathBuf::from(value);
                Ok(())
            }
            "--output" => {
                opts.output_object = PathBuf::from(value);
                Ok(())
            }
            "--write-image" => {
                opts.write_image = true;
                Ok(())
            }
            "--require-admission" => {
                opts.require_admission = true;
                Ok(())
            }
            _ => parse_param_arg(&mut opts.param, flag, value),
        })?;
        Ok(opts)
    }
}

fn stage41_report(opts: &Stage41Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    let param = build_dae_param(opts.param.input());
    let payload = build_dae_param_payload(opts.param.input());

    push_check(
        &mut checks,
        "real-dae-object-present",
        opts.source_object.exists(),
        json!({"path": path_string(&opts.source_object)}),
        &mut blockers,
        "stage41 source eBPF object is missing",
    );
    let symbol = locate_param_symbol_in_object(&opts.source_object);
    let symbol_json = match &symbol {
        Ok(location) => json!({
            "symbol": location.symbol,
            "section": location.section,
            "symbol_size": location.symbol_size,
            "file_offset": location.file_offset,
            "section_offset": location.section_offset,
            "symbol_value": location.symbol_value,
        }),
        Err(err) => json!({"error": err.to_string()}),
    };
    push_check(
        &mut checks,
        "param-symbol-locatable",
        symbol.is_ok(),
        symbol_json.clone(),
        &mut blockers,
        "stage41 cannot locate PARAM symbol in source object",
    );
    let source_param = read_param_from_object(&opts.source_object);
    push_check(
        &mut checks,
        "source-param-is-zero-baseline",
        source_param
            .as_ref()
            .map(|value| *value == Default::default())
            .unwrap_or(false),
        json!({
            "status": if source_param.is_ok() { "read" } else { "error" },
            "error": source_param.as_ref().err().map(ToString::to_string),
        }),
        &mut blockers,
        "stage41 source object PARAM baseline is not zero or cannot be read",
    );

    let mut rewrite_report = Value::Null;
    let mut rewritten_param = Value::Null;
    let mut write_passed = !opts.write_image;
    if opts.write_image && blockers.is_empty() {
        match write_param_aware_object(&opts.source_object, &opts.output_object, param) {
            Ok(report) => {
                write_passed = report.rewritten_param_matches;
                rewritten_param = match read_param_from_object(&opts.output_object) {
                    Ok(value) => json!({
                        "tproxy_port": value.tproxy_port,
                        "control_plane_pid": value.control_plane_pid,
                        "dae0_ifindex": value.dae0_ifindex,
                        "dae_netns_id": value.dae_netns_id,
                        "dae0peer_mac": mac_string(value.dae0peer_mac),
                        "has_bpf_get_current_task": value.has_bpf_get_current_task,
                        "padding": value.padding,
                    }),
                    Err(err) => json!({"error": err.to_string()}),
                };
                rewrite_report = json!({
                    "source_len": report.source_len,
                    "output_len": report.output_len,
                    "expected_param_size": report.expected_param_size,
                    "previous_param_was_zero": report.previous_param_was_zero,
                    "rewritten_param_matches": report.rewritten_param_matches,
                    "location": {
                        "symbol": report.location.symbol,
                        "section": report.location.section,
                        "symbol_size": report.location.symbol_size,
                        "file_offset": report.location.file_offset,
                    },
                });
            }
            Err(err) => {
                write_passed = false;
                rewrite_report = json!({"status": "fail", "error": err.to_string()});
            }
        }
    }
    if opts.write_image && !write_passed {
        blockers.push("stage41 PARAM-aware object image rewrite failed".to_owned());
    }

    let param_object_image_admitted = blockers.is_empty() && write_passed;
    json!({
        "name": "stage41-param-object-image-admission",
        "stage": "stage41",
        "evidence_class": "param-aware-bpf-object-image-writer",
        "read_only": !opts.write_image,
        "blocked": !blockers.is_empty(),
        "blockers": blockers,
        "checks": checks,
        "source_object": path_string(&opts.source_object),
        "output_object": path_string(&opts.output_object),
        "param_symbol": symbol_json,
        "param_payload": {
            "symbol": DAE_PARAM_SYMBOL,
            "rust_layout_size": DAE_PARAM_SYMBOL_SIZE,
            "tproxy_port_host": payload.tproxy_port_host,
            "tproxy_port_big_endian": payload.tproxy_port_big_endian,
            "control_plane_pid": payload.control_plane_pid,
            "dae0_ifindex": payload.dae0_ifindex,
            "dae_netns_id": payload.dae_netns_id,
            "dae0peer_mac": mac_string(payload.dae0peer_mac),
            "has_bpf_get_current_task": payload.has_bpf_get_current_task,
        },
        "param_object_image_write_requested": opts.write_image,
        "param_object_image_written": opts.write_image && write_passed,
        "param_object_image_admitted": param_object_image_admitted,
        "rewrite_report": rewrite_report,
        "rewritten_param": rewritten_param,
        "active_tproxy_traffic_executed": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "remaining_blockers": [
            "PARAM-aware object image must still be loaded and attached in an isolated smoke",
            "active tproxy TCP UDP DNS traffic evidence is still missing",
            "outbound true dataplane admission is still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
    })
}

#[derive(Debug, Clone)]
struct Stage42Options {
    root: PathBuf,
    source_object: PathBuf,
    param_object: PathBuf,
    execute_smoke: bool,
    ack_root_gate: bool,
    iface: String,
    section: String,
    param: ParamOptions,
}

impl Default for Stage42Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_STAGE42_ROOT),
            source_object: PathBuf::from(DEFAULT_SOURCE_OBJECT),
            param_object: PathBuf::from(DEFAULT_STAGE42_ROOT).join("bpf_bpfel.param.o"),
            execute_smoke: false,
            ack_root_gate: false,
            iface: DEFAULT_STAGE42_IFACE.to_owned(),
            section: DEFAULT_STAGE42_SECTION.to_owned(),
            param: ParamOptions::default(),
        }
    }
}

impl Stage42Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        parse_common_args(args, "stage42", |flag, value| match flag {
            "--root" => {
                opts.root = PathBuf::from(value);
                if opts.param_object
                    == PathBuf::from(DEFAULT_STAGE42_ROOT).join("bpf_bpfel.param.o")
                {
                    opts.param_object = opts.root.join("bpf_bpfel.param.o");
                }
                Ok(())
            }
            "--object" => {
                opts.source_object = PathBuf::from(value);
                Ok(())
            }
            "--param-object" => {
                opts.param_object = PathBuf::from(value);
                Ok(())
            }
            "--execute-smoke" => {
                opts.execute_smoke = true;
                Ok(())
            }
            "--ack-root-gate" => {
                opts.ack_root_gate = true;
                Ok(())
            }
            "--iface" => {
                opts.iface = value;
                Ok(())
            }
            "--section" => {
                opts.section = value;
                Ok(())
            }
            _ => parse_param_arg(&mut opts.param, flag, value),
        })?;
        Ok(opts)
    }
}

fn stage42_report(opts: &Stage42Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage42 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage42 root-gated smoke requires --ack-root-gate",
    );
    push_check(
        &mut checks,
        "temporary-interface-name-valid",
        iface_name_valid(&opts.iface),
        json!({"iface": opts.iface, "max_linux_ifname_len": 15}),
        &mut blockers,
        "stage42 temporary interface name is invalid",
    );
    push_check(
        &mut checks,
        "temporary-interface-not-production",
        opts.iface != "dae0" && opts.iface != "dae0peer",
        json!({"iface": opts.iface}),
        &mut blockers,
        "stage42 cannot target production dae0/dae0peer names",
    );
    for tool in ["ip", "tc"] {
        push_check(
            &mut checks,
            match tool {
                "ip" => "tool-ip-available",
                _ => "tool-tc-available",
            },
            command_exists(tool),
            json!({"tool": tool}),
            &mut blockers,
            "required host tool is missing",
        );
    }
    push_check(
        &mut checks,
        "source-object-present",
        opts.source_object.exists(),
        json!({"path": path_string(&opts.source_object)}),
        &mut blockers,
        "stage42 source eBPF object is missing",
    );
    if opts.execute_smoke {
        push_check(
            &mut checks,
            "temporary-interface-name-free",
            !iface_exists(&opts.iface),
            json!({"iface": opts.iface}),
            &mut blockers,
            "stage42 temporary interface name already exists",
        );
    }

    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut param_image = Value::Null;
    let mut attach_show = Value::Null;
    let mut param_object_tc_attach_smoke_passed = false;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage42_smoke(opts);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        param_image = result.param_image;
        attach_show = result.attach_show;
        param_object_tc_attach_smoke_passed = result.passed;
        if !param_object_tc_attach_smoke_passed {
            blockers.push("stage42 PARAM-aware object tc attach smoke failed".to_owned());
        }
    }
    let leftovers = iface_leftovers(&opts.iface);
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage42 temporary resources remain after cleanup".to_owned());
    }

    json!({
        "name": "stage42-param-object-load-admission",
        "stage": "stage42",
        "evidence_class": "root-gated-param-aware-real-object-tc-load-smoke",
        "root": path_string(&opts.root),
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "blockers": blockers,
        "checks": checks,
        "source_object": path_string(&opts.source_object),
        "param_object": path_string(&opts.param_object),
        "section": opts.section,
        "temporary_iface": opts.iface,
        "filter_pref": STAGE42_FILTER_PREF,
        "param_object_generated": opts.execute_smoke && param_image["status"].as_str() == Some("pass"),
        "param_object_tc_attach_smoke_passed": param_object_tc_attach_smoke_passed,
        "param_aware_object_load_admitted": param_object_tc_attach_smoke_passed,
        "active_tproxy_traffic_executed": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "param_image": param_image,
        "attach_show": attach_show,
        "executed_steps": executed_steps,
        "cleanup_steps": cleanup_steps,
        "temporary_resources": {
            "iface": opts.iface,
            "leftovers_after_cleanup": leftovers,
        },
        "remaining_blockers": [
            "production-name topology plus transparent listener must be revalidated with the PARAM-aware object",
            "active tproxy TCP UDP DNS traffic evidence is still missing",
            "outbound true dataplane admission is still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
    })
}

struct Stage42SmokeResult {
    passed: bool,
    param_image: Value,
    attach_show: Value,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
}

fn execute_stage42_smoke(opts: &Stage42Options) -> Stage42SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let param = build_dae_param(opts.param.input());
    let param_image = match write_param_aware_object(&opts.source_object, &opts.param_object, param)
    {
        Ok(report) => json!({
            "status": "pass",
            "path": path_string(&opts.param_object),
            "rewritten_param_matches": report.rewritten_param_matches,
            "previous_param_was_zero": report.previous_param_was_zero,
            "source_len": report.source_len,
            "output_len": report.output_len,
            "param": {
                "tproxy_port": param.tproxy_port,
                "control_plane_pid": param.control_plane_pid,
                "dae0_ifindex": param.dae0_ifindex,
                "dae_netns_id": param.dae_netns_id,
                "dae0peer_mac": mac_string(param.dae0peer_mac),
                "has_bpf_get_current_task": param.has_bpf_get_current_task,
            },
        }),
        Err(err) => json!({
            "status": "fail",
            "path": path_string(&opts.param_object),
            "error": err.to_string(),
        }),
    };
    let mut ok = param_image["status"].as_str() == Some("pass");
    ok &= run_step(
        &mut executed_steps,
        "create-temporary-dummy-interface",
        CommandSpec::new("ip", &["link", "add", &opts.iface, "type", "dummy"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "bring-temporary-interface-up",
        CommandSpec::new("ip", &["link", "set", &opts.iface, "up"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "attach-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "add", "dev", &opts.iface, "clsact"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "attach-param-aware-ebpf-program",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                &opts.iface,
                "ingress",
                "pref",
                STAGE42_FILTER_PREF,
                "bpf",
                "da",
                "obj",
                &path_string(&opts.param_object),
                "sec",
                &opts.section,
            ],
        ),
    );
    let attach_show = run_observation_step(
        &mut executed_steps,
        "show-param-aware-ebpf-program-filter",
        CommandSpec::new("tc", &["filter", "show", "dev", &opts.iface, "ingress"]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-param-aware-ebpf-program-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &opts.iface,
                "ingress",
                "pref",
                STAGE42_FILTER_PREF,
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "del", "dev", &opts.iface, "clsact"]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-interface",
        CommandSpec::new("ip", &["link", "del", &opts.iface]),
    );
    let attach_output = attach_show["stdout"].as_str().unwrap_or_default();
    Stage42SmokeResult {
        passed: ok
            && attach_show["status"].as_str() == Some("pass")
            && attach_output.contains(&opts.section)
            && iface_leftovers(&opts.iface).is_empty(),
        param_image,
        attach_show,
        executed_steps,
        cleanup_steps,
    }
}

fn stage43_report() -> Value {
    blocked_static_report(
        "stage43-production-param-listener-admission",
        "stage43",
        "production-name topology plus PARAM-aware object plus transparent listener combined gate",
        "Stage 43 requires Stage 38 production names, Stage 39 transparent listener handoff, and Stage 42 PARAM-aware object load to be re-run as one evidence chain",
        &[
            "combined production-name PARAM-aware transparent-listener smoke is not executed",
            "active tproxy TCP UDP DNS traffic evidence is still missing",
            "outbound true dataplane admission is still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
        ],
        json!({
            "requires": [
                "production-name dae0/dae0peer/daens topology",
                "PARAM-aware object image loaded through tc/libbpf",
                "IP_TRANSPARENT TCP and UDP listener fd handoff into listen_socket_map key 0/1"
            ],
            "combined_prerequisites_admitted": false,
        }),
    )
}

fn stage44_report() -> Value {
    blocked_static_report(
        "stage44-active-tcp-tproxy-admission",
        "stage44",
        "active TCP tproxy datapath gate",
        "Stage 44 must prove redirected TCP packets reach the transparent listener and outbound relay with original destination, SO_MARK, and mptcp parity",
        &[
            "active TCP tproxy traffic is not executed",
            "RouteDialTcp reroute and outbound relay evidence is missing",
            "matched TCP latency throughput benchmark is missing",
        ],
        json!({
            "traffic": "tcp",
            "required_evidence": [
                "redirected SYN enters tproxy listener",
                "original destination is observed",
                "routing result and outbound target are recorded",
                "MagicNetwork mark and mptcp are preserved",
                "reply path succeeds"
            ],
            "active_tproxy_tcp_executed": false,
        }),
    )
}

fn stage45_report() -> Value {
    blocked_static_report(
        "stage45-active-udp-tproxy-admission",
        "stage45",
        "active UDP tproxy datapath gate",
        "Stage 45 must prove UDP endpoint pool, packet routing, outbound PacketConn, and sendPkt reply parity under the PARAM-aware object",
        &[
            "active UDP tproxy traffic is not executed",
            "UDP endpoint pool live evidence is missing",
            "matched UDP latency loss throughput benchmark is missing",
        ],
        json!({
            "traffic": "udp",
            "required_evidence": [
                "transparent UDP packet enters handlePkt-equivalent path",
                "endpoint pool creates and trims entries",
                "PacketConn WriteTo and ReadFrom semantics are preserved",
                "sendPkt reply path succeeds"
            ],
            "active_tproxy_udp_executed": false,
        }),
    )
}

fn stage46_report() -> Value {
    blocked_static_report(
        "stage46-active-dns-tproxy-admission",
        "stage46",
        "transparent DNS UDP/53 and reload cache gate",
        "Stage 46 must prove DNS UDP/53 transparent traffic, DNS upstream routing, cache restore, and domain-routing owner migration under reload",
        &[
            "transparent DNS UDP/53 traffic is not executed",
            "reload DNS cache migration live evidence is missing",
            "domain_routing_map owner migration live evidence is missing",
        ],
        json!({
            "traffic": "dns-udp53",
            "required_evidence": [
                "transparent UDP/53 request enters DNS controller path",
                "DNS upstream MagicNetwork mark and mptcp are preserved",
                "DNS cache hit/miss and restore evidence is recorded",
                "domain routing owner merge/remove survives reload"
            ],
            "active_tproxy_dns_executed": false,
        }),
    )
}

fn stage47_report() -> Value {
    blocked_static_report(
        "stage47-outbound-true-dataplane-admission",
        "stage47",
        "outbound true dataplane gate",
        "Stage 47 must prove protocol true dataplane, shared transport, reload cleanup, fallback/rollback, and benchmark evidence before any outbound default replacement",
        &[
            "outbound true dataplane admission is still incomplete",
            "shared transport true dataplane evidence is missing",
            "Go vs Rust protocol benchmark evidence is missing",
        ],
        json!({
            "protocol_batches": [
                "SOCKS5 TCP CONNECT and UDP ASSOCIATE",
                "HTTP CONNECT and passthrough",
                "Shadowsocks AEAD TCP and UDP",
                "shared transports: TLS/uTLS/REALITY/WS/gRPC/xHTTP/Meek/Mux",
                "QUIC/H3 protocols: Hysteria2/TUIC/Juicity"
            ],
            "outbound_true_dataplane_admitted": false,
        }),
    )
}

fn stage48_report() -> Value {
    blocked_static_report(
        "stage48-true-daemon-benchmark-admission",
        "stage48",
        "true Rust default daemon lifecycle and matched benchmark gate",
        "Stage 48 must start a true Rust daemon candidate, compare it against Go default daemon on the same host/corpus, and keep product switch denied until every datapath row passes",
        &[
            "true Rust default daemon lifecycle smoke is not executed",
            "matched Go default daemon vs true Rust candidate benchmark is missing",
            "clean dae-wing and daed product-chain recertification is missing",
        ],
        json!({
            "required_benchmarks": [
                "TCP proxy latency and throughput",
                "UDP proxy latency loss throughput",
                "DNS UDP/53 latency and cache behavior",
                "RSS CPU startup time reload time",
                "outbound protocol benchmarks on admitted protocols"
            ],
            "true_rust_default_daemon_admitted": false,
        }),
    )
}

fn blocked_static_report(
    name: &str,
    stage: &str,
    evidence_class: &str,
    decision: &str,
    blockers: &[&str],
    detail: Value,
) -> Value {
    json!({
        "name": name,
        "stage": stage,
        "evidence_class": evidence_class,
        "read_only": true,
        "blocked": false,
        "blockers": [],
        "gate_decision": decision,
        "detail": detail,
        "active_tproxy_traffic_executed": false,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "remaining_blockers": blockers,
    })
}

fn parse_common_args<F>(args: &[String], stage: &str, mut set: F) -> Result<(), RunnerOutput>
where
    F: FnMut(&str, String) -> Result<(), RunnerOutput>,
{
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if matches!(
            arg.as_str(),
            "--write-image"
                | "--require-admission"
                | "--execute-smoke"
                | "--ack-root-gate"
                | "--has-bpf-get-current-task"
                | "--no-bpf-get-current-task"
        ) {
            set(arg, String::new())?;
            continue;
        }
        if let Some((flag, value)) = arg.split_once('=') {
            set(flag, value.to_owned())?;
            continue;
        }
        let flag = arg.as_str();
        let value = iter
            .next()
            .cloned()
            .ok_or_else(|| RunnerOutput::usage(format!("missing value for {stage} {flag}")))?;
        set(flag, value)?;
    }
    Ok(())
}

fn parse_param_arg(
    param: &mut ParamOptions,
    flag: &str,
    value: String,
) -> Result<(), RunnerOutput> {
    match flag {
        "--tproxy-port" => param.tproxy_port = parse_port(&value, flag)?,
        "--control-plane-pid" => param.control_plane_pid = parse_u32(&value, flag)?,
        "--dae0-ifindex" => param.dae0_ifindex = parse_u32(&value, flag)?,
        "--dae-netns-id" => param.dae_netns_id = parse_u32(&value, flag)?,
        "--dae0peer-mac" => param.dae0peer_mac = parse_mac(&value)?,
        "--has-bpf-get-current-task" => param.has_bpf_get_current_task = true,
        "--no-bpf-get-current-task" => param.has_bpf_get_current_task = false,
        _ => {
            return Err(RunnerOutput::usage(format!(
                "unsupported runtime stage41-48 argument: {flag}"
            )));
        }
    }
    Ok(())
}

fn parse_port(value: &str, flag: &str) -> Result<u16, RunnerOutput> {
    value
        .parse::<u16>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
        .and_then(|port| {
            if port == 0 {
                Err(RunnerOutput::usage(format!(
                    "invalid {flag}: must be non-zero"
                )))
            } else {
                Ok(port)
            }
        })
}

fn parse_u32(value: &str, flag: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {flag}: {err}")))
        .and_then(|parsed| {
            if parsed == 0 {
                Err(RunnerOutput::usage(format!(
                    "invalid {flag}: must be non-zero"
                )))
            } else {
                Ok(parsed)
            }
        })
}

fn parse_mac(value: &str) -> Result<[u8; 6], RunnerOutput> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(RunnerOutput::usage(
            "invalid --dae0peer-mac: expected six colon-separated hex octets",
        ));
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(RunnerOutput::usage(
                "invalid --dae0peer-mac: each octet must have two hex digits",
            ));
        }
        mac[index] = u8::from_str_radix(part, 16)
            .map_err(|err| RunnerOutput::usage(format!("invalid --dae0peer-mac: {err}")))?;
    }
    if mac == [0; 6] {
        return Err(RunnerOutput::usage(
            "invalid --dae0peer-mac: must be non-zero",
        ));
    }
    Ok(mac)
}

fn push_check(
    checks: &mut Vec<Value>,
    name: &str,
    passed: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &str,
) {
    if !passed {
        blockers.push(blocker.to_owned());
    }
    checks.push(json!({
        "name": name,
        "status": if passed { "pass" } else { "fail" },
        "detail": detail,
        "blocker": if passed { Value::Null } else { Value::String(blocker.to_owned()) },
    }));
}

fn tmp_root_allowed(path: &Path) -> bool {
    path.is_absolute()
        && path
            .parent()
            .map(|parent| parent == Path::new("/tmp"))
            .unwrap_or(false)
}

fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(command);
            candidate.is_file()
        })
    })
}

fn iface_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn iface_exists(iface: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", iface])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn iface_leftovers(iface: &str) -> Vec<String> {
    if iface_exists(iface) {
        vec![format!("iface:{iface}")]
    } else {
        Vec::new()
    }
}

struct CommandSpec<'a> {
    program: &'a str,
    args: Vec<&'a str>,
}

impl<'a> CommandSpec<'a> {
    fn new(program: &'a str, args: &[&'a str]) -> Self {
        Self {
            program,
            args: args.to_vec(),
        }
    }
}

fn run_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> bool {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    steps.push(json!({
        "name": name,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    }));
    status == "pass"
}

fn run_observation_step(steps: &mut Vec<Value>, name: &str, spec: CommandSpec<'_>) -> Value {
    let output = Command::new(spec.program).args(&spec.args).output();
    let (status, code, stdout, stderr) = command_output(output);
    let value = json!({
        "name": name,
        "status": status,
        "program": spec.program,
        "args": spec.args,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    });
    steps.push(value.clone());
    value
}

fn command_output(
    output: std::io::Result<std::process::Output>,
) -> (&'static str, Option<i32>, String, String) {
    match output {
        Ok(output) => (
            if output.status.success() {
                "pass"
            } else {
                "fail"
            },
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ),
        Err(err) => ("fail", None, String::new(), err.to_string()),
    }
}

fn mac_string(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
