use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use dae_ebpf_support::{
    DAE_PARAM_SYMBOL, DAE_PARAM_SYMBOL_SIZE, DaeParamInput, build_dae_param_payload,
    dae_param_requirements, dae_param_runtime_values_present,
    direct_tc_object_loader_rewrites_param, param_aware_load_admitted,
};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE40_OBJECT: &str = "control/bpf_bpfel.o";
const DEFAULT_STAGE40_TPROXY_PORT: u16 = 12345;
const DEFAULT_STAGE40_CONTROL_PLANE_PID: u32 = 77;
const DEFAULT_STAGE40_DAE0_IFINDEX: u32 = 8;
const DEFAULT_STAGE40_DAE_NETNS_ID: u32 = 9;
const DEFAULT_STAGE40_DAE0PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 40];

pub(crate) fn run_stage40_param_aware_object_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage40Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage40_report(&opts);
    let admitted = report["param_aware_object_load_admitted"]
        .as_bool()
        .unwrap_or(false);
    let output = format!("{report}\n");
    if opts.require_admission && !admitted {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage40Options {
    object_path: PathBuf,
    stage39_report: Option<PathBuf>,
    tproxy_port: u16,
    control_plane_pid: u32,
    dae0_ifindex: u32,
    dae_netns_id: u32,
    dae0peer_mac: [u8; 6],
    has_bpf_get_current_task: bool,
    require_admission: bool,
}

impl Default for Stage40Options {
    fn default() -> Self {
        Self {
            object_path: PathBuf::from(DEFAULT_STAGE40_OBJECT),
            stage39_report: None,
            tproxy_port: DEFAULT_STAGE40_TPROXY_PORT,
            control_plane_pid: DEFAULT_STAGE40_CONTROL_PLANE_PID,
            dae0_ifindex: DEFAULT_STAGE40_DAE0_IFINDEX,
            dae_netns_id: DEFAULT_STAGE40_DAE_NETNS_ID,
            dae0peer_mac: DEFAULT_STAGE40_DAE0PEER_MAC,
            has_bpf_get_current_task: true,
            require_admission: false,
        }
    }
}

impl Stage40Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--object" => {
                    opts.object_path = PathBuf::from(next_value(&mut iter, "stage40 --object")?);
                }
                "--stage39-report" => {
                    opts.stage39_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage40 --stage39-report",
                    )?));
                }
                "--tproxy-port" => {
                    opts.tproxy_port =
                        parse_port(&next_value(&mut iter, "stage40 --tproxy-port")?)?;
                }
                "--control-plane-pid" => {
                    opts.control_plane_pid = parse_u32(
                        &next_value(&mut iter, "stage40 --control-plane-pid")?,
                        "stage40 --control-plane-pid",
                    )?;
                }
                "--dae0-ifindex" => {
                    opts.dae0_ifindex = parse_u32(
                        &next_value(&mut iter, "stage40 --dae0-ifindex")?,
                        "stage40 --dae0-ifindex",
                    )?;
                }
                "--dae-netns-id" => {
                    opts.dae_netns_id = parse_u32(
                        &next_value(&mut iter, "stage40 --dae-netns-id")?,
                        "stage40 --dae-netns-id",
                    )?;
                }
                "--dae0peer-mac" => {
                    opts.dae0peer_mac =
                        parse_mac(&next_value(&mut iter, "stage40 --dae0peer-mac")?)?;
                }
                "--has-bpf-get-current-task" => opts.has_bpf_get_current_task = true,
                "--no-bpf-get-current-task" => opts.has_bpf_get_current_task = false,
                "--require-admission" => opts.require_admission = true,
                _ if arg.starts_with("--object=") => {
                    opts.object_path = PathBuf::from(value_after_equals(arg, "stage40 --object")?);
                }
                _ if arg.starts_with("--stage39-report=") => {
                    opts.stage39_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage40 --stage39-report",
                    )?));
                }
                _ if arg.starts_with("--tproxy-port=") => {
                    opts.tproxy_port =
                        parse_port(&value_after_equals(arg, "stage40 --tproxy-port")?)?;
                }
                _ if arg.starts_with("--control-plane-pid=") => {
                    opts.control_plane_pid = parse_u32(
                        &value_after_equals(arg, "stage40 --control-plane-pid")?,
                        "stage40 --control-plane-pid",
                    )?;
                }
                _ if arg.starts_with("--dae0-ifindex=") => {
                    opts.dae0_ifindex = parse_u32(
                        &value_after_equals(arg, "stage40 --dae0-ifindex")?,
                        "stage40 --dae0-ifindex",
                    )?;
                }
                _ if arg.starts_with("--dae-netns-id=") => {
                    opts.dae_netns_id = parse_u32(
                        &value_after_equals(arg, "stage40 --dae-netns-id")?,
                        "stage40 --dae-netns-id",
                    )?;
                }
                _ if arg.starts_with("--dae0peer-mac=") => {
                    opts.dae0peer_mac =
                        parse_mac(&value_after_equals(arg, "stage40 --dae0peer-mac")?)?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage40-param-aware-object-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage40_report(opts: &Stage40Options) -> Value {
    let input = DaeParamInput {
        tproxy_port: opts.tproxy_port,
        control_plane_pid: opts.control_plane_pid,
        dae0_ifindex: opts.dae0_ifindex,
        dae_netns_id: opts.dae_netns_id,
        dae0peer_mac: opts.dae0peer_mac,
        has_bpf_get_current_task: opts.has_bpf_get_current_task,
    };
    let payload = build_dae_param_payload(input);
    let param_values_present = dae_param_runtime_values_present(&payload);
    let object_probe = probe_param_symbol(&opts.object_path);
    let object_param_symbol_size_matches = object_probe.size == Some(DAE_PARAM_SYMBOL_SIZE);
    let object_param_symbol_found = object_probe.found && object_param_symbol_size_matches;
    let rust_param_aware_loader_proven = false;
    let direct_tc_loader_rejected = !direct_tc_object_loader_rewrites_param();
    let param_aware_object_load_admitted = param_aware_load_admitted(
        rust_param_aware_loader_proven,
        object_param_symbol_found,
        object_probe.size,
        &payload,
    );

    let mut checks = Vec::new();
    let mut blockers = Vec::new();
    push_check(
        &mut checks,
        "real-dae-object-present",
        opts.object_path.exists(),
        json!({"path": path_string(&opts.object_path)}),
        &mut blockers,
        "stage40 real dae eBPF object is missing",
    );
    push_check(
        &mut checks,
        "object-param-symbol-present",
        object_probe.found,
        object_probe.to_json(),
        &mut blockers,
        "stage40 real dae eBPF object does not expose PARAM symbol",
    );
    push_check(
        &mut checks,
        "object-param-symbol-size-matches",
        object_param_symbol_size_matches,
        json!({
            "expected_size": DAE_PARAM_SYMBOL_SIZE,
            "observed_size": object_probe.size,
            "symbol": DAE_PARAM_SYMBOL,
        }),
        &mut blockers,
        "stage40 real dae eBPF object PARAM symbol size does not match Rust ABI",
    );
    push_check(
        &mut checks,
        "runtime-param-values-present",
        param_values_present,
        json!({
            "tproxy_port_nonzero": payload.tproxy_port_host != 0,
            "control_plane_pid_nonzero": payload.control_plane_pid != 0,
            "dae0_ifindex_nonzero": payload.dae0_ifindex != 0,
            "dae_netns_id_nonzero": payload.dae_netns_id != 0,
            "dae0peer_mac_nonzero": payload.dae0peer_mac != [0; 6],
        }),
        &mut blockers,
        "stage40 PARAM runtime values are incomplete",
    );
    push_check(
        &mut checks,
        "direct-tc-object-loader-rejected-for-active-traffic",
        direct_tc_loader_rejected,
        json!({
            "tc_filter_obj_sets_param": direct_tc_object_loader_rewrites_param(),
            "reason": "tc filter add obj loads the object but does not set CollectionSpec.Variables[PARAM] before load",
        }),
        &mut blockers,
        "stage40 direct tc object loader was not rejected for active traffic",
    );
    push_check(
        &mut checks,
        "rust-param-aware-loader-proven",
        rust_param_aware_loader_proven,
        json!({
            "required": "set PARAM before LoadAndAssign/full object load",
            "implemented_in_rust": rust_param_aware_loader_proven,
        }),
        &mut blockers,
        "stage40 PARAM-aware Rust object loader is not implemented/proven",
    );

    let stage39 = read_report(
        opts.stage39_report.as_deref(),
        "transparent_listener_handoff_smoke_passed",
    );
    push_check(
        &mut checks,
        "stage39-transparent-listener-report-passed",
        !opts.require_admission || stage39.passed,
        json!({
            "path": stage39.path.clone(),
            "status": stage39.status,
            "transparent_listener_handoff_smoke_passed": stage39.passed,
            "blockers": stage39.blockers.clone(),
            "required_for_admission": opts.require_admission,
        }),
        &mut blockers,
        "stage40 admission requires a passed Stage 39 transparent listener report",
    );

    let remaining_blockers = vec![
        "PARAM-aware Rust BPF object loader is not implemented/proven",
        "direct tc filter obj load cannot rewrite PARAM before BPF load",
        "active tproxy TCP UDP DNS traffic evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ];

    json!({
        "name": "stage40-param-aware-object-admission",
        "stage": "stage40",
        "evidence_class": "param-aware-real-bpf-object-loader-admission-gate",
        "read_only": true,
        "blocked": !blockers.is_empty(),
        "blockers": blockers,
        "checks": checks,
        "object_contract": {
            "object_path": path_string(&opts.object_path),
            "required_symbol": DAE_PARAM_SYMBOL,
            "expected_symbol_size": DAE_PARAM_SYMBOL_SIZE,
            "symbol_probe": object_probe.to_json(),
            "go_reference": "control/bpf_utils.go:fullLoadBpfObjects",
            "kernel_reference": "control/kern/tproxy.c:struct dae_param",
            "required_loader_sequence": [
                "setup dae netns",
                "read dae0 ifindex, dae netns id, and dae0peer MAC",
                "pack PARAM with network-order tproxy_port",
                "set CollectionSpec.Variables[PARAM] before object load",
                "load and assign the BPF object",
                "attach tc/cgroup programs"
            ]
        },
        "param_payload": {
            "symbol": payload.symbol,
            "rust_layout_size": payload.rust_layout_size,
            "tproxy_port_host": payload.tproxy_port_host,
            "tproxy_port_big_endian": payload.tproxy_port_big_endian,
            "control_plane_pid": payload.control_plane_pid,
            "dae0_ifindex": payload.dae0_ifindex,
            "dae_netns_id": payload.dae_netns_id,
            "dae0peer_mac": mac_string(payload.dae0peer_mac),
            "has_bpf_get_current_task": payload.has_bpf_get_current_task,
            "padding": payload.padding,
            "runtime_values_present": param_values_present,
            "values_source": "representative-stage40-defaults-or-explicit-cli-args"
        },
        "param_requirements": dae_param_requirements()
            .iter()
            .map(|requirement| json!({
                "field": requirement.field,
                "source": requirement.source,
                "requirement": requirement.requirement,
            }))
            .collect::<Vec<_>>(),
        "stage39_report": {
            "path": stage39.path,
            "status": stage39.status,
            "passed": stage39.passed,
            "blockers": stage39.blockers,
        },
        "direct_tc_object_loader_rejected_for_active_traffic": direct_tc_loader_rejected,
        "rust_param_aware_loader_proven": rust_param_aware_loader_proven,
        "param_aware_object_load_executed": false,
        "param_aware_object_load_admitted": param_aware_object_load_admitted,
        "real_loaded_object_param_rewrite_executed": false,
        "production_name_dae0_dae0peer_attach_executed": false,
        "transparent_listener_handoff_smoke_passed": false,
        "active_tproxy_traffic_executed": false,
        "active_tproxy_traffic_allowed": false,
        "live_candidate_run_allowed": false,
        "default_path_mutated": false,
        "default_switch_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "remaining_blockers": remaining_blockers,
    })
}

#[derive(Debug, Clone)]
struct ParamSymbolProbe {
    found: bool,
    status: String,
    size: Option<usize>,
    symbol: String,
    tool: String,
    detail: String,
}

impl ParamSymbolProbe {
    fn to_json(&self) -> Value {
        json!({
            "found": self.found,
            "status": self.status,
            "size": self.size,
            "symbol": self.symbol,
            "tool": self.tool,
            "detail": self.detail,
        })
    }
}

fn probe_param_symbol(path: &Path) -> ParamSymbolProbe {
    if !path.exists() {
        return ParamSymbolProbe {
            found: false,
            status: "object-missing".to_owned(),
            size: None,
            symbol: DAE_PARAM_SYMBOL.to_owned(),
            tool: "llvm-readelf".to_owned(),
            detail: path_string(path),
        };
    }
    let output = match Command::new("llvm-readelf").arg("-s").arg(path).output() {
        Ok(output) => output,
        Err(err) => {
            return ParamSymbolProbe {
                found: false,
                status: "tool-error".to_owned(),
                size: None,
                symbol: DAE_PARAM_SYMBOL.to_owned(),
                tool: "llvm-readelf".to_owned(),
                detail: err.to_string(),
            };
        }
    };
    if !output.status.success() {
        return ParamSymbolProbe {
            found: false,
            status: "readelf-failed".to_owned(),
            size: None,
            symbol: DAE_PARAM_SYMBOL.to_owned(),
            tool: "llvm-readelf".to_owned(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        };
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.last() == Some(&DAE_PARAM_SYMBOL) && parts.len() >= 8 {
            let size = parts.get(2).and_then(|part| part.parse::<usize>().ok());
            return ParamSymbolProbe {
                found: true,
                status: "found".to_owned(),
                size,
                symbol: DAE_PARAM_SYMBOL.to_owned(),
                tool: "llvm-readelf".to_owned(),
                detail: line.trim().to_owned(),
            };
        }
    }
    ParamSymbolProbe {
        found: false,
        status: "missing".to_owned(),
        size: None,
        symbol: DAE_PARAM_SYMBOL.to_owned(),
        tool: "llvm-readelf".to_owned(),
        detail: "PARAM symbol not found in symbol table".to_owned(),
    }
}

#[derive(Debug, Clone)]
struct PriorReport {
    path: Option<String>,
    status: String,
    passed: bool,
    blockers: Vec<String>,
}

fn read_report(path: Option<&Path>, pass_key: &str) -> PriorReport {
    let Some(path) = path else {
        return PriorReport {
            path: None,
            status: "not-provided".to_owned(),
            passed: false,
            blockers: Vec::new(),
        };
    };
    let path_text = path_string(path);
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return PriorReport {
                path: Some(path_text),
                status: format!("read-error: {err}"),
                passed: false,
                blockers: Vec::new(),
            };
        }
    };
    let value: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(err) => {
            return PriorReport {
                path: Some(path_text),
                status: format!("parse-error: {err}"),
                passed: false,
                blockers: Vec::new(),
            };
        }
    };
    let blockers = value["blockers"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    PriorReport {
        path: Some(path_text),
        status: "loaded".to_owned(),
        passed: value[pass_key].as_bool().unwrap_or(false),
        blockers,
    }
}

fn push_check(
    checks: &mut Vec<Value>,
    name: &str,
    pass: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &str,
) {
    let blocker_value = if pass {
        Value::Null
    } else {
        blockers.push(blocker.to_owned());
        Value::String(blocker.to_owned())
    };
    checks.push(json!({
        "name": name,
        "status": if pass { "pass" } else { "fail" },
        "detail": detail,
        "blocker": blocker_value,
    }));
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {flag}")))
}

fn value_after_equals(arg: &str, flag: &str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {flag}")))
}

fn parse_port(value: &str) -> Result<u16, RunnerOutput> {
    value
        .parse::<u16>()
        .map_err(|err| RunnerOutput::usage(format!("invalid stage40 --tproxy-port: {err}")))
        .and_then(|port| {
            if port == 0 {
                Err(RunnerOutput::usage(
                    "invalid stage40 --tproxy-port: must be non-zero",
                ))
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
            "invalid stage40 --dae0peer-mac: expected six colon-separated hex octets",
        ));
    }
    let mut mac = [0_u8; 6];
    for (index, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(RunnerOutput::usage(
                "invalid stage40 --dae0peer-mac: each octet must have two hex digits",
            ));
        }
        mac[index] = u8::from_str_radix(part, 16)
            .map_err(|err| RunnerOutput::usage(format!("invalid stage40 --dae0peer-mac: {err}")))?;
    }
    if mac == [0; 6] {
        return Err(RunnerOutput::usage(
            "invalid stage40 --dae0peer-mac: must be non-zero",
        ));
    }
    Ok(mac)
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
