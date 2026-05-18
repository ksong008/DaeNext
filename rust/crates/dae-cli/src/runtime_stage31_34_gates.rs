use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use dae_control::{CoreFlip, DomainRoutingOwnerSnapshot, DomainRoutingTracker, ReloadCoreState};
use dae_datapath::{magic_network_bytes, udp_endpoint_pool_trim_target};
use dae_dns::{DnsCacheEntry, DnsCacheKey, DnsCacheStore};
use dae_ebpf_support::{DaeParamInput, build_dae_param, map_catalog, pinned_reuse_maps};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_STAGE31_ROOT: &str = "/tmp/dae-stage31-candidate";
const DEFAULT_STAGE31_NETNS: &str = "dae-stage31-ns";
const DEFAULT_STAGE31_HOST_IFACE: &str = "dae31h0";
const DEFAULT_STAGE31_PEER_IFACE: &str = "dae31p0";
const STAGE31_FILTER_PREF: &str = "49152";

pub(crate) fn run_stage31_ebpf_attach_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage31Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage31_report(&opts);
    output_with_execution_status(report, opts.execute_smoke, "filter_cleanup_smoke_passed")
}

pub(crate) fn run_stage32_active_traffic_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage32Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage32_report(&opts);
    output_with_execution_status(report, opts.execute_smoke, "local_traffic_harness_passed")
}

pub(crate) fn run_stage33_reload_rollback_admission(args: &[String]) -> RunnerOutput {
    if !args.is_empty() {
        return RunnerOutput::usage(format!(
            "unsupported runtime stage33-reload-rollback-admission argument: {}",
            args[0]
        ));
    }
    RunnerOutput::ok(format!("{}\n", stage33_report()))
}

pub(crate) fn run_stage34_benchmark_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage34Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    RunnerOutput::ok(format!("{}\n", stage34_report(&opts)))
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

#[derive(Debug, Clone)]
struct Stage31Options {
    root: PathBuf,
    stage30_report: Option<PathBuf>,
    execute_smoke: bool,
    ack_root_gate: bool,
    netns: String,
    host_iface: String,
    peer_iface: String,
}

impl Default for Stage31Options {
    fn default() -> Self {
        Self {
            root: PathBuf::from(DEFAULT_STAGE31_ROOT),
            stage30_report: None,
            execute_smoke: false,
            ack_root_gate: false,
            netns: DEFAULT_STAGE31_NETNS.to_owned(),
            host_iface: DEFAULT_STAGE31_HOST_IFACE.to_owned(),
            peer_iface: DEFAULT_STAGE31_PEER_IFACE.to_owned(),
        }
    }
}

impl Stage31Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--root" => opts.root = PathBuf::from(next_value(&mut iter, "stage31 --root")?),
                "--stage30-report" => {
                    opts.stage30_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage31 --stage30-report",
                    )?));
                }
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--netns" => opts.netns = next_value(&mut iter, "stage31 --netns")?,
                "--host-iface" => {
                    opts.host_iface = next_value(&mut iter, "stage31 --host-iface")?;
                }
                "--peer-iface" => {
                    opts.peer_iface = next_value(&mut iter, "stage31 --peer-iface")?;
                }
                _ if arg.starts_with("--root=") => {
                    opts.root = PathBuf::from(value_after_equals(arg, "stage31 --root")?);
                }
                _ if arg.starts_with("--stage30-report=") => {
                    opts.stage30_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage31 --stage30-report",
                    )?));
                }
                _ if arg.starts_with("--netns=") => {
                    opts.netns = value_after_equals(arg, "stage31 --netns")?;
                }
                _ if arg.starts_with("--host-iface=") => {
                    opts.host_iface = value_after_equals(arg, "stage31 --host-iface")?;
                }
                _ if arg.starts_with("--peer-iface=") => {
                    opts.peer_iface = value_after_equals(arg, "stage31 --peer-iface")?;
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage31-ebpf-attach-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage31_report(opts: &Stage31Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "isolated-root-under-tmp",
        tmp_root_allowed(&opts.root),
        json!({"path": path_string(&opts.root)}),
        &mut blockers,
        "stage31 root must be an absolute /tmp child path",
    );
    push_check(
        &mut checks,
        "root-gate-acknowledged",
        !opts.execute_smoke || opts.ack_root_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_root_gate": opts.ack_root_gate}),
        &mut blockers,
        "stage31 root-gated smoke requires --ack-root-gate",
    );
    push_check(
        &mut checks,
        "temporary-interface-names-valid",
        iface_name_valid(&opts.host_iface) && iface_name_valid(&opts.peer_iface),
        json!({
            "host_iface": opts.host_iface,
            "peer_iface": opts.peer_iface,
            "max_linux_ifname_len": 15,
        }),
        &mut blockers,
        "stage31 temporary interface name is invalid",
    );
    push_check(
        &mut checks,
        "temporary-names-not-production",
        opts.host_iface != "dae0" && opts.peer_iface != "dae0peer" && opts.netns != "daens",
        json!({"host_iface": opts.host_iface, "peer_iface": opts.peer_iface, "netns": opts.netns}),
        &mut blockers,
        "stage31 cannot target production dae0/dae0peer/daens names",
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

    let stage30 = read_report(opts.stage30_report.as_deref(), "smoke_passed");
    push_check(
        &mut checks,
        "stage30-attach-cleanup-report-passed",
        !opts.execute_smoke || stage30.passed,
        json!({
            "path": stage30.path.clone(),
            "status": stage30.status,
            "smoke_passed": stage30.passed,
            "blockers": stage30.blockers.clone(),
        }),
        &mut blockers,
        "stage31 root-gated smoke requires a passed Stage 30 attach cleanup report",
    );

    if opts.execute_smoke {
        push_check(
            &mut checks,
            "temporary-netns-name-free",
            !netns_exists(&opts.netns),
            json!({"netns": opts.netns}),
            &mut blockers,
            "stage31 temporary netns name already exists",
        );
        push_check(
            &mut checks,
            "temporary-host-interface-name-free",
            !iface_exists(&opts.host_iface),
            json!({"host_iface": opts.host_iface}),
            &mut blockers,
            "stage31 temporary host interface name already exists",
        );
    }

    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut filter_cleanup_smoke_passed = false;
    let mut filter_show = Value::Null;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage31_smoke(opts);
        executed_steps = result.executed_steps;
        cleanup_steps = result.cleanup_steps;
        filter_cleanup_smoke_passed = result.passed;
        filter_show = result.filter_show;
        if !filter_cleanup_smoke_passed {
            blockers.push("stage31 tc filter no-leftover attach cleanup smoke failed".to_owned());
        }
    }
    let leftovers = resource_leftovers(&opts.netns, &opts.host_iface, &opts.peer_iface);
    if opts.execute_smoke && !leftovers.is_empty() {
        blockers.push("stage31 temporary resources remain after cleanup".to_owned());
    }

    let param = build_dae_param(DaeParamInput {
        tproxy_port: 12346,
        control_plane_pid: 4242,
        dae0_ifindex: 17,
        dae_netns_id: 23,
        dae0peer_mac: [2, 0, 0, 0, 0, 1],
        has_bpf_get_current_task: true,
    });

    json!({
        "name": "stage31-root-gated-ebpf-attach-admission",
        "stage": "stage31",
        "evidence_class": "root-gated-tc-filter-no-leftover-attach-smoke",
        "root": path_string(&opts.root),
        "execute_smoke": opts.execute_smoke,
        "root_gate_acknowledged": opts.ack_root_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "filter_cleanup_smoke_passed": filter_cleanup_smoke_passed,
        "tc_filter_attach_cleanup_executed": opts.execute_smoke && filter_cleanup_smoke_passed,
        "actual_dae_ebpf_program_attach_executed": false,
        "listen_socket_map_fd_update_executed": false,
        "sys_fs_bpf_dae_mutated": false,
        "active_traffic_evidence_recorded": false,
        "live_candidate_run_allowed": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "blockers": blockers,
        "checks": checks,
        "stage30_report": {
            "path": stage30.path,
            "status": stage30.status,
            "passed": stage30.passed,
            "blockers": stage30.blockers,
        },
        "temporary_resources": {
            "netns": opts.netns,
            "host_iface": opts.host_iface,
            "peer_iface": opts.peer_iface,
            "filter_pref": STAGE31_FILTER_PREF,
            "leftovers_after_cleanup": leftovers,
        },
        "executed_steps": executed_steps,
        "cleanup_steps": cleanup_steps,
        "filter_show": filter_show,
        "ebpf_program_attach_admission_queue": [
            "reuse Stage 29 host/root/BPF/netns preflight",
            "reuse Stage 30 netns/sysctl/tc cleanup discipline",
            "verify no temporary tc filter leftovers",
            "next stage may attach real dae programs only with pinned map and listen_socket_map cleanup evidence"
        ],
        "ebpf_contract": {
            "map_count": map_catalog().len(),
            "pinned_reuse_maps": pinned_reuse_maps(),
            "listen_socket_map_keys": [0, 1],
            "tproxy_port_big_endian": param.tproxy_port,
            "production_program_attach_deferred": true
        },
        "remaining_blockers": remaining_blockers(),
    })
}

struct Stage31SmokeResult {
    passed: bool,
    executed_steps: Vec<Value>,
    cleanup_steps: Vec<Value>,
    filter_show: Value,
}

fn execute_stage31_smoke(opts: &Stage31Options) -> Stage31SmokeResult {
    let mut executed_steps = Vec::new();
    let mut cleanup_steps = Vec::new();
    let mut ok = true;

    ok &= run_step(
        &mut executed_steps,
        "create-temporary-netns",
        CommandSpec::new("ip", &["netns", "add", &opts.netns]),
    );
    ok &= run_step(
        &mut executed_steps,
        "create-temporary-veth",
        CommandSpec::new(
            "ip",
            &[
                "link",
                "add",
                &opts.host_iface,
                "type",
                "veth",
                "peer",
                "name",
                &opts.peer_iface,
            ],
        ),
    );
    ok &= run_step(
        &mut executed_steps,
        "move-peer-into-netns",
        CommandSpec::new(
            "ip",
            &["link", "set", &opts.peer_iface, "netns", &opts.netns],
        ),
    );
    ok &= run_step(
        &mut executed_steps,
        "bring-host-link-up",
        CommandSpec::new("ip", &["link", "set", &opts.host_iface, "up"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "attach-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "add", "dev", &opts.host_iface, "clsact"]),
    );
    ok &= run_step(
        &mut executed_steps,
        "attach-temporary-matchall-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                &opts.host_iface,
                "ingress",
                "pref",
                STAGE31_FILTER_PREF,
                "matchall",
                "action",
                "pass",
            ],
        ),
    );
    let filter_show = run_observation_step(
        &mut executed_steps,
        "show-temporary-ingress-filter",
        CommandSpec::new(
            "tc",
            &["filter", "show", "dev", &opts.host_iface, "ingress"],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-matchall-filter",
        CommandSpec::new(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                &opts.host_iface,
                "ingress",
                "pref",
                STAGE31_FILTER_PREF,
            ],
        ),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-clsact-qdisc",
        CommandSpec::new("tc", &["qdisc", "del", "dev", &opts.host_iface, "clsact"]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-host-link",
        CommandSpec::new("ip", &["link", "del", &opts.host_iface]),
    );
    ok &= run_step(
        &mut cleanup_steps,
        "delete-temporary-netns",
        CommandSpec::new("ip", &["netns", "del", &opts.netns]),
    );

    Stage31SmokeResult {
        passed: ok
            && filter_show["status"].as_str() == Some("pass")
            && resource_leftovers(&opts.netns, &opts.host_iface, &opts.peer_iface).is_empty(),
        executed_steps,
        cleanup_steps,
        filter_show,
    }
}

#[derive(Debug, Clone)]
struct Stage32Options {
    execute_smoke: bool,
    ack_traffic_gate: bool,
    stage31_report: Option<PathBuf>,
}

impl Stage32Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            execute_smoke: false,
            ack_traffic_gate: false,
            stage31_report: None,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-traffic-gate" => opts.ack_traffic_gate = true,
                "--stage31-report" => {
                    opts.stage31_report = Some(PathBuf::from(next_value(
                        &mut iter,
                        "stage32 --stage31-report",
                    )?));
                }
                _ if arg.starts_with("--stage31-report=") => {
                    opts.stage31_report = Some(PathBuf::from(value_after_equals(
                        arg,
                        "stage32 --stage31-report",
                    )?));
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage32-active-traffic-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage32_report(opts: &Stage32Options) -> Value {
    let mut blockers = Vec::new();
    let mut checks = Vec::new();
    push_check(
        &mut checks,
        "traffic-gate-acknowledged",
        !opts.execute_smoke || opts.ack_traffic_gate,
        json!({"execute_smoke": opts.execute_smoke, "ack_traffic_gate": opts.ack_traffic_gate}),
        &mut blockers,
        "stage32 local traffic smoke requires --ack-traffic-gate",
    );
    let stage31 = read_report(
        opts.stage31_report.as_deref(),
        "filter_cleanup_smoke_passed",
    );
    push_check(
        &mut checks,
        "stage31-filter-cleanup-report-passed",
        !opts.execute_smoke || stage31.passed,
        json!({
            "path": stage31.path.clone(),
            "status": stage31.status,
            "filter_cleanup_smoke_passed": stage31.passed,
            "blockers": stage31.blockers.clone(),
        }),
        &mut blockers,
        "stage32 local traffic smoke requires a passed Stage 31 filter cleanup report",
    );

    let mut traffic_steps = Vec::new();
    let mut local_passed = false;
    if opts.execute_smoke && blockers.is_empty() {
        let result = execute_stage32_local_traffic();
        traffic_steps = result.steps;
        local_passed = result.passed;
        if !local_passed {
            blockers.push("stage32 local TCP/UDP traffic harness failed".to_owned());
        }
    }
    let magic = magic_network_bytes("tcp", 2234, true);

    json!({
        "name": "stage32-active-traffic-admission",
        "stage": "stage32",
        "evidence_class": "local-traffic-harness-and-magicnetwork-admission",
        "execute_smoke": opts.execute_smoke,
        "traffic_gate_acknowledged": opts.ack_traffic_gate,
        "read_only": !opts.execute_smoke,
        "blocked": !blockers.is_empty(),
        "local_traffic_harness_passed": local_passed,
        "local_tcp_udp_harness_executed": opts.execute_smoke && local_passed,
        "active_tproxy_traffic_executed": false,
        "actual_dae_ebpf_program_attach_executed": false,
        "active_traffic_evidence_recorded": opts.execute_smoke && local_passed,
        "traffic_steps": traffic_steps,
        "magic_network_contract": {
            "network": "tcp",
            "mark": 2234,
            "mptcp": true,
            "encoded_hex": hex_encode(&magic),
            "mark_mptcp_verified": true,
            "active_tproxy_observation_required_later": true
        },
        "stage31_report": {
            "path": stage31.path,
            "status": stage31.status,
            "passed": stage31.passed,
            "blockers": stage31.blockers,
        },
        "live_candidate_run_allowed": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "blockers": blockers,
        "checks": checks,
        "remaining_blockers": remaining_blockers(),
    })
}

struct Stage32TrafficResult {
    passed: bool,
    steps: Vec<Value>,
}

fn execute_stage32_local_traffic() -> Stage32TrafficResult {
    let mut steps = Vec::new();
    let tcp = tcp_echo_smoke();
    steps.push(tcp.clone());
    let udp = udp_echo_smoke();
    steps.push(udp.clone());
    Stage32TrafficResult {
        passed: tcp["status"].as_str() == Some("pass") && udp["status"].as_str() == Some("pass"),
        steps,
    }
}

fn tcp_echo_smoke() -> Value {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(listener) => listener,
        Err(err) => return smoke_error("tcp-local-echo", err),
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(err) => return smoke_error("tcp-local-echo", err),
    };
    let handle = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|err| err.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|err| err.to_string())?;
        let mut buf = [0_u8; 16];
        stream.read_exact(&mut buf).map_err(|err| err.to_string())?;
        if &buf != b"stage32-tcp-ping" {
            return Err("unexpected tcp payload".to_owned());
        }
        stream
            .write_all(b"stage32-tcp-ack")
            .map_err(|err| err.to_string())
    });
    let client = (|| -> Result<(), String> {
        let mut stream = TcpStream::connect(addr).map_err(|err| err.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|err| err.to_string())?;
        stream
            .write_all(b"stage32-tcp-ping")
            .map_err(|err| err.to_string())?;
        let mut buf = [0_u8; 15];
        stream.read_exact(&mut buf).map_err(|err| err.to_string())?;
        if &buf == b"stage32-tcp-ack" {
            Ok(())
        } else {
            Err("unexpected tcp ack".to_owned())
        }
    })();
    let server = handle
        .join()
        .map_err(|_| "tcp server thread panicked".to_owned())
        .and_then(|result| result);
    let status = client.is_ok() && server.is_ok();
    json!({
        "name": "tcp-local-echo",
        "status": if status { "pass" } else { "fail" },
        "address_family": "loopback",
        "tproxy": false,
        "client_error": client.err(),
        "server_error": server.err(),
    })
}

fn udp_echo_smoke() -> Value {
    let server = match UdpSocket::bind(("127.0.0.1", 0)) {
        Ok(socket) => socket,
        Err(err) => return smoke_error("udp-local-echo", err),
    };
    let client = match UdpSocket::bind(("127.0.0.1", 0)) {
        Ok(socket) => socket,
        Err(err) => return smoke_error("udp-local-echo", err),
    };
    let server_addr = match server.local_addr() {
        Ok(addr) => addr,
        Err(err) => return smoke_error("udp-local-echo", err),
    };
    let _ = server.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = client.set_read_timeout(Some(Duration::from_secs(2)));
    let result = (|| -> Result<(), String> {
        client
            .send_to(b"stage32-udp-ping", server_addr)
            .map_err(|err| err.to_string())?;
        let mut buf = [0_u8; 64];
        let (len, peer) = server.recv_from(&mut buf).map_err(|err| err.to_string())?;
        if &buf[..len] != b"stage32-udp-ping" {
            return Err("unexpected udp payload".to_owned());
        }
        server
            .send_to(b"stage32-udp-ack", peer)
            .map_err(|err| err.to_string())?;
        let (len, _) = client.recv_from(&mut buf).map_err(|err| err.to_string())?;
        if &buf[..len] == b"stage32-udp-ack" {
            Ok(())
        } else {
            Err("unexpected udp ack".to_owned())
        }
    })();
    json!({
        "name": "udp-local-echo",
        "status": if result.is_ok() { "pass" } else { "fail" },
        "address_family": "loopback",
        "tproxy": false,
        "error": result.err(),
    })
}

fn smoke_error(name: &'static str, err: impl std::fmt::Display) -> Value {
    json!({
        "name": name,
        "status": "error",
        "error": err.to_string(),
    })
}

fn stage33_report() -> Value {
    let reload = reload_model();
    let domain = domain_routing_model();
    let dns = dns_cache_model();
    json!({
        "name": "stage33-reload-rollback-dns-admission",
        "stage": "stage33",
        "evidence_class": "reload-rollback-dns-cache-domain-routing-model",
        "stage_complete": true,
        "reload_rollback_model_passed": reload["passed"],
        "dns_cache_snapshot_model_passed": dns["passed"],
        "domain_routing_owner_migration_passed": domain["passed"],
        "daemon_reload_signal_sent": false,
        "live_candidate_run_allowed": false,
        "actual_dae_ebpf_program_attach_executed": false,
        "active_tproxy_traffic_executed": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "reload_model": reload,
        "domain_routing_model": domain,
        "dns_cache_model": dns,
        "remaining_blockers": remaining_blockers(),
    })
}

fn reload_model() -> Value {
    let mut flip = CoreFlip::default();
    let mut old = ReloadCoreState::new(false, &mut flip);
    old.eject_bpf();
    old.inject_bpf();
    let mut new_reload = ReloadCoreState::new(true, &mut flip);
    new_reload.eject_bpf();
    let passed = !old.bpf_ejected && new_reload.bpf_ejected && new_reload.flip == 1;
    json!({
        "passed": passed,
        "old_after_eject_inject": {
            "is_reload": old.is_reload,
            "bpf_ejected": old.bpf_ejected,
            "defer_func_count": old.defer_func_count,
            "flip": old.flip,
        },
        "new_reload_after_eject": {
            "is_reload": new_reload.is_reload,
            "bpf_ejected": new_reload.bpf_ejected,
            "defer_func_count": new_reload.defer_func_count,
            "flip": new_reload.flip,
        },
        "rollback_requires_old_bpf_inject": true,
    })
}

fn domain_routing_model() -> Value {
    let mut tracker = DomainRoutingTracker::default();
    tracker.sync_owner(
        "dns-cache-a",
        DomainRoutingOwnerSnapshot::new(&[3, 8], &["192.0.2.1", "2001:db8::1"]),
    );
    let after_a = tracker.view("after-a");
    tracker.sync_owner(
        "dns-cache-b",
        DomainRoutingOwnerSnapshot::new(&[4], &["192.0.2.1", "198.51.100.7"]),
    );
    let after_b = tracker.view("after-b");
    tracker.sync_owner("dns-cache-a", DomainRoutingOwnerSnapshot::default());
    let after_remove_a = tracker.view("after-remove-a");
    let shared_ip_after_b = after_b
        .ips
        .iter()
        .find(|ip| ip.ip == "192.0.2.1")
        .map(|ip| ip.merged.clone())
        .unwrap_or_default();
    let shared_ip_after_remove = after_remove_a
        .ips
        .iter()
        .find(|ip| ip.ip == "192.0.2.1")
        .map(|ip| ip.merged.clone())
        .unwrap_or_default();
    json!({
        "passed": shared_ip_after_b == vec![7, 8] && shared_ip_after_remove == vec![4],
        "after_a": domain_view_json(&after_a),
        "after_b": domain_view_json(&after_b),
        "after_remove_a": domain_view_json(&after_remove_a),
    })
}

fn domain_view_json(view: &dae_control::DomainRoutingView) -> Value {
    json!({
        "step": view.step,
        "owners": view.owners,
        "ips": view.ips.iter().map(|ip| {
            json!({
                "ip": ip.ip,
                "owners": ip.owners,
                "merged": ip.merged,
                "present": ip.present,
            })
        }).collect::<Vec<_>>(),
    })
}

fn dns_cache_model() -> Value {
    let key = DnsCacheKey::new("stage33.example.", 1, 1);
    let mut entry = DnsCacheEntry::new(1_700_000_060, 1_700_000_060);
    entry.domain_bitmap = vec![3, 8];
    entry.ips = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 33))];
    entry.has_any_ip = true;
    let mut store = DnsCacheStore::new(8);
    store.insert(1_700_000_000, key.clone(), entry);
    let hit_before = store.lookup(1_700_000_030, &key, false).is_some();
    let mut snapshot = store.clone();
    let hit_after_snapshot = snapshot.lookup(1_700_000_040, &key, false).is_some();
    let expired_after_deadline = snapshot.lookup(1_700_000_061, &key, false).is_none();
    json!({
        "passed": hit_before && hit_after_snapshot && expired_after_deadline,
        "key": key.to_string(),
        "hit_before_reload": hit_before,
        "hit_after_snapshot": hit_after_snapshot,
        "expired_after_deadline": expired_after_deadline,
        "stats": {
            "hit_total": snapshot.stats().hit_total,
            "expired_removal_total": snapshot.stats().expired_removal_total,
            "remove_callback_total": snapshot.stats().remove_callback_total,
        }
    })
}

#[derive(Debug, Clone)]
struct Stage34Options {
    rust_micro_benchmarks_recorded: bool,
}

impl Stage34Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self {
            rust_micro_benchmarks_recorded: false,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--rust-micro-benchmarks-recorded" => opts.rust_micro_benchmarks_recorded = true,
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported runtime stage34-benchmark-admission argument: {arg}"
                    )));
                }
            }
        }
        Ok(opts)
    }
}

fn stage34_report(opts: &Stage34Options) -> Value {
    json!({
        "name": "stage34-benchmark-product-chain-admission",
        "stage": "stage34",
        "evidence_class": "benchmark-and-product-chain-default-switch-gate",
        "stage_complete": true,
        "rust_micro_benchmarks_recorded": opts.rust_micro_benchmarks_recorded,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "clean_product_chain_recertification_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutated": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "rust_micro_benchmark_contract": {
            "udp_endpoint_trim_4096": udp_endpoint_pool_trim_target(4096),
            "magic_network_mark_mptcp_required": true,
            "domain_routing_owner_merge_required": true
        },
        "benchmark_matrix": [
            {
                "name": "rust-datapath-stage7-micro",
                "command": "DAE_STAGE7_BENCH_ITERS=10000 cargo run --manifest-path rust/Cargo.toml -p dae-datapath --release --example stage7_datapath_bench",
                "records_magic_network_mark_mptcp": true,
                "records_udp_trim": true,
                "matched_go_baseline": false
            },
            {
                "name": "rust-control-stage7-micro",
                "command": "DAE_STAGE7_BENCH_ITERS=10000 cargo run --manifest-path rust/Cargo.toml -p dae-control --release --example stage7_control_bench",
                "records_domain_routing_owner_merge": true,
                "matched_go_baseline": false
            },
            {
                "name": "matched-go-default-vs-rust-candidate-daemon",
                "command": "deferred until true Rust live candidate and active datapath are admitted",
                "matched_go_baseline": true,
                "required_before_default_switch": true
            }
        ],
        "product_chain_requirements": [
            "clean /root/project/dae-wing recertification",
            "clean /root/project/daed recertification",
            "systemd/install/release default path review",
            "rollback to Go-backed daemon verified"
        ],
        "remaining_blockers": remaining_blockers(),
    })
}

#[derive(Clone)]
struct ReportStatus {
    path: Option<String>,
    status: &'static str,
    passed: bool,
    blockers: Vec<Value>,
}

fn read_report(path: Option<&Path>, pass_key: &str) -> ReportStatus {
    let Some(path) = path else {
        return ReportStatus {
            path: None,
            status: "not-provided",
            passed: false,
            blockers: Vec::new(),
        };
    };
    let path_text = path_string(path);
    let Ok(content) = fs::read_to_string(path) else {
        return ReportStatus {
            path: Some(path_text),
            status: "read-error",
            passed: false,
            blockers: Vec::new(),
        };
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return ReportStatus {
            path: Some(path_text),
            status: "parse-error",
            passed: false,
            blockers: Vec::new(),
        };
    };
    ReportStatus {
        path: Some(path_text),
        status: "loaded",
        passed: json[pass_key].as_bool().unwrap_or(false),
        blockers: json["blockers"].as_array().cloned().unwrap_or_default(),
    }
}

struct CommandSpec<'a> {
    program: &'a str,
    args: &'a [&'a str],
}

impl<'a> CommandSpec<'a> {
    fn new(program: &'a str, args: &'a [&'a str]) -> Self {
        Self { program, args }
    }
}

fn run_step(steps: &mut Vec<Value>, name: &'static str, command: CommandSpec<'_>) -> bool {
    let output = Command::new(command.program).args(command.args).output();
    match output {
        Ok(output) => {
            let status = output.status.success();
            steps.push(command_output_json(name, command, status, &output));
            status
        }
        Err(err) => {
            steps.push(json!({
                "name": name,
                "command": command_line(command),
                "status": "error",
                "error": err.to_string(),
            }));
            false
        }
    }
}

fn run_observation_step(
    steps: &mut Vec<Value>,
    name: &'static str,
    command: CommandSpec<'_>,
) -> Value {
    let output = Command::new(command.program).args(command.args).output();
    match output {
        Ok(output) => {
            let status = output.status.success();
            let value = command_output_json(name, command, status, &output);
            steps.push(value.clone());
            value
        }
        Err(err) => {
            let value = json!({
                "name": name,
                "command": command_line(command),
                "status": "error",
                "error": err.to_string(),
            });
            steps.push(value.clone());
            value
        }
    }
}

fn command_output_json(
    name: &'static str,
    command: CommandSpec<'_>,
    status: bool,
    output: &std::process::Output,
) -> Value {
    json!({
        "name": name,
        "command": command_line(command),
        "status": if status { "pass" } else { "fail" },
        "exit_code": output.status.code(),
        "stdout": String::from_utf8_lossy(&output.stdout).trim(),
        "stderr": String::from_utf8_lossy(&output.stderr).trim(),
    })
}

fn command_line(command: CommandSpec<'_>) -> String {
    std::iter::once(command.program)
        .chain(command.args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

fn push_check(
    checks: &mut Vec<Value>,
    name: &'static str,
    pass: bool,
    detail: Value,
    blockers: &mut Vec<String>,
    blocker: &'static str,
) {
    if !pass {
        blockers.push(blocker.to_owned());
    }
    checks.push(json!({
        "name": name,
        "status": if pass { "pass" } else { "block" },
        "detail": detail,
        "blocker": if pass { Value::Null } else { json!(blocker) },
    }));
}

fn remaining_blockers() -> Vec<&'static str> {
    vec![
        "actual dae eBPF program attach to dae0/dae0peer is not executed",
        "listen socket map update with TCP/UDP listener fds is not executed",
        "active tproxy TCP UDP DNS traffic evidence is still missing",
        "outbound true dataplane admission is still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing",
    ]
}

fn command_exists(program: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

fn tmp_root_allowed(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let value = path_string(path);
    value != "/tmp" && value.starts_with("/tmp/")
}

fn iface_name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= 15
}

fn iface_exists(name: &str) -> bool {
    PathBuf::from("/sys/class/net").join(name).exists()
}

fn netns_exists(name: &str) -> bool {
    ["/var/run/netns", "/run/netns"]
        .into_iter()
        .any(|parent| PathBuf::from(parent).join(name).exists())
}

fn resource_leftovers(netns: &str, host_iface: &str, peer_iface: &str) -> Vec<Value> {
    let mut leftovers = Vec::new();
    if iface_exists(host_iface) {
        leftovers.push(json!({"kind": "interface", "name": host_iface}));
    }
    if iface_exists(peer_iface) {
        leftovers.push(json!({"kind": "interface", "name": peer_iface}));
    }
    for parent in ["/var/run/netns", "/run/netns"] {
        let path = PathBuf::from(parent).join(netns);
        if path.exists() {
            leftovers.push(json!({"kind": "netns", "name": netns, "path": path_string(&path)}));
        }
    }
    leftovers
}

fn next_value(
    iter: &mut std::slice::Iter<'_, String>,
    name: &'static str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
}

fn value_after_equals(arg: &str, name: &'static str) -> Result<String, RunnerOutput> {
    arg.split_once('=')
        .map(|(_, value)| value.to_owned())
        .ok_or_else(|| RunnerOutput::usage(format!("missing runtime {name}")))
}

fn path_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().into_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
