use super::utils::*;
use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage31Options {
    root: PathBuf,
    stage30_report: Option<PathBuf>,
    pub(super) execute_smoke: bool,
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
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
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

pub(super) fn stage31_report(opts: &Stage31Options) -> Value {
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
