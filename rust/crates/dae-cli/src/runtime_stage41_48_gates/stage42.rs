use super::utils::*;
use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage42Options {
    root: PathBuf,
    source_object: PathBuf,
    param_object: PathBuf,
    pub(super) execute_smoke: bool,
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
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
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

pub(super) fn stage42_report(opts: &Stage42Options) -> Value {
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
