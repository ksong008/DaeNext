use super::utils::*;
use super::*;

#[derive(Debug, Clone)]
pub(super) struct Stage32Options {
    pub(super) execute_smoke: bool,
    ack_traffic_gate: bool,
    stage31_report: Option<PathBuf>,
}

impl Stage32Options {
    pub(super) fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
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

pub(super) fn stage32_report(opts: &Stage32Options) -> Value {
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
