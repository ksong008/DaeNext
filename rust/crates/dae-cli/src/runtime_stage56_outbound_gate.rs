use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport, UdpDirectPacketConn,
    UdpDirectSocketOptions, UdpDirectSocketReport, bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::socks5::{self, Socks5Address, handshake, udp_packet};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_ASSOCIATE_TARGET: &str = "0.0.0.0:0";
const DEFAULT_PACKET_TARGET: &str = "stage56.example:5353";
const DEFAULT_USERNAME: &str = "user";
const DEFAULT_PASSWORD: &str = "pass";
const DEFAULT_PAYLOAD: &[u8] = b"stage56-socks5-udp-ping";
const DEFAULT_RESPONSE: &[u8] = b"stage56-socks5-udp-ack";

pub(crate) fn run_stage56_socks5_udp_associate_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage56Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage56_report(&opts);
    let passed = report["socks5_udp_smoke_passed"].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage56Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    associate_target: String,
    packet_target: String,
    username: String,
    password: String,
    payload: Vec<u8>,
    response: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage56Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            associate_target: DEFAULT_ASSOCIATE_TARGET.to_owned(),
            packet_target: DEFAULT_PACKET_TARGET.to_owned(),
            username: DEFAULT_USERNAME.to_owned(),
            password: DEFAULT_PASSWORD.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            response: DEFAULT_RESPONSE.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage56Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage56 --benchmark-iters")?, arg)?;
                }
                "--associate-target" => {
                    opts.associate_target = next_value(&mut iter, "stage56 --associate-target")?;
                }
                "--packet-target" => {
                    opts.packet_target = next_value(&mut iter, "stage56 --packet-target")?;
                }
                "--username" => opts.username = next_value(&mut iter, "stage56 --username")?,
                "--password" => opts.password = next_value(&mut iter, "stage56 --password")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage56 --payload")?.into_bytes();
                }
                "--response" => {
                    opts.response = next_value(&mut iter, "stage56 --response")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage56 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage56 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--associate-target=") => {
                    opts.associate_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--packet-target=") => {
                    opts.packet_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--username=") => {
                    opts.username = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--password=") => {
                    opts.password = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--payload=") => {
                    opts.payload = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--response=") => {
                    opts.response = arg.split_once('=').unwrap().1.as_bytes().to_vec();
                }
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(arg.split_once('=').unwrap().1, "--so-mark")?;
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    let timeout_ms = parse_u64(arg.split_once('=').unwrap().1, "--timeout-ms")?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage56 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage56 --benchmark-iters must be greater than zero",
            ));
        }
        Ok(opts)
    }
}

fn stage56_report(opts: &Stage56Options) -> Value {
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let response_ascii = String::from_utf8_lossy(&opts.response).to_string();
    let mut report = json!({
        "name": "stage56-socks5-udp-associate-dataplane-admission",
        "stage": "stage56",
        "evidence_class": "opt-in-protocol-udp-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_tcp_true_dataplane_admitted": true,
        "socks5_udp_smoke_passed": false,
        "socks5_udp_associate_admitted": false,
        "socks5_protocol_true_dataplane_admitted": false,
        "socks5_auth_observed": false,
        "socks5_udp_associate_request_observed": false,
        "socks5_udp_packet_wrap_unwrap_recorded": false,
        "socks5_udp_payload_roundtrip_recorded": false,
        "socks5_tcp_control_connection_retained": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "socks5_udp_contract": {
            "protocol": "SOCKS5",
            "scope": "UDP ASSOCIATE loopback true dataplane",
            "tcp_control_proxy": null,
            "associate_target": opts.associate_target,
            "packet_target": opts.packet_target,
            "username_password_auth_required": true,
            "command": "UDP ASSOCIATE",
            "bind_reply_uses_unspecified_ip": true,
            "unspecified_bind_falls_back_to_proxy_host": true,
            "payload_ascii": payload_ascii,
            "response_ascii": response_ascii,
            "tcp_control_connection_must_be_retained": true,
            "default_go_path_preserved": true
        },
        "tcp_control_underlay": {
            "requested_mark": opts.so_mark,
            "requested_mptcp": opts.mptcp,
            "listener": null,
            "last_dial_report": null,
            "so_mark_observed": false,
            "mptcp_status_recorded": false,
            "mptcp_protocol_observed": false
        },
        "udp_underlay_socket": {
            "requested_mark": opts.so_mark,
            "mptcp_not_applicable": true,
            "last_socket_report": null,
            "so_mark_observed": false
        },
        "server_observation": null,
        "benchmark": {
            "benchmark_recorded": false,
            "iterations": opts.benchmark_iters,
            "elapsed_ns": null,
            "ns_per_udp_associate": null,
            "scope": "SOCKS5 UDP ASSOCIATE plus TCP control retention plus UDP packet roundtrip over SO_MARKed Rust UDP socket",
            "go_matched_default_daemon_baseline_recorded": false,
            "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
        },
        "protocol_matrix": {
            "socks5_tcp_true_dataplane_admitted": true,
            "socks5_udp_associate_admitted": false,
            "socks5_protocol_true_dataplane_admitted": false,
            "http_connect_true_dataplane_admitted": false,
            "shadowsocks_aead_true_dataplane_admitted": false,
            "vmess_vless_trojan_shared_transport_admitted": false,
            "quic_h3_session_protocols_admitted": false
        },
        "remaining_blockers": [
            "HTTP/HTTPS, Shadowsocks/SS2022, Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS, and shared transport true dataplanes are still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
        "validation_commands": [
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage56/socks5_udp_associate_dataplane_admission.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage56_socks5_udp_associate_dataplane_gate.json",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage56 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage56 -- --nocapture",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage56-socks5-udp-associate-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
            "git diff --check"
        ],
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage56-item338",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.13",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:27.4",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8",
            "rust/crates/dae-outbound/src/socks5/dataplane.rs",
            "rust/crates/dae-outbound/src/socks5/udp_packet.rs",
            "rust/crates/dae-datapath/src/udp_direct.rs"
        ]
    });

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage56 root-gated smoke requires --ack-root-gate because it attempts SO_MARK on TCP control and UDP associate sockets"
        ]);
        return report;
    }

    match run_stage56_smoke(opts) {
        Ok(outcome) => apply_stage56_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage56Outcome {
    tcp_listener_report: TcpLoopbackListenerReport,
    tcp_last_dial_report: TcpDirectDialReport,
    udp_last_socket_report: UdpDirectSocketReport,
    server_summary: Socks5UdpServerSummary,
    elapsed_ns: u128,
    ns_per_udp_associate: f64,
    exchange_count: usize,
    payload_len: usize,
    response_len: usize,
    last_control_bind: String,
    last_resolved_udp_bind: String,
}

fn run_stage56_smoke(opts: &Stage56Options) -> Result<Stage56Outcome, String> {
    let (proxy_addr, udp_addr, tcp_listener_report, handle) = spawn_socks5_udp_server(opts)?;
    let mut tcp_last_dial_report = None;
    let mut udp_last_socket_report = None;
    let mut last_control_bind = String::new();
    let mut last_resolved_udp_bind = String::new();
    let start = Instant::now();
    for _ in 0..opts.benchmark_iters {
        let mut connected = magic_tcp_connect(
            proxy_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage56 tcp control magic_tcp_connect failed: {err}"))?;
        let control = socks5::udp_associate_control_over_stream(
            &mut connected.stream,
            &proxy_addr.to_string(),
            &opts.associate_target,
            &opts.username,
            &opts.password,
        )
        .map_err(|err| format!("stage56 socks5 udp associate control failed: {err}"))?;
        if control.method != handshake::AUTH_PASSWORD {
            return Err(format!(
                "stage56 socks5 auth method mismatch: {}",
                control.method
            ));
        }
        if control.target != opts.associate_target {
            return Err(format!(
                "stage56 socks5 associate target mismatch: got {}, want {}",
                control.target, opts.associate_target
            ));
        }
        let resolved_udp_bind = resolve_udp_associate_bind(&control.bind, proxy_addr)?;
        if resolved_udp_bind != udp_addr {
            return Err(format!(
                "stage56 resolved udp bind mismatch: got {resolved_udp_bind}, want {udp_addr}"
            ));
        }
        let udp = UdpDirectPacketConn::connect(
            resolved_udp_bind,
            &UdpDirectSocketOptions {
                mark: opts.so_mark,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage56 udp socket connect failed: {err}"))?;
        let wrapped = udp_packet::wrap_target(&opts.packet_target, &opts.payload)
            .map_err(|err| err.to_string())?;
        let response = udp
            .exchange(&wrapped, 2048)
            .map_err(|err| format!("stage56 udp packet exchange failed: {err}"))?;
        let unwrapped = udp_packet::unwrap(&response).map_err(|err| err.to_string())?;
        if unwrapped.target.authority() != opts.packet_target {
            return Err(format!(
                "stage56 response target mismatch: got {}, want {}",
                unwrapped.target.authority(),
                opts.packet_target
            ));
        }
        if unwrapped.payload != opts.response {
            return Err("stage56 response payload mismatch".to_owned());
        }
        last_control_bind = control.bind;
        last_resolved_udp_bind = resolved_udp_bind.to_string();
        tcp_last_dial_report = Some(connected.report);
        udp_last_socket_report = Some(udp.report().clone());
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage56 socks5 udp server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage56 server accepted {} control connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage56Outcome {
        tcp_listener_report,
        tcp_last_dial_report: tcp_last_dial_report
            .ok_or_else(|| "stage56 missing tcp control dial report".to_owned())?,
        udp_last_socket_report: udp_last_socket_report
            .ok_or_else(|| "stage56 missing udp socket report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_udp_associate: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        response_len: opts.response.len(),
        last_control_bind,
        last_resolved_udp_bind,
    })
}

fn apply_stage56_outcome(report: &mut Value, outcome: Stage56Outcome) {
    let tcp_so_mark_observed = outcome.tcp_last_dial_report.so_mark_applied
        && outcome.tcp_last_dial_report.so_mark == outcome.tcp_last_dial_report.requested_mark;
    let tcp_mptcp_status_recorded = outcome.tcp_last_dial_report.mptcp_socket_attempted
        || !outcome.tcp_last_dial_report.requested_mptcp;
    let udp_so_mark_observed = outcome.udp_last_socket_report.so_mark_applied
        && outcome.udp_last_socket_report.so_mark == outcome.udp_last_socket_report.requested_mark;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.auth_success_count == outcome.exchange_count
        && outcome.server_summary.udp_associate_count == outcome.exchange_count
        && outcome.server_summary.udp_packet_roundtrip_count == outcome.exchange_count
        && outcome.server_summary.control_retained_during_udp_count == outcome.exchange_count;
    let passed = server_complete
        && tcp_so_mark_observed
        && tcp_mptcp_status_recorded
        && udp_so_mark_observed;

    report["read_only"] = json!(false);
    report["socks5_udp_smoke_passed"] = json!(passed);
    report["socks5_udp_associate_admitted"] = json!(passed);
    report["socks5_protocol_true_dataplane_admitted"] = json!(passed);
    report["socks5_auth_observed"] = json!(outcome.server_summary.auth_success_count > 0);
    report["socks5_udp_associate_request_observed"] =
        json!(outcome.server_summary.udp_associate_count > 0);
    report["socks5_udp_packet_wrap_unwrap_recorded"] =
        json!(outcome.server_summary.udp_packet_roundtrip_count > 0);
    report["socks5_udp_payload_roundtrip_recorded"] =
        json!(outcome.server_summary.udp_packet_roundtrip_count > 0);
    report["socks5_tcp_control_connection_retained"] =
        json!(outcome.server_summary.control_retained_during_udp_count == outcome.exchange_count);
    report["socks5_udp_contract"]["tcp_control_proxy"] =
        json!(outcome.tcp_last_dial_report.peer_addr);
    report["socks5_udp_contract"]["observed_bind_reply"] = json!(outcome.last_control_bind);
    report["socks5_udp_contract"]["resolved_udp_bind"] = json!(outcome.last_resolved_udp_bind);
    report["tcp_control_underlay"]["listener"] = json!({
        "requested_mptcp": outcome.tcp_listener_report.requested_mptcp,
        "mptcp_socket_created": outcome.tcp_listener_report.mptcp_socket_created,
        "fallback_used": outcome.tcp_listener_report.fallback_used,
        "socket_protocol": outcome.tcp_listener_report.socket_protocol,
        "local_addr": outcome.tcp_listener_report.local_addr
    });
    report["tcp_control_underlay"]["last_dial_report"] = json!({
        "requested_mark": outcome.tcp_last_dial_report.requested_mark,
        "requested_mptcp": outcome.tcp_last_dial_report.requested_mptcp,
        "mptcp_socket_attempted": outcome.tcp_last_dial_report.mptcp_socket_attempted,
        "mptcp_socket_created": outcome.tcp_last_dial_report.mptcp_socket_created,
        "mptcp_connect_fallback_used": outcome.tcp_last_dial_report.mptcp_connect_fallback_used,
        "socket_protocol": outcome.tcp_last_dial_report.socket_protocol,
        "so_mark": outcome.tcp_last_dial_report.so_mark,
        "so_mark_applied": outcome.tcp_last_dial_report.so_mark_applied,
        "mptcp_info_available": outcome.tcp_last_dial_report.mptcp_info_available,
        "mptcp_fallen_back": outcome.tcp_last_dial_report.mptcp_fallen_back,
        "mptcp_protocol_observed": outcome.tcp_last_dial_report.mptcp_protocol_observed,
        "peer_addr": outcome.tcp_last_dial_report.peer_addr,
        "local_addr": outcome.tcp_last_dial_report.local_addr
    });
    report["tcp_control_underlay"]["so_mark_observed"] = json!(tcp_so_mark_observed);
    report["tcp_control_underlay"]["mptcp_status_recorded"] = json!(tcp_mptcp_status_recorded);
    report["tcp_control_underlay"]["mptcp_protocol_observed"] =
        json!(outcome.tcp_last_dial_report.mptcp_protocol_observed);
    report["udp_underlay_socket"]["last_socket_report"] = json!({
        "requested_mark": outcome.udp_last_socket_report.requested_mark,
        "so_mark": outcome.udp_last_socket_report.so_mark,
        "so_mark_applied": outcome.udp_last_socket_report.so_mark_applied,
        "peer_addr": outcome.udp_last_socket_report.peer_addr,
        "local_addr": outcome.udp_last_socket_report.local_addr
    });
    report["udp_underlay_socket"]["so_mark_observed"] = json!(udp_so_mark_observed);
    report["server_observation"] = json!({
        "accepted": outcome.server_summary.accepted,
        "auth_success_count": outcome.server_summary.auth_success_count,
        "udp_associate_count": outcome.server_summary.udp_associate_count,
        "udp_packet_roundtrip_count": outcome.server_summary.udp_packet_roundtrip_count,
        "control_retained_during_udp_count": outcome.server_summary.control_retained_during_udp_count,
        "associate_targets": outcome.server_summary.associate_targets,
        "packet_targets": outcome.server_summary.packet_targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_udp_associate"] = json!(outcome.ns_per_udp_associate);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["response_len"] = json!(outcome.response_len);
    report["protocol_matrix"]["socks5_udp_associate_admitted"] = json!(passed);
    report["protocol_matrix"]["socks5_protocol_true_dataplane_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct Socks5UdpServerSummary {
    accepted: usize,
    auth_success_count: usize,
    udp_associate_count: usize,
    udp_packet_roundtrip_count: usize,
    control_retained_during_udp_count: usize,
    associate_targets: Vec<String>,
    packet_targets: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_socks5_udp_server(
    opts: &Stage56Options,
) -> Result<
    (
        SocketAddrV4,
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<Socks5UdpServerSummary, String>>,
    ),
    String,
> {
    let (tcp_listener, tcp_listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage56 bind loopback tcp control listener failed: {err}"))?;
    let tcp_addr = match tcp_listener
        .local_addr()
        .map_err(|err| format!("stage56 tcp listener local_addr failed: {err}"))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage56 tcp listener is not IPv4: {addr}"));
        }
    };
    tcp_listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage56 tcp listener nonblocking failed: {err}"))?;

    let udp_socket = UdpSocket::bind(("127.0.0.1", 0))
        .map_err(|err| format!("stage56 bind udp relay failed: {err}"))?;
    udp_socket
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage56 udp relay read timeout failed: {err}"))?;
    udp_socket
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage56 udp relay write timeout failed: {err}"))?;
    let udp_addr = match udp_socket
        .local_addr()
        .map_err(|err| format!("stage56 udp relay local_addr failed: {err}"))?
    {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage56 udp relay is not IPv4: {addr}"));
        }
    };

    let iterations = opts.benchmark_iters;
    let associate_target = opts.associate_target.clone();
    let packet_target = opts.packet_target.clone();
    let username = opts.username.clone();
    let password = opts.password.clone();
    let payload = opts.payload.clone();
    let response = opts.response.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_socks5_udp_associations(
            tcp_listener,
            udp_socket,
            udp_addr,
            iterations,
            &associate_target,
            &packet_target,
            &username,
            &password,
            &payload,
            &response,
            timeout,
        )
    });
    Ok((tcp_addr, udp_addr, tcp_listener_report, handle))
}

#[allow(clippy::too_many_arguments)]
fn accept_socks5_udp_associations(
    tcp_listener: TcpListener,
    udp_socket: UdpSocket,
    udp_addr: SocketAddrV4,
    iterations: usize,
    associate_target: &str,
    packet_target: &str,
    username: &str,
    password: &str,
    payload: &[u8],
    response: &[u8],
    timeout: Duration,
) -> Result<Socks5UdpServerSummary, String> {
    let mut summary = Socks5UdpServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match tcp_listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage56 server set tcp read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage56 server set tcp write timeout failed: {err}"))?;
                handle_socks5_udp_control(
                    &mut stream,
                    udp_addr.port(),
                    associate_target,
                    username,
                    password,
                    &mut summary,
                )?;
                handle_socks5_udp_packet(
                    &udp_socket,
                    packet_target,
                    payload,
                    response,
                    &mut summary,
                )?;
                summary.control_retained_during_udp_count += 1;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage56 socks5 server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage56 socks5 server accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_socks5_udp_control(
    stream: &mut TcpStream,
    udp_port: u16,
    associate_target: &str,
    username: &str,
    password: &str,
    summary: &mut Socks5UdpServerSummary,
) -> Result<(), String> {
    let mut header = [0_u8; 2];
    stream
        .read_exact(&mut header)
        .map_err(|err| format!("stage56 socks5 greeting header failed: {err}"))?;
    if header[0] != handshake::VERSION {
        return Err(format!("stage56 socks5 bad version: {}", header[0]));
    }
    let mut methods = vec![0_u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .map_err(|err| format!("stage56 socks5 greeting methods failed: {err}"))?;
    if !methods.contains(&handshake::AUTH_PASSWORD) {
        return Err("stage56 socks5 client did not offer password auth".to_owned());
    }
    stream
        .write_all(&[handshake::VERSION, handshake::AUTH_PASSWORD])
        .map_err(|err| format!("stage56 socks5 method reply failed: {err}"))?;

    let mut auth_head = [0_u8; 2];
    stream
        .read_exact(&mut auth_head)
        .map_err(|err| format!("stage56 socks5 auth header failed: {err}"))?;
    if auth_head[0] != handshake::PASSWORD_AUTH_VERSION {
        return Err(format!("stage56 socks5 bad auth version: {}", auth_head[0]));
    }
    let mut got_user = vec![0_u8; auth_head[1] as usize];
    stream
        .read_exact(&mut got_user)
        .map_err(|err| format!("stage56 socks5 auth username failed: {err}"))?;
    let mut pass_len = [0_u8; 1];
    stream
        .read_exact(&mut pass_len)
        .map_err(|err| format!("stage56 socks5 auth password len failed: {err}"))?;
    let mut got_pass = vec![0_u8; pass_len[0] as usize];
    stream
        .read_exact(&mut got_pass)
        .map_err(|err| format!("stage56 socks5 auth password failed: {err}"))?;
    if got_user != username.as_bytes() || got_pass != password.as_bytes() {
        stream
            .write_all(&[handshake::PASSWORD_AUTH_VERSION, 1])
            .map_err(|err| format!("stage56 socks5 auth reject failed: {err}"))?;
        return Err("stage56 socks5 username/password mismatch".to_owned());
    }
    stream
        .write_all(&[handshake::PASSWORD_AUTH_VERSION, 0])
        .map_err(|err| format!("stage56 socks5 auth success failed: {err}"))?;
    summary.auth_success_count += 1;

    let mut request_head = [0_u8; 3];
    stream
        .read_exact(&mut request_head)
        .map_err(|err| format!("stage56 socks5 request header failed: {err}"))?;
    if request_head
        != [
            handshake::VERSION,
            handshake::Socks5Command::UdpAssociate.byte(),
            0,
        ]
    {
        return Err(format!(
            "stage56 socks5 unexpected udp associate header: {:02x?}",
            request_head
        ));
    }
    let requested_target = read_socks5_address(stream)?.authority();
    if requested_target != associate_target {
        return Err(format!(
            "stage56 socks5 associate target mismatch: got {requested_target}, want {associate_target}"
        ));
    }
    summary.udp_associate_count += 1;
    summary.associate_targets.push(requested_target);

    let mut reply = vec![handshake::VERSION, 0, 0];
    Socks5Address::Ipv4 {
        addr: Ipv4Addr::UNSPECIFIED,
        port: udp_port,
    }
    .write_to(&mut reply)
    .map_err(|err| err.to_string())?;
    stream
        .write_all(&reply)
        .map_err(|err| format!("stage56 socks5 udp associate reply failed: {err}"))?;
    Ok(())
}

fn handle_socks5_udp_packet(
    udp_socket: &UdpSocket,
    packet_target: &str,
    payload: &[u8],
    response: &[u8],
    summary: &mut Socks5UdpServerSummary,
) -> Result<(), String> {
    let mut buf = vec![0_u8; 2048];
    let (read, peer) = udp_socket
        .recv_from(&mut buf)
        .map_err(|err| format!("stage56 socks5 udp recv failed: {err}"))?;
    buf.truncate(read);
    let packet = udp_packet::unwrap(&buf).map_err(|err| err.to_string())?;
    if packet.reserved != [0, 0] || packet.fragment != 0 {
        return Err(format!(
            "stage56 socks5 udp bad header: reserved={:02x?} fragment={}",
            packet.reserved, packet.fragment
        ));
    }
    if packet.target.authority() != packet_target {
        return Err(format!(
            "stage56 socks5 udp target mismatch: got {}, want {}",
            packet.target.authority(),
            packet_target
        ));
    }
    if packet.payload != payload {
        return Err("stage56 socks5 udp payload mismatch at server".to_owned());
    }
    let wrapped_response =
        udp_packet::wrap(&packet.target, response).map_err(|err| err.to_string())?;
    udp_socket
        .send_to(&wrapped_response, peer)
        .map_err(|err| format!("stage56 socks5 udp send failed: {err}"))?;
    summary.udp_packet_roundtrip_count += 1;
    summary.packet_targets.push(packet.target.authority());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&packet.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(response).to_string());
    Ok(())
}

fn resolve_udp_associate_bind(
    bind: &str,
    proxy_addr: SocketAddrV4,
) -> Result<SocketAddrV4, String> {
    match Socks5Address::parse(bind).map_err(|err| err.to_string())? {
        Socks5Address::Ipv4 { addr, port } => {
            let resolved = if addr.is_unspecified() {
                *proxy_addr.ip()
            } else {
                addr
            };
            Ok(SocketAddrV4::new(resolved, port))
        }
        Socks5Address::Domain { hostname, port } => {
            if hostname == "localhost" {
                Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            } else {
                Err(format!(
                    "stage56 unsupported domain udp associate bind: {hostname}:{port}"
                ))
            }
        }
        Socks5Address::Ipv6 { addr, port } => Err(format!(
            "stage56 unsupported ipv6 udp associate bind: [{addr}]:{port}"
        )),
    }
}

fn read_socks5_address(stream: &mut TcpStream) -> Result<Socks5Address, String> {
    let mut atyp = [0_u8; 1];
    stream
        .read_exact(&mut atyp)
        .map_err(|err| format!("stage56 socks5 address type failed: {err}"))?;
    let mut bytes = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage56 socks5 ipv4 address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|err| format!("stage56 socks5 domain len failed: {err}"))?;
            bytes.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage56 socks5 domain address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage56 socks5 ipv6 address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        value => return Err(format!("stage56 socks5 bad address type: {value}")),
    }
    let (addr, consumed) = Socks5Address::decode(&bytes).map_err(|err| err.to_string())?;
    if consumed != bytes.len() {
        return Err(format!(
            "stage56 socks5 address consumed {consumed}, len {}",
            bytes.len()
        ));
    }
    Ok(addr)
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    context: &str,
) -> Result<String, RunnerOutput> {
    iter.next()
        .cloned()
        .ok_or_else(|| RunnerOutput::usage(format!("missing value for {context}")))
}

fn parse_usize(value: &str, context: &str) -> Result<usize, RunnerOutput> {
    value
        .parse::<usize>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}

fn parse_u64(value: &str, context: &str) -> Result<u64, RunnerOutput> {
    value
        .parse::<u64>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}

fn parse_u32(value: &str, context: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}
