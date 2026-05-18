use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::socks5::{self, Socks5Address, handshake};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_TARGET: &str = "stage55.example:443";
const DEFAULT_USERNAME: &str = "user";
const DEFAULT_PASSWORD: &str = "pass";
const DEFAULT_PAYLOAD: &[u8] = b"stage55-socks5-ping";
const DEFAULT_BIND_REPLY: &str = "127.0.0.1:5300";

pub(crate) fn run_stage55_socks5_outbound_true_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage55Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage55_report(&opts);
    let passed = report["socks5_tcp_smoke_passed"].as_bool().unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage55Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    target: String,
    username: String,
    password: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage55Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            target: DEFAULT_TARGET.to_owned(),
            username: DEFAULT_USERNAME.to_owned(),
            password: DEFAULT_PASSWORD.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage55Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage55 --benchmark-iters")?, arg)?;
                }
                "--target" => opts.target = next_value(&mut iter, "stage55 --target")?,
                "--username" => opts.username = next_value(&mut iter, "stage55 --username")?,
                "--password" => opts.password = next_value(&mut iter, "stage55 --password")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage55 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage55 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage55 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
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
                _ if arg.starts_with("--so-mark=") => {
                    opts.so_mark = parse_u32(arg.split_once('=').unwrap().1, "--so-mark")?;
                }
                _ if arg.starts_with("--timeout-ms=") => {
                    let timeout_ms = parse_u64(arg.split_once('=').unwrap().1, "--timeout-ms")?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ => {
                    return Err(RunnerOutput::usage(format!(
                        "unsupported stage55 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage55 --benchmark-iters must be greater than zero",
            ));
        }
        Ok(opts)
    }
}

fn stage55_report(opts: &Stage55Options) -> Value {
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage55-socks5-outbound-true-dataplane-admission",
        "stage": "stage55",
        "evidence_class": "opt-in-protocol-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_tcp_smoke_passed": false,
        "socks5_tcp_true_dataplane_admitted": false,
        "socks5_auth_observed": false,
        "socks5_connect_request_observed": false,
        "socks5_payload_roundtrip_recorded": false,
        "socks5_udp_associate_admitted": false,
        "protocol_outbound_partial_admitted": false,
        "active_tcp_tproxy_admitted": true,
        "active_udp_tproxy_admitted": true,
        "active_dns_tproxy_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "socks5_contract": {
            "protocol": "SOCKS5",
            "scope": "TCP CONNECT loopback true dataplane",
            "proxy": null,
            "target": opts.target,
            "username_password_auth_required": true,
            "command": "CONNECT",
            "bind_reply": DEFAULT_BIND_REPLY,
            "payload_ascii": payload_ascii,
            "udp_associate_deferred": "requires TCP control connection plus UDP PacketConn lifecycle gate",
            "default_go_path_preserved": true
        },
        "underlay_socket": {
            "requested_mark": opts.so_mark,
            "requested_mptcp": opts.mptcp,
            "listener": null,
            "last_dial_report": null,
            "so_mark_observed": false,
            "mptcp_status_recorded": false,
            "mptcp_protocol_observed": false
        },
        "server_observation": null,
        "benchmark": {
            "benchmark_recorded": false,
            "iterations": opts.benchmark_iters,
            "elapsed_ns": null,
            "ns_per_connect": null,
            "scope": "SOCKS5 TCP CONNECT plus username/password auth plus payload roundtrip over Rust underlay socket",
            "go_matched_default_daemon_baseline_recorded": false,
            "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
        },
        "protocol_matrix": {
            "socks5_tcp_true_dataplane_admitted": false,
            "socks5_udp_associate_admitted": false,
            "http_connect_true_dataplane_admitted": false,
            "shadowsocks_aead_true_dataplane_admitted": false,
            "vmess_vless_trojan_shared_transport_admitted": false,
            "quic_h3_session_protocols_admitted": false
        },
        "remaining_blockers": [
            "SOCKS5 UDP associate true dataplane is still incomplete",
            "HTTP/HTTPS, Shadowsocks/SS2022, Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS, and shared transport true dataplanes are still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
        "validation_commands": [
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage55/socks5_outbound_true_dataplane_admission.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage55_socks5_outbound_true_dataplane_gate.json",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage55 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage55 -- --nocapture",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage55-socks5-outbound-true-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
            "git diff --check"
        ],
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage55-item333",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.1",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.13",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8",
            "rust/crates/dae-outbound/src/socks5/dataplane.rs",
            "rust/crates/dae-datapath/src/tcp_direct.rs"
        ]
    });

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage55 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage55_smoke(opts) {
        Ok(outcome) => apply_stage55_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage55Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: Socks5ServerSummary,
    elapsed_ns: u128,
    ns_per_connect: f64,
    exchange_count: usize,
    payload_len: usize,
    last_bind: String,
}

fn run_stage55_smoke(opts: &Stage55Options) -> Result<Stage55Outcome, String> {
    let (proxy_addr, listener_report, handle) = spawn_socks5_loopback_server(opts)?;
    let mut last_dial_report = None;
    let mut last_bind = String::new();
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
        .map_err(|err| format!("stage55 magic_tcp_connect failed: {err}"))?;
        let report = socks5::tcp_connect_exchange_over_stream(
            &mut connected.stream,
            &proxy_addr.to_string(),
            &opts.target,
            &opts.username,
            &opts.password,
            &opts.payload,
        )
        .map_err(|err| format!("stage55 socks5 exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage55 socks5 payload mismatch".to_owned());
        }
        if report.method != handshake::AUTH_PASSWORD {
            return Err(format!(
                "stage55 socks5 auth method mismatch: {}",
                report.method
            ));
        }
        last_bind = report.bind;
        last_dial_report = Some(connected.report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage55 socks5 server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage55 socks5 accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage55Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage55 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_connect: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        last_bind,
    })
}

fn apply_stage55_outcome(report: &mut Value, outcome: Stage55Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.auth_success_count == outcome.exchange_count
        && outcome.server_summary.connect_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["socks5_tcp_smoke_passed"] = json!(passed);
    report["socks5_tcp_true_dataplane_admitted"] = json!(passed);
    report["socks5_auth_observed"] = json!(outcome.server_summary.auth_success_count > 0);
    report["socks5_connect_request_observed"] = json!(outcome.server_summary.connect_count > 0);
    report["socks5_payload_roundtrip_recorded"] =
        json!(outcome.server_summary.payload_roundtrip_count > 0);
    report["protocol_outbound_partial_admitted"] = json!(passed);
    report["socks5_contract"]["proxy"] = json!(outcome.last_dial_report.peer_addr);
    report["socks5_contract"]["observed_bind_reply"] = json!(outcome.last_bind);
    report["underlay_socket"]["listener"] = json!({
        "requested_mptcp": outcome.listener_report.requested_mptcp,
        "mptcp_socket_created": outcome.listener_report.mptcp_socket_created,
        "fallback_used": outcome.listener_report.fallback_used,
        "socket_protocol": outcome.listener_report.socket_protocol,
        "local_addr": outcome.listener_report.local_addr
    });
    report["underlay_socket"]["last_dial_report"] = json!({
        "requested_mark": outcome.last_dial_report.requested_mark,
        "requested_mptcp": outcome.last_dial_report.requested_mptcp,
        "mptcp_socket_attempted": outcome.last_dial_report.mptcp_socket_attempted,
        "mptcp_socket_created": outcome.last_dial_report.mptcp_socket_created,
        "mptcp_connect_fallback_used": outcome.last_dial_report.mptcp_connect_fallback_used,
        "socket_protocol": outcome.last_dial_report.socket_protocol,
        "so_mark": outcome.last_dial_report.so_mark,
        "so_mark_applied": outcome.last_dial_report.so_mark_applied,
        "mptcp_info_available": outcome.last_dial_report.mptcp_info_available,
        "mptcp_fallen_back": outcome.last_dial_report.mptcp_fallen_back,
        "mptcp_protocol_observed": outcome.last_dial_report.mptcp_protocol_observed,
        "peer_addr": outcome.last_dial_report.peer_addr,
        "local_addr": outcome.last_dial_report.local_addr
    });
    report["underlay_socket"]["so_mark_observed"] = json!(so_mark_observed);
    report["underlay_socket"]["mptcp_status_recorded"] = json!(mptcp_status_recorded);
    report["underlay_socket"]["mptcp_protocol_observed"] =
        json!(outcome.last_dial_report.mptcp_protocol_observed);
    report["server_observation"] = json!({
        "accepted": outcome.server_summary.accepted,
        "auth_success_count": outcome.server_summary.auth_success_count,
        "connect_count": outcome.server_summary.connect_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_connect"] = json!(outcome.ns_per_connect);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["protocol_matrix"]["socks5_tcp_true_dataplane_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct Socks5ServerSummary {
    accepted: usize,
    auth_success_count: usize,
    connect_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    payload_ascii: Vec<String>,
}

fn spawn_socks5_loopback_server(
    opts: &Stage55Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<Socks5ServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage55 bind loopback socks5 listener failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage55 socks5 listener local_addr failed: {err}"))?;
    let proxy_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => {
            return Err(format!("stage55 socks5 listener is not IPv4: {local_addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage55 socks5 listener nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let username = opts.username.clone();
    let password = opts.password.clone();
    let payload = opts.payload.clone();
    let target = opts.target.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_socks5_connections(
            listener, iterations, &username, &password, &target, &payload, timeout,
        )
    });
    Ok((proxy_addr, listener_report, handle))
}

fn accept_socks5_connections(
    listener: TcpListener,
    iterations: usize,
    username: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    timeout: Duration,
) -> Result<Socks5ServerSummary, String> {
    let mut summary = Socks5ServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage55 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage55 server set write timeout failed: {err}"))?;
                handle_socks5_connection(
                    &mut stream,
                    username,
                    password,
                    target,
                    payload,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage55 socks5 server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage55 socks5 server accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_socks5_connection(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
    target: &str,
    payload: &[u8],
    summary: &mut Socks5ServerSummary,
) -> Result<(), String> {
    let mut header = [0_u8; 2];
    stream
        .read_exact(&mut header)
        .map_err(|err| format!("stage55 socks5 greeting header failed: {err}"))?;
    if header[0] != handshake::VERSION {
        return Err(format!("stage55 socks5 bad version: {}", header[0]));
    }
    let mut methods = vec![0_u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .map_err(|err| format!("stage55 socks5 greeting methods failed: {err}"))?;
    if !methods.contains(&handshake::AUTH_PASSWORD) {
        return Err("stage55 socks5 client did not offer password auth".to_owned());
    }
    stream
        .write_all(&[handshake::VERSION, handshake::AUTH_PASSWORD])
        .map_err(|err| format!("stage55 socks5 method reply failed: {err}"))?;

    let mut auth_head = [0_u8; 2];
    stream
        .read_exact(&mut auth_head)
        .map_err(|err| format!("stage55 socks5 auth header failed: {err}"))?;
    if auth_head[0] != handshake::PASSWORD_AUTH_VERSION {
        return Err(format!("stage55 socks5 bad auth version: {}", auth_head[0]));
    }
    let mut got_user = vec![0_u8; auth_head[1] as usize];
    stream
        .read_exact(&mut got_user)
        .map_err(|err| format!("stage55 socks5 auth username failed: {err}"))?;
    let mut pass_len = [0_u8; 1];
    stream
        .read_exact(&mut pass_len)
        .map_err(|err| format!("stage55 socks5 auth password len failed: {err}"))?;
    let mut got_pass = vec![0_u8; pass_len[0] as usize];
    stream
        .read_exact(&mut got_pass)
        .map_err(|err| format!("stage55 socks5 auth password failed: {err}"))?;
    if got_user != username.as_bytes() || got_pass != password.as_bytes() {
        stream
            .write_all(&[handshake::PASSWORD_AUTH_VERSION, 1])
            .map_err(|err| format!("stage55 socks5 auth reject failed: {err}"))?;
        return Err("stage55 socks5 username/password mismatch".to_owned());
    }
    stream
        .write_all(&[handshake::PASSWORD_AUTH_VERSION, 0])
        .map_err(|err| format!("stage55 socks5 auth success failed: {err}"))?;
    summary.auth_success_count += 1;

    let mut request_head = [0_u8; 3];
    stream
        .read_exact(&mut request_head)
        .map_err(|err| format!("stage55 socks5 request header failed: {err}"))?;
    if request_head != [handshake::VERSION, 1, 0] {
        return Err(format!(
            "stage55 socks5 unexpected request header: {:02x?}",
            request_head
        ));
    }
    let requested_target = read_socks5_address(stream)?.authority();
    if requested_target != target {
        return Err(format!(
            "stage55 socks5 target mismatch: got {requested_target}, want {target}"
        ));
    }
    summary.connect_count += 1;
    summary.targets.push(requested_target);

    let mut reply = vec![handshake::VERSION, 0, 0];
    Socks5Address::parse(DEFAULT_BIND_REPLY)
        .map_err(|err| err.to_string())?
        .write_to(&mut reply)
        .map_err(|err| err.to_string())?;
    stream
        .write_all(&reply)
        .map_err(|err| format!("stage55 socks5 connect reply failed: {err}"))?;

    let mut got_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut got_payload)
        .map_err(|err| format!("stage55 socks5 payload read failed: {err}"))?;
    if got_payload != payload {
        return Err("stage55 socks5 payload mismatch at server".to_owned());
    }
    stream
        .write_all(&got_payload)
        .map_err(|err| format!("stage55 socks5 payload echo failed: {err}"))?;
    summary.payload_roundtrip_count += 1;
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&got_payload).to_string());
    Ok(())
}

fn read_socks5_address(stream: &mut TcpStream) -> Result<Socks5Address, String> {
    let mut atyp = [0_u8; 1];
    stream
        .read_exact(&mut atyp)
        .map_err(|err| format!("stage55 socks5 address type failed: {err}"))?;
    let mut bytes = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage55 socks5 ipv4 address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|err| format!("stage55 socks5 domain len failed: {err}"))?;
            bytes.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage55 socks5 domain address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .map_err(|err| format!("stage55 socks5 ipv6 address failed: {err}"))?;
            bytes.extend_from_slice(&rest);
        }
        value => return Err(format!("stage55 socks5 bad address type: {value}")),
    }
    let (addr, consumed) = Socks5Address::decode(&bytes).map_err(|err| err.to_string())?;
    if consumed != bytes.len() {
        return Err(format!(
            "stage55 socks5 address consumed {consumed}, len {}",
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
