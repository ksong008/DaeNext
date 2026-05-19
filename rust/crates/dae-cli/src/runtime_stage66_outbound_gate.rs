use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::vmess;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_TARGET: &str = "1.2.3.4:53";
const DEFAULT_PAYLOAD: &[u8] = b"stage66-vmess-udp-ping";

pub(crate) fn run_stage66_vmess_aead_udp_over_tcp_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage66Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage66_report(&opts);
    let passed = report["vmess_aead_udp_over_tcp_smoke_passed"]
        .as_bool()
        .unwrap_or(false);
    let blocked = report["blocked"].as_bool().unwrap_or(false);
    let output = format!("{report}\n");
    if opts.execute_smoke && (blocked || !passed) {
        RunnerOutput::stdout_error(output.trim_end())
    } else {
        RunnerOutput::ok(output)
    }
}

#[derive(Debug, Clone)]
struct Stage66Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    uuid: String,
    target: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage66Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage66Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage66 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage66 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage66 --target")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage66 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage66 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage66 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--uuid=") => {
                    opts.uuid = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage66 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage66 --benchmark-iters must be greater than zero",
            ));
        }
        vmess::vmess_cmd_key_from_uuid(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage66 uuid is invalid: {err}")))?;
        Ok(opts)
    }
}

fn stage66_report(opts: &Stage66Options) -> Value {
    let cmd_key = match vmess::vmess_cmd_key_from_uuid(&opts.uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage66-vmess-aead-udp-over-tcp-dataplane-admission",
                "stage": "stage66",
                "blocked": true,
                "blockers": [format!("stage66 uuid is invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage66-vmess-aead-udp-over-tcp-dataplane-admission",
        "stage": "stage66",
        "evidence_class": "opt-in-protocol-vmess-aead-udp-over-tcp-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": []
    });
    report["socks5_protocol_true_dataplane_admitted"] = json!(true);
    report["http_connect_true_dataplane_admitted"] = json!(true);
    report["shadowsocks_aead_protocol_true_dataplane_admitted"] = json!(true);
    report["trojanc_tcp_true_dataplane_admitted"] = json!(true);
    report["trojan_udp_over_tcp_admitted"] = json!(true);
    report["trojan_protocol_true_dataplane_admitted"] = json!(false);
    report["vless_tcp_raw_true_dataplane_admitted"] = json!(true);
    report["vless_udp_over_tcp_admitted"] = json!(true);
    report["vless_mux_admitted"] = json!(true);
    report["vless_protocol_partial_admitted"] = json!(true);
    report["vless_protocol_true_dataplane_admitted"] = json!(false);
    report["vmess_aead_tcp_true_dataplane_admitted"] = json!(true);
    report["vmess_aead_udp_over_tcp_smoke_passed"] = json!(false);
    report["vmess_aead_udp_over_tcp_admitted"] = json!(false);
    report["vmess_protocol_partial_admitted"] = json!(false);
    report["vmess_protocol_true_dataplane_admitted"] = json!(false);
    report["vmess_udp_packet_addr_admitted"] = json!(false);
    report["vmess_mux_admitted"] = json!(false);
    report["vmess_tls_underlay_admitted"] = json!(false);
    report["vmess_shared_transport_admitted"] = json!(false);
    report["ss2022_true_dataplane_admitted"] = json!(false);
    report["protocol_outbound_partial_admitted"] = json!(true);
    report["outbound_true_dataplane_admitted"] = json!(false);
    report["matched_go_rust_default_daemon_benchmark_recorded"] = json!(false);
    report["default_switch_allowed"] = json!(false);
    report["default_path_mutation_allowed"] = json!(false);
    report["product_chain_switch_allowed"] = json!(false);
    report["true_rust_default_daemon_admitted"] = json!(false);
    report["go_default_path_preserved"] = json!(true);
    report["go_fallback_required"] = json!(true);
    report["server_observation"] = json!(null);
    report["vmess_aead_udp_over_tcp_contract"] = json!({
        "protocol": "vmess",
        "scope": "VMess AEAD network=udp fixed target packet stream over Rust TCP stream",
        "uuid": opts.uuid,
        "cmd_key_hex": hex_encode(&cmd_key),
        "network": "udp",
        "underlay_network": "tcp",
        "security": "auto/aes-128-gcm",
        "security_byte": vmess::VMESS_AEAD_SECURITY_AES_128_GCM,
        "target": opts.target,
        "payload_ascii": payload_ascii,
        "packet_len": opts.payload.len(),
        "server": null,
        "eauth_crc_validated": false,
        "request_header_aead_validated": false,
        "response_header_aead_validated": false,
        "shake128_chunk_masking_validated": false,
        "udp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "packet_addr_deferred": "VMess sp.packet-addr.v2fly.arpa packet-addr mode is deferred",
        "tls_shared_transport_deferred": "VMess TLS, WS, gRPC, HTTP/H2, HTTPUpgrade, Meek, and xHTTP require separate transport gates",
        "default_go_path_preserved": true
    });
    report["underlay_socket"] = json!({
        "requested_mark": opts.so_mark,
        "requested_mptcp": opts.mptcp,
        "listener": null,
        "last_dial_report": null,
        "so_mark_observed": false,
        "mptcp_status_recorded": false,
        "mptcp_protocol_observed": false
    });
    report["benchmark"] = json!({
        "benchmark_recorded": false,
        "iterations": opts.benchmark_iters,
        "elapsed_ns": null,
        "ns_per_vmess_aead_udp_over_tcp_exchange": null,
        "scope": "VMess AEAD UDP-over-TCP fixed-target packet echo over SO_MARKed Rust TCP socket",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"] = json!({
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_tls_underlay_admitted": false,
        "shadowsocks_aead_protocol_true_dataplane_admitted": true,
        "ss2022_true_dataplane_admitted": false,
        "trojanc_tcp_true_dataplane_admitted": true,
        "trojan_udp_over_tcp_admitted": true,
        "trojan_protocol_true_dataplane_admitted": false,
        "vless_tcp_raw_true_dataplane_admitted": true,
        "vless_udp_over_tcp_admitted": true,
        "vless_mux_admitted": true,
        "vless_protocol_true_dataplane_admitted": false,
        "vmess_aead_tcp_true_dataplane_admitted": true,
        "vmess_aead_udp_over_tcp_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Trojan TLS and Trojan-Go shared transport rows are still incomplete",
        "VLESS TLS/REALITY/XTLS Vision/shared transport/xHTTP xmux rows are still incomplete",
        "VMess packet-addr/mux/TLS/shared transport rows are still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage66/vmess_aead_udp_over_tcp_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage66_vmess_aead_udp_over_tcp_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage66 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage66 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage66 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage66-vmess-aead-udp-over-tcp-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage66",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "rust/crates/dae-outbound/src/vmess/dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage66 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage66_smoke(opts) {
        Ok(outcome) => apply_stage66_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage66Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: VMessAeadUdpServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    request_header_len: usize,
    request_chunk_len: usize,
    response_header_len: usize,
    response_chunk_len: usize,
    cmd_key_hex: String,
}

fn run_stage66_smoke(opts: &Stage66Options) -> Result<Stage66Outcome, String> {
    let (server_addr, listener_report, handle) = spawn_vmess_aead_udp_server(opts)?;
    let mut last_dial_report = None;
    let mut last_exchange = None;
    let start = Instant::now();
    for _ in 0..opts.benchmark_iters {
        let mut connected = magic_tcp_connect(
            server_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage66 magic_tcp_connect failed: {err}"))?;
        let report = vmess::aead_udp_over_tcp_exchange_over_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.uuid,
            &opts.target,
            &opts.payload,
        )
        .map_err(|err| format!("stage66 VMess AEAD UDP-over-TCP exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage66 VMess AEAD UDP payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_exchange = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage66 VMess UDP server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage66 VMess server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let last_exchange =
        last_exchange.ok_or_else(|| "stage66 missing exchange report".to_owned())?;
    Ok(Stage66Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage66 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        request_header_len: last_exchange.request_header_len,
        request_chunk_len: last_exchange.request_chunk_len,
        response_header_len: last_exchange.response_header_len,
        response_chunk_len: last_exchange.response_chunk_len,
        cmd_key_hex: last_exchange.cmd_key_hex,
    })
}

fn apply_stage66_outcome(report: &mut Value, outcome: Stage66Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.eauth_crc_count == outcome.exchange_count
        && outcome.server_summary.request_header_aead_count == outcome.exchange_count
        && outcome.server_summary.response_header_aead_count == outcome.exchange_count
        && outcome.server_summary.udp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.shake128_chunk_masking_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vmess_aead_udp_over_tcp_smoke_passed"] = json!(passed);
    report["vmess_aead_udp_over_tcp_admitted"] = json!(passed);
    report["vmess_protocol_partial_admitted"] = json!(passed);
    report["vmess_aead_udp_over_tcp_contract"]["server"] =
        json!(outcome.last_dial_report.peer_addr);
    report["vmess_aead_udp_over_tcp_contract"]["cmd_key_hex"] = json!(outcome.cmd_key_hex);
    report["vmess_aead_udp_over_tcp_contract"]["eauth_crc_validated"] = json!(passed);
    report["vmess_aead_udp_over_tcp_contract"]["request_header_aead_validated"] = json!(passed);
    report["vmess_aead_udp_over_tcp_contract"]["response_header_aead_validated"] = json!(passed);
    report["vmess_aead_udp_over_tcp_contract"]["shake128_chunk_masking_validated"] = json!(passed);
    report["vmess_aead_udp_over_tcp_contract"]["udp_command_validated"] = json!(passed);
    report["vmess_aead_udp_over_tcp_contract"]["target_metadata_validated"] = json!(passed);
    report["vmess_aead_udp_over_tcp_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "eauth_crc_count": outcome.server_summary.eauth_crc_count,
        "request_header_aead_count": outcome.server_summary.request_header_aead_count,
        "response_header_aead_count": outcome.server_summary.response_header_aead_count,
        "udp_command_count": outcome.server_summary.udp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "shake128_chunk_masking_count": outcome.server_summary.shake128_chunk_masking_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vmess_aead_udp_over_tcp_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.request_header_len);
    report["benchmark"]["request_chunk_len"] = json!(outcome.request_chunk_len);
    report["benchmark"]["response_header_len"] = json!(outcome.response_header_len);
    report["benchmark"]["response_chunk_len"] = json!(outcome.response_chunk_len);
    report["protocol_matrix"]["vmess_aead_udp_over_tcp_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct VMessAeadUdpServerSummary {
    accepted: usize,
    eauth_crc_count: usize,
    request_header_aead_count: usize,
    response_header_aead_count: usize,
    udp_command_count: usize,
    target_metadata_count: usize,
    shake128_chunk_masking_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_vmess_aead_udp_server(
    opts: &Stage66Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VMessAeadUdpServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage66 bind loopback VMess server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage66 VMess server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => return Err(format!("stage66 VMess listener is not IPv4: {addr}")),
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage66 VMess nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let uuid = opts.uuid.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_vmess_aead_udp(listener, iterations, &uuid, &target, &payload, timeout)
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vmess_aead_udp(
    listener: TcpListener,
    iterations: usize,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    timeout: Duration,
) -> Result<VMessAeadUdpServerSummary, String> {
    let mut summary = VMessAeadUdpServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage66 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage66 server set write timeout failed: {err}"))?;
                handle_vmess_aead_udp(
                    &mut stream,
                    uuid,
                    expected_target,
                    expected_payload,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage66 VMess server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage66 VMess accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vmess_aead_udp(
    stream: &mut TcpStream,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    summary: &mut VMessAeadUdpServerSummary,
) -> Result<(), String> {
    let request = vmess::read_aead_udp_over_tcp_request_from_stream(stream, uuid)
        .map_err(|err| format!("stage66 read VMess UDP request failed: {err}"))?;
    if !request.request.eauth_crc_validated {
        return Err("stage66 VMess EAuthID checksum was not validated".to_owned());
    }
    if request.request.command != dae_outbound::VMessNetwork::Udp.byte() {
        return Err(format!(
            "stage66 VMess command mismatch: got {}, want {}",
            request.request.command,
            dae_outbound::VMessNetwork::Udp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage66 VMess target mismatch: got {}, want {}",
            request.request.target, expected_target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage66 VMess UDP request payload mismatch".to_owned());
    }
    if request.packet_len != expected_payload.len() {
        return Err(format!(
            "stage66 VMess UDP packet length mismatch: got {}, want {}",
            request.packet_len,
            expected_payload.len()
        ));
    }
    let response = vmess::aead_tcp_response_packet(&request.request, &request.request.payload)
        .map_err(|err| format!("stage66 encode VMess UDP response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage66 write VMess UDP echo failed: {err}"))?;

    summary.eauth_crc_count += 1;
    summary.request_header_aead_count += 1;
    summary.response_header_aead_count += 1;
    summary.udp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.shake128_chunk_masking_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    Ok(())
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
