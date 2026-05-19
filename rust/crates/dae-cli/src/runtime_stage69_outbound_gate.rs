use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::{shared_transport, vmess};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_TARGET: &str = "stage69-vmess-ws.example:443";
const DEFAULT_WS_HOST: &str = "stage69-vmess-proxy.example";
const DEFAULT_WS_PATH: &str = "/dae-vmess-ws";
const DEFAULT_PAYLOAD: &[u8] = b"stage69-vmess-ws-ping";

pub(crate) fn run_stage69_vmess_websocket_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage69Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage69_report(&opts);
    let passed = report["vmess_websocket_smoke_passed"]
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
struct Stage69Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    uuid: String,
    target: String,
    ws_host: String,
    ws_path: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage69Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            ws_host: DEFAULT_WS_HOST.to_owned(),
            ws_path: DEFAULT_WS_PATH.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage69Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage69 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage69 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage69 --target")?,
                "--ws-host" => opts.ws_host = next_value(&mut iter, "stage69 --ws-host")?,
                "--ws-path" => opts.ws_path = next_value(&mut iter, "stage69 --ws-path")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage69 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage69 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage69 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--ws-host=") => {
                    opts.ws_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--ws-path=") => {
                    opts.ws_path = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage69 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage69 --benchmark-iters must be greater than zero",
            ));
        }
        vmess::vmess_cmd_key_from_uuid(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage69 uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage69 target is invalid: {err}")))?;
        if opts.ws_host.is_empty() {
            return Err(RunnerOutput::usage("stage69 --ws-host must not be empty"));
        }
        if opts.ws_path.is_empty() {
            opts.ws_path = "/".to_owned();
        } else if !opts.ws_path.starts_with('/') {
            opts.ws_path = format!("/{}", opts.ws_path);
        }
        Ok(opts)
    }
}

fn stage69_report(opts: &Stage69Options) -> Value {
    let cmd_key = match vmess::vmess_cmd_key_from_uuid(&opts.uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage69-vmess-websocket-dataplane-admission",
                "stage": "stage69",
                "blocked": true,
                "blockers": [format!("stage69 uuid is invalid: {err}")]
            });
        }
    };
    if let Err(err) = dae_outbound::VMessMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage69-vmess-websocket-dataplane-admission",
            "stage": "stage69",
            "blocked": true,
            "blockers": [format!("stage69 target is invalid: {err}")]
        });
    }
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage69-vmess-websocket-dataplane-admission",
        "stage": "stage69",
        "evidence_class": "opt-in-protocol-vmess-aead-websocket-shared-transport-true-dataplane-smoke",
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
    report["vmess_aead_udp_over_tcp_admitted"] = json!(true);
    report["vmess_udp_packet_addr_admitted"] = json!(true);
    report["vmess_mux_admitted"] = json!(true);
    report["vmess_websocket_smoke_passed"] = json!(false);
    report["vmess_websocket_admitted"] = json!(false);
    report["vmess_shared_transport_partial_admitted"] = json!(false);
    report["vmess_protocol_partial_admitted"] = json!(true);
    report["vmess_protocol_true_dataplane_admitted"] = json!(false);
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
    report["vmess_websocket_contract"] = json!({
        "protocol": "vmess",
        "scope": "VMess AEAD TCP request/response carried by WebSocket binary frames over Rust TCP stream",
        "uuid": opts.uuid,
        "cmd_key_hex": hex_encode(&cmd_key),
        "network": "tcp",
        "underlay_network": "tcp",
        "transport": "websocket",
        "security": "auto/aes-128-gcm",
        "security_byte": vmess::VMESS_AEAD_SECURITY_AES_128_GCM,
        "target": opts.target,
        "ws_host": opts.ws_host,
        "ws_path": opts.ws_path,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "server": null,
        "http_upgrade_validated": false,
        "websocket_binary_frame_validated": false,
        "eauth_crc_validated": false,
        "request_header_aead_validated": false,
        "response_header_aead_validated": false,
        "shake128_chunk_masking_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "tls_wss_deferred": "WSS/TLS/uTLS and TLS fragmentation require separate TLS underlay gates",
        "other_shared_transport_deferred": "VMess gRPC, HTTP/H2, HTTPUpgrade, Meek, and xHTTP require separate transport gates",
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
        "ns_per_vmess_websocket_exchange": null,
        "scope": "VMess AEAD TCP request/response over WebSocket binary frames on a SO_MARKed Rust TCP socket",
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
        "vmess_aead_udp_over_tcp_admitted": true,
        "vmess_udp_packet_addr_admitted": true,
        "vmess_mux_admitted": true,
        "vmess_websocket_admitted": false,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Trojan TLS and Trojan-Go shared transport rows are still incomplete",
        "VLESS TLS/REALITY/XTLS Vision/shared transport/xHTTP xmux rows are still incomplete",
        "VMess WSS/TLS/uTLS, gRPC, HTTP/H2, HTTPUpgrade, Meek, xHTTP, and full shared transport rows are still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage69/vmess_websocket_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage69_vmess_websocket_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage69 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage69 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage69 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage69-vmess-websocket-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage69",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "/root/project/outbound/protocol/vmess/dialer.go",
        "/root/project/outbound/transport/ws/ws.go",
        "rust/crates/dae-outbound/src/vmess/dataplane.rs",
        "rust/crates/dae-outbound/src/shared_transport/dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage69 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage69_smoke(opts) {
        Ok(outcome) => apply_stage69_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage69Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: VMessWebSocketServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    request_header_len: usize,
    request_chunk_len: usize,
    response_header_len: usize,
    response_chunk_len: usize,
    websocket_request_frame_len: usize,
    websocket_response_frame_len: usize,
    cmd_key_hex: String,
}

fn run_stage69_smoke(opts: &Stage69Options) -> Result<Stage69Outcome, String> {
    let (server_addr, listener_report, handle) = spawn_vmess_websocket_server(opts)?;
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
        .map_err(|err| format!("stage69 magic_tcp_connect failed: {err}"))?;
        let report = vmess::aead_tcp_exchange_over_websocket_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.uuid,
            &opts.target,
            &opts.ws_host,
            &opts.ws_path,
            &opts.payload,
        )
        .map_err(|err| format!("stage69 VMess WebSocket exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage69 VMess WebSocket payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_exchange = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage69 VMess WebSocket server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage69 VMess WebSocket server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let last_exchange =
        last_exchange.ok_or_else(|| "stage69 missing exchange report".to_owned())?;
    Ok(Stage69Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage69 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        request_header_len: last_exchange.request_header_len,
        request_chunk_len: last_exchange.request_chunk_len,
        response_header_len: last_exchange.response_header_len,
        response_chunk_len: last_exchange.response_chunk_len,
        websocket_request_frame_len: last_exchange.websocket_request_frame_len,
        websocket_response_frame_len: last_exchange.websocket_response_frame_len,
        cmd_key_hex: last_exchange.cmd_key_hex,
    })
}

fn apply_stage69_outcome(report: &mut Value, outcome: Stage69Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.http_upgrade_count == outcome.exchange_count
        && outcome.server_summary.websocket_binary_request_count == outcome.exchange_count
        && outcome.server_summary.eauth_crc_count == outcome.exchange_count
        && outcome.server_summary.request_header_aead_count == outcome.exchange_count
        && outcome.server_summary.response_header_aead_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vmess_websocket_smoke_passed"] = json!(passed);
    report["vmess_websocket_admitted"] = json!(passed);
    report["vmess_shared_transport_partial_admitted"] = json!(passed);
    report["vmess_protocol_partial_admitted"] = json!(true);
    report["vmess_websocket_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["vmess_websocket_contract"]["cmd_key_hex"] = json!(outcome.cmd_key_hex);
    report["vmess_websocket_contract"]["http_upgrade_validated"] = json!(passed);
    report["vmess_websocket_contract"]["websocket_binary_frame_validated"] = json!(passed);
    report["vmess_websocket_contract"]["eauth_crc_validated"] = json!(passed);
    report["vmess_websocket_contract"]["request_header_aead_validated"] = json!(passed);
    report["vmess_websocket_contract"]["response_header_aead_validated"] = json!(passed);
    report["vmess_websocket_contract"]["shake128_chunk_masking_validated"] = json!(passed);
    report["vmess_websocket_contract"]["tcp_command_validated"] = json!(passed);
    report["vmess_websocket_contract"]["target_metadata_validated"] = json!(passed);
    report["vmess_websocket_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "http_upgrade_count": outcome.server_summary.http_upgrade_count,
        "websocket_binary_request_count": outcome.server_summary.websocket_binary_request_count,
        "eauth_crc_count": outcome.server_summary.eauth_crc_count,
        "request_header_aead_count": outcome.server_summary.request_header_aead_count,
        "response_header_aead_count": outcome.server_summary.response_header_aead_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "ws_hosts": outcome.server_summary.ws_hosts,
        "ws_paths": outcome.server_summary.ws_paths,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vmess_websocket_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.request_header_len);
    report["benchmark"]["request_chunk_len"] = json!(outcome.request_chunk_len);
    report["benchmark"]["response_header_len"] = json!(outcome.response_header_len);
    report["benchmark"]["response_chunk_len"] = json!(outcome.response_chunk_len);
    report["benchmark"]["websocket_request_frame_len"] = json!(outcome.websocket_request_frame_len);
    report["benchmark"]["websocket_response_frame_len"] =
        json!(outcome.websocket_response_frame_len);
    report["protocol_matrix"]["vmess_websocket_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct VMessWebSocketServerSummary {
    accepted: usize,
    http_upgrade_count: usize,
    websocket_binary_request_count: usize,
    eauth_crc_count: usize,
    request_header_aead_count: usize,
    response_header_aead_count: usize,
    tcp_command_count: usize,
    target_metadata_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    ws_hosts: Vec<String>,
    ws_paths: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_vmess_websocket_server(
    opts: &Stage69Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VMessWebSocketServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage69 bind loopback VMess WebSocket server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage69 VMess WebSocket server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage69 VMess WebSocket listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage69 VMess WebSocket nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let uuid = opts.uuid.clone();
    let target = opts.target.clone();
    let ws_host = opts.ws_host.clone();
    let ws_path = opts.ws_path.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_vmess_websocket(
            listener, iterations, &uuid, &target, &ws_host, &ws_path, &payload, timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vmess_websocket(
    listener: TcpListener,
    iterations: usize,
    uuid: &str,
    expected_target: &str,
    expected_host: &str,
    expected_path: &str,
    expected_payload: &[u8],
    timeout: Duration,
) -> Result<VMessWebSocketServerSummary, String> {
    let mut summary = VMessWebSocketServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage69 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage69 server set write timeout failed: {err}"))?;
                handle_vmess_websocket(
                    &mut stream,
                    uuid,
                    expected_target,
                    expected_host,
                    expected_path,
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
                    "stage69 VMess WebSocket server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage69 VMess WebSocket accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vmess_websocket(
    stream: &mut TcpStream,
    uuid: &str,
    expected_target: &str,
    expected_host: &str,
    expected_path: &str,
    expected_payload: &[u8],
    summary: &mut VMessWebSocketServerSummary,
) -> Result<(), String> {
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage69 read WebSocket upgrade failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage69 WebSocket upgrade is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")) {
        return Err("stage69 WebSocket upgrade path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {expected_host}\r\n")) {
        return Err("stage69 WebSocket Host header mismatch".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage69 WebSocket Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                shared_transport::WS_ACCEPT_SAMPLE
            )
            .as_bytes(),
        )
        .map_err(|err| format!("stage69 write WebSocket upgrade response failed: {err}"))?;
    let request = vmess::read_aead_tcp_request_from_websocket_stream(stream, uuid)
        .map_err(|err| format!("stage69 read VMess WebSocket request failed: {err}"))?;
    if !request.request.eauth_crc_validated {
        return Err("stage69 VMess EAuthID checksum was not validated".to_owned());
    }
    if request.request.command != dae_outbound::VMessNetwork::Tcp.byte() {
        return Err(format!(
            "stage69 VMess command mismatch: got {}, want {}",
            request.request.command,
            dae_outbound::VMessNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage69 VMess target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage69 VMess WebSocket payload mismatch".to_owned());
    }
    let response = vmess::aead_tcp_response_packet(&request.request, &request.request.payload)
        .map_err(|err| format!("stage69 encode VMess WebSocket response failed: {err}"))?;
    let response = shared_transport::websocket_server_binary_frame(&response)
        .map_err(|err| format!("stage69 encode WebSocket response frame failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage69 write VMess WebSocket echo failed: {err}"))?;

    summary.http_upgrade_count += 1;
    summary.websocket_binary_request_count += 1;
    summary.eauth_crc_count += 1;
    summary.request_header_aead_count += 1;
    summary.response_header_aead_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
    summary.ws_hosts.push(expected_host.to_owned());
    summary.ws_paths.push(expected_path.to_owned());
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

fn parse_u32(value: &str, context: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}

fn parse_u64(value: &str, context: &str) -> Result<u64, RunnerOutput> {
    value
        .parse::<u64>()
        .map_err(|_| RunnerOutput::usage(format!("invalid {context}: {value}")))
}
