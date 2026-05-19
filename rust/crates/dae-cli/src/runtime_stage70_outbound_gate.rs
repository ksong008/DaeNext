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
const DEFAULT_TARGET: &str = "stage70-vmess-httpupgrade.example:443";
const DEFAULT_HTTPUPGRADE_HOST: &str = "stage70-vmess-proxy.example";
const DEFAULT_HTTPUPGRADE_PATH: &str = "/dae-vmess-httpupgrade";
const DEFAULT_PAYLOAD: &[u8] = b"stage70-vmess-httpupgrade-ping";

pub(crate) fn run_stage70_vmess_httpupgrade_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage70Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage70_report(&opts);
    let passed = report["vmess_httpupgrade_smoke_passed"]
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
struct Stage70Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    uuid: String,
    target: String,
    httpupgrade_host: String,
    httpupgrade_path: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage70Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            httpupgrade_host: DEFAULT_HTTPUPGRADE_HOST.to_owned(),
            httpupgrade_path: DEFAULT_HTTPUPGRADE_PATH.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage70Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage70 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage70 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage70 --target")?,
                "--httpupgrade-host" => {
                    opts.httpupgrade_host = next_value(&mut iter, "stage70 --httpupgrade-host")?
                }
                "--httpupgrade-path" => {
                    opts.httpupgrade_path = next_value(&mut iter, "stage70 --httpupgrade-path")?
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage70 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage70 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage70 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--httpupgrade-host=") => {
                    opts.httpupgrade_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--httpupgrade-path=") => {
                    opts.httpupgrade_path = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage70 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage70 --benchmark-iters must be greater than zero",
            ));
        }
        vmess::vmess_cmd_key_from_uuid(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage70 uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage70 target is invalid: {err}")))?;
        if opts.httpupgrade_host.is_empty() {
            return Err(RunnerOutput::usage(
                "stage70 --httpupgrade-host must not be empty",
            ));
        }
        if opts.httpupgrade_path.is_empty() {
            opts.httpupgrade_path = "/".to_owned();
        } else if !opts.httpupgrade_path.starts_with('/') {
            opts.httpupgrade_path = format!("/{}", opts.httpupgrade_path);
        }
        Ok(opts)
    }
}

fn stage70_report(opts: &Stage70Options) -> Value {
    let cmd_key = match vmess::vmess_cmd_key_from_uuid(&opts.uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage70-vmess-httpupgrade-dataplane-admission",
                "stage": "stage70",
                "blocked": true,
                "blockers": [format!("stage70 uuid is invalid: {err}")]
            });
        }
    };
    if let Err(err) = dae_outbound::VMessMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage70-vmess-httpupgrade-dataplane-admission",
            "stage": "stage70",
            "blocked": true,
            "blockers": [format!("stage70 target is invalid: {err}")]
        });
    }
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage70-vmess-httpupgrade-dataplane-admission",
        "stage": "stage70",
        "evidence_class": "opt-in-protocol-vmess-aead-httpupgrade-shared-transport-true-dataplane-smoke",
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
    report["vmess_websocket_admitted"] = json!(true);
    report["vmess_httpupgrade_smoke_passed"] = json!(false);
    report["vmess_httpupgrade_admitted"] = json!(false);
    report["vmess_shared_transport_partial_admitted"] = json!(true);
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
    report["vmess_httpupgrade_contract"] = json!({
        "protocol": "vmess",
        "scope": "VMess AEAD TCP request/response carried directly after HTTPUpgrade 101 over a Rust TCP stream",
        "uuid": opts.uuid,
        "cmd_key_hex": hex_encode(&cmd_key),
        "network": "tcp",
        "underlay_network": "tcp",
        "transport": "httpupgrade",
        "security": "auto/aes-128-gcm",
        "security_byte": vmess::VMESS_AEAD_SECURITY_AES_128_GCM,
        "target": opts.target,
        "httpupgrade_host": opts.httpupgrade_host,
        "httpupgrade_path": opts.httpupgrade_path,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "server": null,
        "http_upgrade_validated": false,
        "httpupgrade_tunnel_validated": false,
        "eauth_crc_validated": false,
        "request_header_aead_validated": false,
        "response_header_aead_validated": false,
        "shake128_chunk_masking_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "tls_https_deferred": "HTTPS HTTPUpgrade, TLS/uTLS, and TLS fragmentation require separate TLS underlay gates",
        "other_shared_transport_deferred": "VMess WSS, gRPC, HTTP/H2, Meek, and xHTTP require separate transport gates",
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
        "ns_per_vmess_httpupgrade_exchange": null,
        "scope": "VMess AEAD TCP request/response after HTTPUpgrade 101 on a SO_MARKed Rust TCP socket",
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
        "vmess_websocket_admitted": true,
        "vmess_httpupgrade_admitted": false,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Trojan TLS and Trojan-Go shared transport rows are still incomplete",
        "VLESS TLS/REALITY/XTLS Vision/shared transport/xHTTP xmux rows are still incomplete",
        "VMess HTTPS HTTPUpgrade/TLS/uTLS, WSS, gRPC, HTTP/H2, Meek, xHTTP, and full shared transport rows are still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage70/vmess_httpupgrade_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage70_vmess_httpupgrade_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage70 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage70 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage70 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage70-vmess-httpupgrade-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage70",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "/root/project/outbound/protocol/vmess/dialer.go",
        "/root/project/outbound/transport/httpupgrade/httpupgrade.go",
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
            "stage70 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage70_smoke(opts) {
        Ok(outcome) => apply_stage70_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage70Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: VMessHttpUpgradeServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    request_header_len: usize,
    request_chunk_len: usize,
    response_header_len: usize,
    response_chunk_len: usize,
    httpupgrade_request_len: usize,
    httpupgrade_response_head_len: usize,
    cmd_key_hex: String,
}

fn run_stage70_smoke(opts: &Stage70Options) -> Result<Stage70Outcome, String> {
    let (server_addr, listener_report, handle) = spawn_vmess_httpupgrade_server(opts)?;
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
        .map_err(|err| format!("stage70 magic_tcp_connect failed: {err}"))?;
        let report = vmess::aead_tcp_exchange_over_httpupgrade_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.uuid,
            &opts.target,
            &opts.httpupgrade_host,
            &opts.httpupgrade_path,
            &opts.payload,
        )
        .map_err(|err| format!("stage70 VMess HttpUpgrade exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage70 VMess HttpUpgrade payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_exchange = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage70 VMess HttpUpgrade server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage70 VMess HttpUpgrade server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let last_exchange =
        last_exchange.ok_or_else(|| "stage70 missing exchange report".to_owned())?;
    Ok(Stage70Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage70 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        request_header_len: last_exchange.request_header_len,
        request_chunk_len: last_exchange.request_chunk_len,
        response_header_len: last_exchange.response_header_len,
        response_chunk_len: last_exchange.response_chunk_len,
        httpupgrade_request_len: last_exchange.httpupgrade_request_len,
        httpupgrade_response_head_len: last_exchange.httpupgrade_response_head_len,
        cmd_key_hex: last_exchange.cmd_key_hex,
    })
}

fn apply_stage70_outcome(report: &mut Value, outcome: Stage70Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.http_upgrade_count == outcome.exchange_count
        && outcome.server_summary.httpupgrade_tunnel_count == outcome.exchange_count
        && outcome.server_summary.eauth_crc_count == outcome.exchange_count
        && outcome.server_summary.request_header_aead_count == outcome.exchange_count
        && outcome.server_summary.response_header_aead_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vmess_httpupgrade_smoke_passed"] = json!(passed);
    report["vmess_httpupgrade_admitted"] = json!(passed);
    report["vmess_shared_transport_partial_admitted"] = json!(true);
    report["vmess_protocol_partial_admitted"] = json!(true);
    report["vmess_httpupgrade_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["vmess_httpupgrade_contract"]["cmd_key_hex"] = json!(outcome.cmd_key_hex);
    report["vmess_httpupgrade_contract"]["http_upgrade_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["httpupgrade_tunnel_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["eauth_crc_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["request_header_aead_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["response_header_aead_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["shake128_chunk_masking_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["tcp_command_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["target_metadata_validated"] = json!(passed);
    report["vmess_httpupgrade_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "httpupgrade_tunnel_count": outcome.server_summary.httpupgrade_tunnel_count,
        "eauth_crc_count": outcome.server_summary.eauth_crc_count,
        "request_header_aead_count": outcome.server_summary.request_header_aead_count,
        "response_header_aead_count": outcome.server_summary.response_header_aead_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "httpupgrade_hosts": outcome.server_summary.httpupgrade_hosts,
        "httpupgrade_paths": outcome.server_summary.httpupgrade_paths,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vmess_httpupgrade_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.request_header_len);
    report["benchmark"]["request_chunk_len"] = json!(outcome.request_chunk_len);
    report["benchmark"]["response_header_len"] = json!(outcome.response_header_len);
    report["benchmark"]["response_chunk_len"] = json!(outcome.response_chunk_len);
    report["benchmark"]["httpupgrade_request_len"] = json!(outcome.httpupgrade_request_len);
    report["benchmark"]["httpupgrade_response_head_len"] =
        json!(outcome.httpupgrade_response_head_len);
    report["protocol_matrix"]["vmess_httpupgrade_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct VMessHttpUpgradeServerSummary {
    accepted: usize,
    http_upgrade_count: usize,
    httpupgrade_tunnel_count: usize,
    eauth_crc_count: usize,
    request_header_aead_count: usize,
    response_header_aead_count: usize,
    tcp_command_count: usize,
    target_metadata_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    httpupgrade_hosts: Vec<String>,
    httpupgrade_paths: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_vmess_httpupgrade_server(
    opts: &Stage70Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VMessHttpUpgradeServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage70 bind loopback VMess HttpUpgrade server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage70 VMess HttpUpgrade server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage70 VMess HttpUpgrade listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage70 VMess HttpUpgrade nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let uuid = opts.uuid.clone();
    let target = opts.target.clone();
    let httpupgrade_host = opts.httpupgrade_host.clone();
    let httpupgrade_path = opts.httpupgrade_path.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_vmess_httpupgrade(
            listener,
            iterations,
            &uuid,
            &target,
            &httpupgrade_host,
            &httpupgrade_path,
            &payload,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vmess_httpupgrade(
    listener: TcpListener,
    iterations: usize,
    uuid: &str,
    expected_target: &str,
    expected_host: &str,
    expected_path: &str,
    expected_payload: &[u8],
    timeout: Duration,
) -> Result<VMessHttpUpgradeServerSummary, String> {
    let mut summary = VMessHttpUpgradeServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage70 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage70 server set write timeout failed: {err}"))?;
                handle_vmess_httpupgrade(
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
                    "stage70 VMess HttpUpgrade server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage70 VMess HttpUpgrade accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vmess_httpupgrade(
    stream: &mut TcpStream,
    uuid: &str,
    expected_target: &str,
    expected_host: &str,
    expected_path: &str,
    expected_payload: &[u8],
    summary: &mut VMessHttpUpgradeServerSummary,
) -> Result<(), String> {
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage70 read HttpUpgrade upgrade failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage70 HttpUpgrade upgrade is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")) {
        return Err("stage70 HttpUpgrade upgrade path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {expected_host}\r\n")) {
        return Err("stage70 HttpUpgrade Host header mismatch".to_owned());
    }
    if !request_head.contains("Connection: upgrade\r\n") {
        return Err("stage70 HttpUpgrade Connection header missing".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage70 HttpUpgrade Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .map_err(|err| format!("stage70 write HttpUpgrade upgrade response failed: {err}"))?;
    let request = vmess::read_aead_tcp_request_from_httpupgrade_stream(stream, uuid)
        .map_err(|err| format!("stage70 read VMess HttpUpgrade request failed: {err}"))?;
    if !request.request.eauth_crc_validated {
        return Err("stage70 VMess EAuthID checksum was not validated".to_owned());
    }
    if request.request.command != dae_outbound::VMessNetwork::Tcp.byte() {
        return Err(format!(
            "stage70 VMess command mismatch: got {}, want {}",
            request.request.command,
            dae_outbound::VMessNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage70 VMess target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage70 VMess HttpUpgrade payload mismatch".to_owned());
    }
    let response = vmess::aead_tcp_response_packet(&request.request, &request.request.payload)
        .map_err(|err| format!("stage70 encode VMess HttpUpgrade response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage70 write VMess HttpUpgrade echo failed: {err}"))?;

    summary.http_upgrade_count += 1;
    summary.httpupgrade_tunnel_count += 1;
    summary.eauth_crc_count += 1;
    summary.request_header_aead_count += 1;
    summary.response_header_aead_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
    summary.httpupgrade_hosts.push(expected_host.to_owned());
    summary.httpupgrade_paths.push(expected_path.to_owned());
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
