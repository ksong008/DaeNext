use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::{http_proxy::HttpConnectOptions, vmess};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_TARGET: &str = "stage73-vmess-http-target.example:443";
const DEFAULT_HTTP_PROXY_TARGET: &str = "stage73-vmess-http-proxy.example:443";
const DEFAULT_HTTP_HOST: &str = "stage73-vmess-http.example";
const DEFAULT_HTTP_PATH: &str = "/dae-stage73-http";
const DEFAULT_PAYLOAD: &[u8] = b"stage73-vmess-http-put-ping";

pub(crate) fn run_stage73_vmess_http_transport_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage73Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage73_report(&opts);
    let passed = report["vmess_http_transport_put_smoke_passed"]
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
struct Stage73Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    uuid: String,
    target: String,
    http_proxy_target: String,
    http_host: String,
    http_path: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage73Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            http_proxy_target: DEFAULT_HTTP_PROXY_TARGET.to_owned(),
            http_host: DEFAULT_HTTP_HOST.to_owned(),
            http_path: DEFAULT_HTTP_PATH.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage73Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage73 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage73 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage73 --target")?,
                "--http-proxy-target" => {
                    opts.http_proxy_target = next_value(&mut iter, "stage73 --http-proxy-target")?
                }
                "--http-host" => opts.http_host = next_value(&mut iter, "stage73 --http-host")?,
                "--http-path" => opts.http_path = next_value(&mut iter, "stage73 --http-path")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage73 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage73 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage73 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--http-proxy-target=") => {
                    opts.http_proxy_target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--http-host=") => {
                    opts.http_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--http-path=") => {
                    opts.http_path = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage73 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage73 --benchmark-iters must be greater than zero",
            ));
        }
        vmess::vmess_cmd_key_from_uuid(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage73 uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage73 target is invalid: {err}")))?;
        if opts.http_proxy_target.is_empty() {
            return Err(RunnerOutput::usage(
                "stage73 --http-proxy-target must not be empty",
            ));
        }
        if opts.http_host.is_empty() {
            return Err(RunnerOutput::usage("stage73 --http-host must not be empty"));
        }
        if opts.http_path.is_empty() {
            opts.http_path = "/".to_owned();
        } else if !opts.http_path.starts_with('/') {
            opts.http_path = format!("/{}", opts.http_path);
        }
        Ok(opts)
    }

    fn http_options(&self) -> HttpConnectOptions {
        let mut options = HttpConnectOptions::connect(&self.http_proxy_target);
        options.host_override = self.http_host.clone();
        options.transport.enabled = true;
        options.transport.path = self.http_path.clone();
        options
    }
}

fn stage73_report(opts: &Stage73Options) -> Value {
    let cmd_key = match vmess::vmess_cmd_key_from_uuid(&opts.uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage73-vmess-http-transport-dataplane-admission",
                "stage": "stage73",
                "blocked": true,
                "blockers": [format!("stage73 uuid is invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage73-vmess-http-transport-dataplane-admission",
        "stage": "stage73",
        "evidence_class": "opt-in-protocol-vmess-aead-http-transport-put-shared-transport-dataplane-smoke",
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
    report["vmess_httpupgrade_admitted"] = json!(true);
    report["vmess_grpc_hunk_admitted"] = json!(true);
    report["vmess_grpc_full_http2_admitted"] = json!(false);
    report["vmess_meek_polling_admitted"] = json!(true);
    report["vmess_meek_full_https_roundtripper_admitted"] = json!(false);
    report["vmess_http_transport_put_smoke_passed"] = json!(false);
    report["vmess_http_transport_put_admitted"] = json!(false);
    report["vmess_http_h2_full_admitted"] = json!(false);
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
    report["vmess_http_transport_contract"] = json!({
        "protocol": "vmess",
        "scope": "VMess AEAD TCP request/response carried after HTTP transport PUT 200 over a Rust TCP stream",
        "uuid": opts.uuid,
        "cmd_key_hex": hex_encode(&cmd_key),
        "network": "tcp",
        "underlay_network": "tcp",
        "transport": "http-transport-put",
        "full_http2_stack": false,
        "security": "auto/aes-128-gcm",
        "security_byte": vmess::VMESS_AEAD_SECURITY_AES_128_GCM,
        "target": opts.target,
        "http_proxy_target": opts.http_proxy_target,
        "http_host": opts.http_host,
        "http_path": opts.http_path,
        "http_method": "PUT",
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "server": null,
        "http_transport_put_validated": false,
        "http_status_200_validated": false,
        "eauth_crc_validated": false,
        "request_header_aead_validated": false,
        "response_header_aead_validated": false,
        "shake128_chunk_masking_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "http2_tls_deferred": "HTTPS proxy TLS/uTLS, ALPN, HTTP/2 h2 pool, request-body pipe, and h2 route context require separate gates",
        "other_shared_transport_deferred": "VMess WSS, xHTTP, full gRPC HTTP/2, full Meek HTTPS lifecycle, and full HTTP/H2 require separate transport gates",
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
        "ns_per_vmess_http_transport_exchange": null,
        "scope": "VMess AEAD TCP request/response carried after HTTP transport PUT 200 on a SO_MARKed Rust TCP socket",
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
        "vmess_httpupgrade_admitted": true,
        "vmess_grpc_hunk_admitted": true,
        "vmess_meek_polling_admitted": true,
        "vmess_http_transport_put_admitted": false,
        "vmess_http_h2_full_admitted": false,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Trojan TLS and Trojan-Go shared transport rows are still incomplete",
        "VLESS TLS/REALITY/XTLS Vision/shared transport/xHTTP xmux rows are still incomplete",
        "VMess full HTTP/2 h2 pool/TLS/uTLS, WSS, xHTTP, full gRPC HTTP/2/TLS, full Meek HTTPS, HTTPS HTTPUpgrade/TLS/uTLS, and full shared transport rows are still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage73/vmess_http_transport_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage73_vmess_http_transport_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage73 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage73 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage73 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage73-vmess-http-transport-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage73",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.12",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "/root/project/outbound/dialer/v2ray/v2ray.go",
        "/root/project/outbound/protocol/http/http.go",
        "/root/project/outbound/protocol/http/conn.go",
        "rust/crates/dae-outbound/src/vmess/dataplane.rs",
        "rust/crates/dae-outbound/src/http_proxy/request.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage73 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage73_smoke(opts) {
        Ok(outcome) => apply_stage73_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage73Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: VMessHttpTransportServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    request_header_len: usize,
    request_chunk_len: usize,
    response_header_len: usize,
    response_chunk_len: usize,
    http_transport_request_len: usize,
    http_transport_response_head_len: usize,
    cmd_key_hex: String,
}

fn run_stage73_smoke(opts: &Stage73Options) -> Result<Stage73Outcome, String> {
    let (server_addr, listener_report, handle) = spawn_vmess_http_transport_server(opts)?;
    let mut last_dial_report = None;
    let mut last_exchange = None;
    let http_options = opts.http_options();
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
        .map_err(|err| format!("stage73 magic_tcp_connect failed: {err}"))?;
        let report = vmess::aead_tcp_exchange_over_http_transport_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.uuid,
            &opts.target,
            &http_options,
            &opts.payload,
        )
        .map_err(|err| format!("stage73 VMess HTTP transport exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage73 VMess HTTP transport payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_exchange = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage73 VMess HTTP transport server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage73 VMess HTTP transport server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let last_exchange =
        last_exchange.ok_or_else(|| "stage73 missing exchange report".to_owned())?;
    Ok(Stage73Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage73 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        request_header_len: last_exchange.request_header_len,
        request_chunk_len: last_exchange.request_chunk_len,
        response_header_len: last_exchange.response_header_len,
        response_chunk_len: last_exchange.response_chunk_len,
        http_transport_request_len: last_exchange.http_transport_request_len,
        http_transport_response_head_len: last_exchange.http_transport_response_head_len,
        cmd_key_hex: last_exchange.cmd_key_hex,
    })
}

fn apply_stage73_outcome(report: &mut Value, outcome: Stage73Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.http_transport_put_count == outcome.exchange_count
        && outcome.server_summary.http_status_200_count == outcome.exchange_count
        && outcome.server_summary.eauth_crc_count == outcome.exchange_count
        && outcome.server_summary.request_header_aead_count == outcome.exchange_count
        && outcome.server_summary.response_header_aead_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vmess_http_transport_put_smoke_passed"] = json!(passed);
    report["vmess_http_transport_put_admitted"] = json!(passed);
    report["vmess_shared_transport_partial_admitted"] = json!(true);
    report["vmess_protocol_partial_admitted"] = json!(true);
    report["vmess_http_transport_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["vmess_http_transport_contract"]["cmd_key_hex"] = json!(outcome.cmd_key_hex);
    report["vmess_http_transport_contract"]["http_transport_put_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["http_status_200_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["eauth_crc_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["request_header_aead_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["response_header_aead_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["shake128_chunk_masking_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["tcp_command_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["target_metadata_validated"] = json!(passed);
    report["vmess_http_transport_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "http_transport_put_count": outcome.server_summary.http_transport_put_count,
        "http_status_200_count": outcome.server_summary.http_status_200_count,
        "eauth_crc_count": outcome.server_summary.eauth_crc_count,
        "request_header_aead_count": outcome.server_summary.request_header_aead_count,
        "response_header_aead_count": outcome.server_summary.response_header_aead_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "http_request_uris": outcome.server_summary.http_request_uris,
        "http_hosts": outcome.server_summary.http_hosts,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vmess_http_transport_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.request_header_len);
    report["benchmark"]["request_chunk_len"] = json!(outcome.request_chunk_len);
    report["benchmark"]["response_header_len"] = json!(outcome.response_header_len);
    report["benchmark"]["response_chunk_len"] = json!(outcome.response_chunk_len);
    report["benchmark"]["http_transport_request_len"] = json!(outcome.http_transport_request_len);
    report["benchmark"]["http_transport_response_head_len"] =
        json!(outcome.http_transport_response_head_len);
    report["protocol_matrix"]["vmess_http_transport_put_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct VMessHttpTransportServerSummary {
    accepted: usize,
    http_transport_put_count: usize,
    http_status_200_count: usize,
    eauth_crc_count: usize,
    request_header_aead_count: usize,
    response_header_aead_count: usize,
    tcp_command_count: usize,
    target_metadata_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    http_request_uris: Vec<String>,
    http_hosts: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_vmess_http_transport_server(
    opts: &Stage73Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VMessHttpTransportServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp).map_err(|err| {
        format!("stage73 bind loopback VMess HTTP transport server failed: {err}")
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage73 VMess HTTP transport server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage73 VMess HTTP transport listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage73 VMess HTTP transport nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let uuid = opts.uuid.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let http_options = opts.http_options();
    let handle = thread::spawn(move || {
        accept_vmess_http_transport(
            listener,
            iterations,
            &uuid,
            &target,
            &payload,
            &http_options,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vmess_http_transport(
    listener: TcpListener,
    iterations: usize,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    http_options: &HttpConnectOptions,
    timeout: Duration,
) -> Result<VMessHttpTransportServerSummary, String> {
    let mut summary = VMessHttpTransportServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage73 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage73 server set write timeout failed: {err}"))?;
                handle_vmess_http_transport(
                    &mut stream,
                    uuid,
                    expected_target,
                    expected_payload,
                    http_options,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage73 VMess HTTP transport server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage73 VMess HTTP transport accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vmess_http_transport(
    stream: &mut TcpStream,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    http_options: &HttpConnectOptions,
    summary: &mut VMessHttpTransportServerSummary,
) -> Result<(), String> {
    let head = vmess::read_http_transport_request_head_from_stream(stream, http_options)
        .map_err(|err| format!("stage73 read HTTP transport request failed: {err}"))?;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .map_err(|err| format!("stage73 write HTTP transport 200 failed: {err}"))?;
    let request = vmess::read_aead_tcp_request_from_stream(stream, uuid)
        .map_err(|err| format!("stage73 read VMess HTTP transport request failed: {err}"))?;
    if !request.eauth_crc_validated {
        return Err("stage73 VMess EAuthID checksum was not validated".to_owned());
    }
    if request.command != dae_outbound::VMessNetwork::Tcp.byte() {
        return Err(format!(
            "stage73 VMess command mismatch: got {}, want {}",
            request.command,
            dae_outbound::VMessNetwork::Tcp.byte()
        ));
    }
    if request.target != expected_target {
        return Err(format!(
            "stage73 VMess target mismatch: got {}, want {expected_target}",
            request.target
        ));
    }
    if request.payload != expected_payload {
        return Err("stage73 VMess HTTP transport payload mismatch".to_owned());
    }
    let response = vmess::aead_tcp_response_packet(&request, &request.payload)
        .map_err(|err| format!("stage73 encode VMess HTTP transport response failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage73 write VMess HTTP transport response failed: {err}"))?;

    summary.http_transport_put_count += 1;
    summary.http_status_200_count += 1;
    summary.eauth_crc_count += 1;
    summary.request_header_aead_count += 1;
    summary.response_header_aead_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
    summary.http_request_uris.push(head.request_uri);
    summary.http_hosts.push(head.host);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.payload).to_string());
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
        .map_err(|err| RunnerOutput::usage(format!("invalid {context}: {err}")))
}

fn parse_u32(value: &str, context: &str) -> Result<u32, RunnerOutput> {
    value
        .parse::<u32>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {context}: {err}")))
}

fn parse_u64(value: &str, context: &str) -> Result<u64, RunnerOutput> {
    value
        .parse::<u64>()
        .map_err(|err| RunnerOutput::usage(format!("invalid {context}: {err}")))
}
