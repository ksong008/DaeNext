use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::{shared_transport, vless};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const DEFAULT_TARGET: &str = "stage79-vless-xhttp-target.example:443";
const DEFAULT_XHTTP_HOST: &str = "stage79-vless-xhttp.example";
const DEFAULT_XHTTP_PATH: &str = "/dae-stage79-xhttp";
const DEFAULT_XHTTP_MODE: &str = "packet-up";
const DEFAULT_XHTTP_SECURITY: &str = "tls";
const DEFAULT_XHTTP_ALPN: &str = "h2";
const DEFAULT_XHTTP_SESSION_ID: &str = "dae-stage79-xhttp";
const DEFAULT_XHTTP_SEQ: u64 = 79;
const DEFAULT_PAYLOAD: &[u8] = b"stage79-vless-xhttp-ping";

pub(crate) fn run_stage79_vless_xhttp_packet_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage79Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage79_report(&opts);
    let passed = report["vless_xhttp_packet_smoke_passed"]
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
struct Stage79Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    uuid: String,
    target: String,
    xhttp_host: String,
    xhttp_path: String,
    xhttp_mode: String,
    xhttp_security: String,
    xhttp_alpn: String,
    xhttp_session_id: String,
    xhttp_seq: u64,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage79Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            uuid: DEFAULT_UUID.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            xhttp_host: DEFAULT_XHTTP_HOST.to_owned(),
            xhttp_path: DEFAULT_XHTTP_PATH.to_owned(),
            xhttp_mode: DEFAULT_XHTTP_MODE.to_owned(),
            xhttp_security: DEFAULT_XHTTP_SECURITY.to_owned(),
            xhttp_alpn: DEFAULT_XHTTP_ALPN.to_owned(),
            xhttp_session_id: DEFAULT_XHTTP_SESSION_ID.to_owned(),
            xhttp_seq: DEFAULT_XHTTP_SEQ,
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage79Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage79 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage79 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage79 --target")?,
                "--xhttp-host" => opts.xhttp_host = next_value(&mut iter, "stage79 --xhttp-host")?,
                "--xhttp-path" => opts.xhttp_path = next_value(&mut iter, "stage79 --xhttp-path")?,
                "--xhttp-mode" => opts.xhttp_mode = next_value(&mut iter, "stage79 --xhttp-mode")?,
                "--xhttp-security" => {
                    opts.xhttp_security = next_value(&mut iter, "stage79 --xhttp-security")?
                }
                "--xhttp-alpn" => opts.xhttp_alpn = next_value(&mut iter, "stage79 --xhttp-alpn")?,
                "--xhttp-session-id" => {
                    opts.xhttp_session_id = next_value(&mut iter, "stage79 --xhttp-session-id")?
                }
                "--xhttp-seq" => {
                    opts.xhttp_seq =
                        parse_u64(&next_value(&mut iter, "stage79 --xhttp-seq")?, arg)?;
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage79 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage79 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage79 --timeout-ms")?, arg)?;
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
                _ if arg.starts_with("--xhttp-host=") => {
                    opts.xhttp_host = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-path=") => {
                    opts.xhttp_path = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-mode=") => {
                    opts.xhttp_mode = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-security=") => {
                    opts.xhttp_security = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-alpn=") => {
                    opts.xhttp_alpn = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-session-id=") => {
                    opts.xhttp_session_id = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--xhttp-seq=") => {
                    opts.xhttp_seq = parse_u64(arg.split_once('=').unwrap().1, "--xhttp-seq")?;
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
                        "unsupported stage79 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage79 --benchmark-iters must be greater than zero",
            ));
        }
        vless::password_to_key(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage79 uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage79 target is invalid: {err}")))?;
        opts.xhttp_options()
            .map_err(|err| RunnerOutput::usage(format!("stage79 xhttp options invalid: {err}")))?;
        Ok(opts)
    }

    fn xhttp_options(
        &self,
    ) -> Result<shared_transport::XHttpLifecycleOptions, dae_outbound::OutboundError> {
        shared_transport::XHttpLifecycleOptions::new(
            &self.xhttp_host,
            &self.xhttp_path,
            &self.xhttp_mode,
            &self.xhttp_security,
            &self.xhttp_alpn,
            &self.xhttp_session_id,
            self.xhttp_seq,
        )
    }
}

fn stage79_report(opts: &Stage79Options) -> Value {
    let key = match vless::password_to_key(&opts.uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage79-vless-xhttp-packet-dataplane-admission",
                "stage": "stage79",
                "blocked": true,
                "blockers": [format!("stage79 uuid is invalid: {err}")]
            });
        }
    };
    if let Err(err) = dae_outbound::VMessMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage79-vless-xhttp-packet-dataplane-admission",
            "stage": "stage79",
            "blocked": true,
            "blockers": [format!("stage79 target is invalid: {err}")]
        });
    }
    let xhttp_options = match opts.xhttp_options() {
        Ok(options) => options,
        Err(err) => {
            return json!({
                "name": "stage79-vless-xhttp-packet-dataplane-admission",
                "stage": "stage79",
                "blocked": true,
                "blockers": [format!("stage79 xhttp options invalid: {err}")]
            });
        }
    };
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage79-vless-xhttp-packet-dataplane-admission",
        "stage": "stage79",
        "evidence_class": "opt-in-protocol-vless-xhttp-packet-up-shared-transport-true-dataplane-smoke",
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
    report["vless_websocket_admitted"] = json!(true);
    report["vless_httpupgrade_admitted"] = json!(true);
    report["vless_grpc_hunk_admitted"] = json!(true);
    report["vless_grpc_full_http2_admitted"] = json!(false);
    report["vless_meek_polling_admitted"] = json!(true);
    report["vless_meek_full_https_roundtripper_admitted"] = json!(false);
    report["vless_http_transport_put_admitted"] = json!(true);
    report["vless_http_h2_full_admitted"] = json!(false);
    report["vless_xhttp_packet_smoke_passed"] = json!(false);
    report["vless_xhttp_admitted"] = json!(false);
    report["vless_xhttp_xmux_admitted"] = json!(false);
    report["vless_shared_transport_partial_admitted"] = json!(true);
    report["vless_protocol_partial_admitted"] = json!(true);
    report["vless_protocol_true_dataplane_admitted"] = json!(false);
    report["vless_tls_underlay_admitted"] = json!(false);
    report["vless_reality_underlay_admitted"] = json!(false);
    report["vless_vision_admitted"] = json!(false);
    report["vless_shared_transport_admitted"] = json!(false);
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
    report["vmess_http_transport_put_admitted"] = json!(true);
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
    report["vless_xhttp_contract"] = json!({
        "protocol": "vless",
        "scope": "VLESS TCP request/response carried by xHTTP packet-up POST body over a Rust TCP stream",
        "uuid": opts.uuid,
        "key_hex": hex_encode(&key),
        "network": "tcp",
        "underlay_network": "tcp",
        "transport": "xhttp-packet-up",
        "target": opts.target,
        "xhttp_host": xhttp_options.host,
        "xhttp_path": normalize_xhttp_path(&xhttp_options.path),
        "xhttp_request_path": shared_transport::xhttp_request_path(&xhttp_options),
        "xhttp_mode": xhttp_options.mode,
        "xhttp_security": xhttp_options.security,
        "xhttp_alpn": xhttp_options.alpn,
        "xhttp_session_id": xhttp_options.session_id,
        "xhttp_seq": xhttp_options.seq,
        "xhttp_packet_up_validated": false,
        "xhttp_xmux_enabled": false,
        "full_h2_h3_stack": false,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "server": null,
        "request_header_validated": false,
        "response_header_validated": false,
        "empty_addons_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "full_xhttp_lifecycle_deferred": "xHTTP H2/H3 request client lifecycle, TLS/uTLS, REALITY, downloadSettings, stream-up/stream-one, padding/placement matrix, and xmux pool require separate gates",
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
        "ns_per_vless_xhttp_packet_exchange": null,
        "scope": "VLESS TCP request/response carried by xHTTP packet-up POST body on a SO_MARKed Rust TCP socket",
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
        "vless_websocket_admitted": true,
        "vless_httpupgrade_admitted": true,
        "vless_grpc_hunk_admitted": true,
        "vless_meek_polling_admitted": true,
        "vless_http_transport_put_admitted": true,
        "vless_xhttp_admitted": false,
        "vless_xhttp_xmux_admitted": false,
        "vless_shared_transport_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vless_tls_underlay_admitted": false,
        "vless_reality_underlay_admitted": false,
        "vless_vision_admitted": false,
        "vmess_aead_tcp_true_dataplane_admitted": true,
        "vmess_aead_udp_over_tcp_admitted": true,
        "vmess_udp_packet_addr_admitted": true,
        "vmess_mux_admitted": true,
        "vmess_websocket_admitted": true,
        "vmess_httpupgrade_admitted": true,
        "vmess_grpc_hunk_admitted": true,
        "vmess_meek_polling_admitted": true,
        "vmess_http_transport_put_admitted": true,
        "vmess_http_h2_full_admitted": false,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Trojan TLS and Trojan-Go shared transport rows are still incomplete",
        "VLESS xHTTP xmux pool, full H2/H3/TLS/uTLS/REALITY lifecycle, downloadSettings, stream-up/stream-one, padding/placement matrix, UDP, and full shared transport rows are still incomplete",
        "VMess full HTTP/2 h2 pool/TLS/uTLS, WSS, xHTTP, full gRPC HTTP/2/TLS, full Meek HTTPS, HTTPS HTTPUpgrade/TLS/uTLS, and full shared transport rows are still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage79/vless_xhttp_packet_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage79_vless_xhttp_packet_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage79 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage79 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage79 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage79-vless-xhttp-packet-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage79",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.8",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "/root/project/outbound/dialer/v2ray/v2ray.go",
        "/root/project/outbound/transport/xhttp/xhttp.go",
        "/root/project/outbound/transport/xhttp/xhttp_test.go",
        "rust/crates/dae-outbound/src/vless/dataplane.rs",
        "rust/crates/dae-outbound/src/shared_transport/xhttp.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage79 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage79_smoke(opts) {
        Ok(outcome) => apply_stage79_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage79Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: VlessXHttpPacketServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    request_header_len: usize,
    response_header_len: usize,
    xhttp_request_len: usize,
    xhttp_request_body_len: usize,
    xhttp_response_head_len: usize,
    xhttp_response_body_len: usize,
    key_hex: String,
}

fn run_stage79_smoke(opts: &Stage79Options) -> Result<Stage79Outcome, String> {
    let key = vless::password_to_key(&opts.uuid)
        .map_err(|err| format!("stage79 uuid is invalid: {err}"))?;
    let (server_addr, listener_report, handle) = spawn_vless_xhttp_packet_server(opts)?;
    let mut last_dial_report = None;
    let mut last_exchange = None;
    let xhttp_options = opts
        .xhttp_options()
        .map_err(|err| format!("stage79 xhttp options invalid: {err}"))?;
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
        .map_err(|err| format!("stage79 magic_tcp_connect failed: {err}"))?;
        let report = vless::tcp_exchange_over_xhttp_packet_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &key,
            &opts.target,
            &xhttp_options,
            &opts.payload,
        )
        .map_err(|err| format!("stage79 VLESS xHTTP packet exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage79 VLESS xHTTP packet payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_exchange = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage79 VLESS xHTTP packet server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage79 VLESS xHTTP packet server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let last_exchange =
        last_exchange.ok_or_else(|| "stage79 missing exchange report".to_owned())?;
    Ok(Stage79Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage79 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        request_header_len: last_exchange.request_header_len,
        response_header_len: last_exchange.response_header_len,
        xhttp_request_len: last_exchange.xhttp_request_len,
        xhttp_request_body_len: last_exchange.xhttp_request_body_len,
        xhttp_response_head_len: last_exchange.xhttp_response_head_len,
        xhttp_response_body_len: last_exchange.xhttp_response_body_len,
        key_hex: last_exchange.key_hex,
    })
}

fn apply_stage79_outcome(report: &mut Value, outcome: Stage79Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.xhttp_packet_up_count == outcome.exchange_count
        && outcome.server_summary.request_header_count == outcome.exchange_count
        && outcome.server_summary.response_header_count == outcome.exchange_count
        && outcome.server_summary.empty_addons_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vless_xhttp_packet_smoke_passed"] = json!(passed);
    report["vless_xhttp_admitted"] = json!(passed);
    report["vless_shared_transport_partial_admitted"] = json!(true);
    report["vless_protocol_partial_admitted"] = json!(true);
    report["vless_xhttp_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["vless_xhttp_contract"]["key_hex"] = json!(outcome.key_hex);
    report["vless_xhttp_contract"]["xhttp_packet_up_validated"] = json!(passed);
    report["vless_xhttp_contract"]["request_header_validated"] = json!(passed);
    report["vless_xhttp_contract"]["response_header_validated"] = json!(passed);
    report["vless_xhttp_contract"]["empty_addons_validated"] = json!(passed);
    report["vless_xhttp_contract"]["tcp_command_validated"] = json!(passed);
    report["vless_xhttp_contract"]["target_metadata_validated"] = json!(passed);
    report["vless_xhttp_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "xhttp_packet_up_count": outcome.server_summary.xhttp_packet_up_count,
        "request_header_count": outcome.server_summary.request_header_count,
        "response_header_count": outcome.server_summary.response_header_count,
        "empty_addons_count": outcome.server_summary.empty_addons_count,
        "tcp_command_count": outcome.server_summary.tcp_command_count,
        "target_metadata_count": outcome.server_summary.target_metadata_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "xhttp_request_paths": outcome.server_summary.xhttp_request_paths,
        "xhttp_hosts": outcome.server_summary.xhttp_hosts,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_vless_xhttp_packet_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.request_header_len);
    report["benchmark"]["response_header_len"] = json!(outcome.response_header_len);
    report["benchmark"]["xhttp_request_len"] = json!(outcome.xhttp_request_len);
    report["benchmark"]["xhttp_request_body_len"] = json!(outcome.xhttp_request_body_len);
    report["benchmark"]["xhttp_response_head_len"] = json!(outcome.xhttp_response_head_len);
    report["benchmark"]["xhttp_response_body_len"] = json!(outcome.xhttp_response_body_len);
    report["protocol_matrix"]["vless_xhttp_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct VlessXHttpPacketServerSummary {
    accepted: usize,
    xhttp_packet_up_count: usize,
    request_header_count: usize,
    response_header_count: usize,
    empty_addons_count: usize,
    tcp_command_count: usize,
    target_metadata_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    xhttp_request_paths: Vec<String>,
    xhttp_hosts: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_vless_xhttp_packet_server(
    opts: &Stage79Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VlessXHttpPacketServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage79 bind loopback VLESS xHTTP packet server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage79 VLESS xHTTP packet server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage79 VLESS xHTTP packet listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage79 VLESS xHTTP packet nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let uuid = opts.uuid.clone();
    let target = opts.target.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let xhttp_options = opts
        .xhttp_options()
        .map_err(|err| format!("stage79 xhttp options invalid: {err}"))?;
    let handle = thread::spawn(move || {
        accept_vless_xhttp_packet(
            listener,
            iterations,
            &uuid,
            &target,
            &payload,
            &xhttp_options,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vless_xhttp_packet(
    listener: TcpListener,
    iterations: usize,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    xhttp_options: &shared_transport::XHttpLifecycleOptions,
    timeout: Duration,
) -> Result<VlessXHttpPacketServerSummary, String> {
    let mut summary = VlessXHttpPacketServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage79 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage79 server set write timeout failed: {err}"))?;
                handle_vless_xhttp_packet(
                    &mut stream,
                    uuid,
                    expected_target,
                    expected_payload,
                    xhttp_options,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage79 VLESS xHTTP packet server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage79 VLESS xHTTP packet accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vless_xhttp_packet(
    stream: &mut TcpStream,
    uuid: &str,
    expected_target: &str,
    expected_payload: &[u8],
    xhttp_options: &shared_transport::XHttpLifecycleOptions,
    summary: &mut VlessXHttpPacketServerSummary,
) -> Result<(), String> {
    let expected_key =
        vless::password_to_key(uuid).map_err(|err| format!("stage79 VLESS key failed: {err}"))?;
    let request = vless::read_tcp_request_from_xhttp_packet_stream(
        stream,
        expected_payload.len(),
        xhttp_options,
    )
    .map_err(|err| format!("stage79 read VLESS xHTTP packet request failed: {err}"))?;
    if request.request.key != expected_key {
        return Err("stage79 VLESS key mismatch".to_owned());
    }
    if request.request.addons_len != 0 {
        return Err(format!(
            "stage79 VLESS addons length mismatch: got {}, want 0",
            request.request.addons_len
        ));
    }
    if request.request.command != dae_outbound::VMessNetwork::Tcp.byte() {
        return Err(format!(
            "stage79 VLESS command mismatch: got {}, want {}",
            request.request.command,
            dae_outbound::VMessNetwork::Tcp.byte()
        ));
    }
    if request.request.target != expected_target {
        return Err(format!(
            "stage79 VLESS target mismatch: got {}, want {expected_target}",
            request.request.target
        ));
    }
    if request.request.payload != expected_payload {
        return Err("stage79 VLESS xHTTP packet payload mismatch".to_owned());
    }
    let response = vless::response_payload_bytes(&request.request.payload);
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                response.len()
            )
            .as_bytes(),
        )
        .map_err(|err| format!("stage79 write xHTTP response head failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage79 write xHTTP response body failed: {err}"))?;

    summary.xhttp_packet_up_count += 1;
    summary.request_header_count += 1;
    summary.response_header_count += 1;
    summary.empty_addons_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
    summary.xhttp_request_paths.push(request.xhttp_request_path);
    summary.xhttp_hosts.push(xhttp_options.host.clone());
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request.request.payload).to_string());
    Ok(())
}

fn normalize_xhttp_path(input: &str) -> String {
    dae_outbound::shared_transport::ir::normalize_xhttp_path_and_query(input).path
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
