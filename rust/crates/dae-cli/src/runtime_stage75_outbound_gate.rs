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
const DEFAULT_TARGET: &str = "stage75-vless-httpupgrade.example:443";
const DEFAULT_HTTPUPGRADE_HOST: &str = "stage75-vless-upgrade.example";
const DEFAULT_HTTPUPGRADE_PATH: &str = "/dae-vless-httpupgrade";
const DEFAULT_PAYLOAD: &[u8] = b"stage75-vless-httpupgrade-ping";

pub(crate) fn run_stage75_vless_httpupgrade_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage75Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage75_report(&opts);
    let passed = report["vless_httpupgrade_smoke_passed"]
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
struct Stage75Options {
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

impl Default for Stage75Options {
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

impl Stage75Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage75 --benchmark-iters")?, arg)?;
                }
                "--uuid" => opts.uuid = next_value(&mut iter, "stage75 --uuid")?,
                "--target" => opts.target = next_value(&mut iter, "stage75 --target")?,
                "--httpupgrade-host" => {
                    opts.httpupgrade_host = next_value(&mut iter, "stage75 --httpupgrade-host")?
                }
                "--httpupgrade-path" => {
                    opts.httpupgrade_path = next_value(&mut iter, "stage75 --httpupgrade-path")?
                }
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage75 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage75 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage75 --timeout-ms")?, arg)?;
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
                        "unsupported stage75 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage75 --benchmark-iters must be greater than zero",
            ));
        }
        vless::password_to_key(&opts.uuid)
            .map_err(|err| RunnerOutput::usage(format!("stage75 uuid is invalid: {err}")))?;
        dae_outbound::VMessMetadata::parse("tcp", &opts.target)
            .map_err(|err| RunnerOutput::usage(format!("stage75 target is invalid: {err}")))?;
        if opts.httpupgrade_host.is_empty() {
            return Err(RunnerOutput::usage(
                "stage75 --httpupgrade-host must not be empty",
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

fn stage75_report(opts: &Stage75Options) -> Value {
    let key = match vless::password_to_key(&opts.uuid) {
        Ok(key) => key,
        Err(err) => {
            return json!({
                "name": "stage75-vless-httpupgrade-dataplane-admission",
                "stage": "stage75",
                "blocked": true,
                "blockers": [format!("stage75 uuid is invalid: {err}")]
            });
        }
    };
    if let Err(err) = dae_outbound::VMessMetadata::parse("tcp", &opts.target) {
        return json!({
            "name": "stage75-vless-httpupgrade-dataplane-admission",
            "stage": "stage75",
            "blocked": true,
            "blockers": [format!("stage75 target is invalid: {err}")]
        });
    }
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage75-vless-httpupgrade-dataplane-admission",
        "stage": "stage75",
        "evidence_class": "opt-in-protocol-vless-httpupgrade-shared-transport-true-dataplane-smoke",
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
    report["vless_protocol_partial_admitted"] = json!(true);
    report["vless_httpupgrade_smoke_passed"] = json!(false);
    report["vless_httpupgrade_admitted"] = json!(false);
    report["vless_shared_transport_partial_admitted"] = json!(false);
    report["vless_tls_underlay_admitted"] = json!(false);
    report["vless_reality_underlay_admitted"] = json!(false);
    report["vless_vision_admitted"] = json!(false);
    report["vless_httpupgrade_admitted"] = json!(false);
    report["vless_grpc_hunk_admitted"] = json!(false);
    report["vless_meek_polling_admitted"] = json!(false);
    report["vless_http_transport_put_admitted"] = json!(false);
    report["vless_xhttp_admitted"] = json!(false);
    report["vless_xhttp_xmux_admitted"] = json!(false);
    report["vless_protocol_true_dataplane_admitted"] = json!(false);
    report["vless_shared_transport_admitted"] = json!(false);
    report["vmess_aead_tcp_true_dataplane_admitted"] = json!(true);
    report["vmess_aead_udp_over_tcp_admitted"] = json!(true);
    report["vmess_udp_packet_addr_admitted"] = json!(true);
    report["vmess_mux_admitted"] = json!(true);
    report["vmess_websocket_admitted"] = json!(true);
    report["vmess_httpupgrade_admitted"] = json!(true);
    report["vmess_grpc_hunk_admitted"] = json!(true);
    report["vmess_meek_polling_admitted"] = json!(true);
    report["vmess_http_transport_put_admitted"] = json!(true);
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
    report["vless_httpupgrade_contract"] = json!({
        "protocol": "vless",
        "scope": "VLESS TCP request/response carried after HTTPUpgrade 101 over a Rust TCP stream",
        "uuid": opts.uuid,
        "key_hex": hex_encode(&key),
        "network": "tcp",
        "underlay_network": "tcp",
        "transport": "httpupgrade",
        "target": opts.target,
        "httpupgrade_host": opts.httpupgrade_host,
        "httpupgrade_path": opts.httpupgrade_path,
        "payload_ascii": payload_ascii,
        "payload_len": opts.payload.len(),
        "server": null,
        "httpupgrade_request_validated": false,
        "http_status_101_validated": false,
        "raw_stream_after_upgrade_validated": false,
        "request_header_validated": false,
        "response_header_validated": false,
        "empty_addons_validated": false,
        "tcp_command_validated": false,
        "target_metadata_validated": false,
        "payload_roundtrip_validated": false,
        "tls_https_deferred": "HTTPS HTTPUpgrade, TLS/uTLS, REALITY, XTLS Vision, ALPN http/1.1, and TLS fragmentation require separate underlay gates",
        "other_shared_transport_deferred": "VLESS gRPC, HTTP/H2, Meek, and xHTTP/xmux require separate transport gates",
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
        "ns_per_vless_httpupgrade_exchange": null,
        "scope": "VLESS TCP request/response after HTTPUpgrade 101 on a SO_MARKed Rust TCP socket",
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
        "vless_httpupgrade_admitted": false,
        "vless_shared_transport_partial_admitted": false,
        "vless_shared_transport_admitted": false,
        "vless_protocol_true_dataplane_admitted": false,
        "vless_tls_underlay_admitted": false,
        "vless_reality_underlay_admitted": false,
        "vless_vision_admitted": false,
        "vless_httpupgrade_admitted": false,
        "vless_grpc_hunk_admitted": false,
        "vless_meek_polling_admitted": false,
        "vless_http_transport_put_admitted": false,
        "vless_xhttp_admitted": false,
        "vless_xhttp_xmux_admitted": false,
        "vmess_aead_tcp_true_dataplane_admitted": true,
        "vmess_aead_udp_over_tcp_admitted": true,
        "vmess_udp_packet_addr_admitted": true,
        "vmess_mux_admitted": true,
        "vmess_websocket_admitted": true,
        "vmess_httpupgrade_admitted": true,
        "vmess_grpc_hunk_admitted": true,
        "vmess_meek_polling_admitted": true,
        "vmess_http_transport_put_admitted": true,
        "vmess_shared_transport_admitted": false,
        "vmess_protocol_true_dataplane_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "Trojan TLS and Trojan-Go shared transport rows are still incomplete",
        "VLESS TLS/REALITY/XTLS Vision/shared transport/xHTTP xmux rows are still incomplete",
        "VLESS HTTPS HTTPUpgrade/TLS/uTLS, gRPC, HTTP/H2, Meek, xHTTP, and full shared transport rows are still incomplete",
        "Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage75/vless_httpupgrade_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage75_vless_httpupgrade_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage75 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage75 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage75 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage75-vless-httpupgrade-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage75",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.4",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.5",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.18",
        "/root/project/outbound/dialer/v2ray/v2ray.go",
        "/root/project/outbound/transport/httpupgrade/httpupgrade.go",
        "rust/crates/dae-cli/src/runtime_stage75_outbound_gate.rs",
        "rust/crates/dae-outbound/src/vless/dataplane.rs",
        "rust/crates/dae-outbound/src/shared_transport/dataplane.rs",
        "rust/crates/dae-datapath/src/tcp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage75 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage75_smoke(opts) {
        Ok(outcome) => apply_stage75_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage75Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: VlessHttpUpgradeServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    request_header_len: usize,
    response_header_len: usize,
    httpupgrade_request_len: usize,
    httpupgrade_response_head_len: usize,
    key_hex: String,
}

fn run_stage75_smoke(opts: &Stage75Options) -> Result<Stage75Outcome, String> {
    let key = vless::password_to_key(&opts.uuid)
        .map_err(|err| format!("stage75 uuid is invalid: {err}"))?;
    let (server_addr, listener_report, handle) = spawn_vless_httpupgrade_server(opts)?;
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
        .map_err(|err| format!("stage75 magic_tcp_connect failed: {err}"))?;
        let report = vless::tcp_exchange_over_httpupgrade_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &key,
            &opts.target,
            &opts.httpupgrade_host,
            &opts.httpupgrade_path,
            &opts.payload,
        )
        .map_err(|err| format!("stage75 VLESS HTTPUpgrade exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage75 VLESS HTTPUpgrade payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
        last_exchange = Some(report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage75 VLESS HTTPUpgrade server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage75 VLESS HTTPUpgrade server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    let last_exchange =
        last_exchange.ok_or_else(|| "stage75 missing exchange report".to_owned())?;
    Ok(Stage75Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage75 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        request_header_len: last_exchange.request_header_len,
        response_header_len: last_exchange.response_header_len,
        httpupgrade_request_len: last_exchange.httpupgrade_request_len,
        httpupgrade_response_head_len: last_exchange.httpupgrade_response_head_len,
        key_hex: last_exchange.key_hex,
    })
}

fn apply_stage75_outcome(report: &mut Value, outcome: Stage75Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.httpupgrade_request_count == outcome.exchange_count
        && outcome.server_summary.http_status_101_count == outcome.exchange_count
        && outcome.server_summary.request_header_count == outcome.exchange_count
        && outcome.server_summary.response_header_count == outcome.exchange_count
        && outcome.server_summary.empty_addons_count == outcome.exchange_count
        && outcome.server_summary.tcp_command_count == outcome.exchange_count
        && outcome.server_summary.target_metadata_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["vless_httpupgrade_smoke_passed"] = json!(passed);
    report["vless_httpupgrade_admitted"] = json!(passed);
    report["vless_shared_transport_partial_admitted"] = json!(passed);
    report["vless_protocol_partial_admitted"] = json!(true);
    report["vless_httpupgrade_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["vless_httpupgrade_contract"]["key_hex"] = json!(outcome.key_hex);
    report["vless_httpupgrade_contract"]["httpupgrade_request_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["http_status_101_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["raw_stream_after_upgrade_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["request_header_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["response_header_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["empty_addons_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["tcp_command_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["target_metadata_validated"] = json!(passed);
    report["vless_httpupgrade_contract"]["payload_roundtrip_validated"] = json!(passed);
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
        "httpupgrade_request_count": outcome.server_summary.httpupgrade_request_count,
        "http_status_101_count": outcome.server_summary.http_status_101_count,
        "request_header_count": outcome.server_summary.request_header_count,
        "response_header_count": outcome.server_summary.response_header_count,
        "empty_addons_count": outcome.server_summary.empty_addons_count,
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
    report["benchmark"]["ns_per_vless_httpupgrade_exchange"] = json!(outcome.ns_per_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["request_header_len"] = json!(outcome.request_header_len);
    report["benchmark"]["response_header_len"] = json!(outcome.response_header_len);
    report["benchmark"]["httpupgrade_request_len"] = json!(outcome.httpupgrade_request_len);
    report["benchmark"]["httpupgrade_response_head_len"] =
        json!(outcome.httpupgrade_response_head_len);
    report["protocol_matrix"]["vless_httpupgrade_admitted"] = json!(passed);
    report["protocol_matrix"]["vless_shared_transport_partial_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct VlessHttpUpgradeServerSummary {
    accepted: usize,
    httpupgrade_request_count: usize,
    http_status_101_count: usize,
    request_header_count: usize,
    response_header_count: usize,
    empty_addons_count: usize,
    tcp_command_count: usize,
    target_metadata_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    httpupgrade_hosts: Vec<String>,
    httpupgrade_paths: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_vless_httpupgrade_server(
    opts: &Stage75Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<VlessHttpUpgradeServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage75 bind loopback VLESS HTTPUpgrade server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage75 VLESS HTTPUpgrade server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!(
                "stage75 VLESS HTTPUpgrade listener is not IPv4: {addr}"
            ));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage75 VLESS HTTPUpgrade nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let key = vless::password_to_key(&opts.uuid)
        .map_err(|err| format!("stage75 uuid is invalid: {err}"))?;
    let target = opts.target.clone();
    let httpupgrade_host = opts.httpupgrade_host.clone();
    let httpupgrade_path = opts.httpupgrade_path.clone();
    let payload = opts.payload.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_vless_httpupgrade(
            listener,
            iterations,
            key,
            &target,
            &httpupgrade_host,
            &httpupgrade_path,
            &payload,
            timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_vless_httpupgrade(
    listener: TcpListener,
    iterations: usize,
    expected_key: [u8; 16],
    expected_target: &str,
    expected_host: &str,
    expected_path: &str,
    expected_payload: &[u8],
    timeout: Duration,
) -> Result<VlessHttpUpgradeServerSummary, String> {
    let mut summary = VlessHttpUpgradeServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage75 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage75 server set write timeout failed: {err}"))?;
                handle_vless_httpupgrade(
                    &mut stream,
                    expected_key,
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
                    "stage75 VLESS HTTPUpgrade server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage75 VLESS HTTPUpgrade accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_vless_httpupgrade(
    stream: &mut TcpStream,
    expected_key: [u8; 16],
    expected_target: &str,
    expected_host: &str,
    expected_path: &str,
    expected_payload: &[u8],
    summary: &mut VlessHttpUpgradeServerSummary,
) -> Result<(), String> {
    let request_head = shared_transport::read_http_head(stream)
        .map_err(|err| format!("stage75 read HTTPUpgrade upgrade failed: {err}"))?;
    let request_head = String::from_utf8(request_head)
        .map_err(|err| format!("stage75 HTTPUpgrade upgrade is not UTF-8: {err}"))?;
    if !request_head.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")) {
        return Err("stage75 HTTPUpgrade upgrade path mismatch".to_owned());
    }
    if !request_head.contains(&format!("Host: {expected_host}\r\n")) {
        return Err("stage75 HTTPUpgrade Host header mismatch".to_owned());
    }
    if !request_head.contains("Connection: upgrade\r\n") {
        return Err("stage75 HTTPUpgrade Connection header missing".to_owned());
    }
    if !request_head.contains("Upgrade: websocket\r\n") {
        return Err("stage75 HTTPUpgrade Upgrade header missing".to_owned());
    }
    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .map_err(|err| format!("stage75 write HTTPUpgrade upgrade response failed: {err}"))?;
    let request = vless::read_tcp_request_from_stream(stream, expected_payload.len())
        .map_err(|err| format!("stage75 read VLESS HTTPUpgrade request failed: {err}"))?;
    if request.version != vless::VLESS_VERSION {
        return Err(format!(
            "stage75 VLESS version mismatch: got {}, want {}",
            request.version,
            vless::VLESS_VERSION
        ));
    }
    if request.key != expected_key {
        return Err("stage75 VLESS key mismatch".to_owned());
    }
    if request.addons_len != 0 {
        return Err(format!(
            "stage75 VLESS addons length mismatch: got {}, want 0",
            request.addons_len
        ));
    }
    if request.command != dae_outbound::VMessNetwork::Tcp.byte() {
        return Err(format!(
            "stage75 VLESS command mismatch: got {}, want {}",
            request.command,
            dae_outbound::VMessNetwork::Tcp.byte()
        ));
    }
    if request.target != expected_target {
        return Err(format!(
            "stage75 VLESS target mismatch: got {}, want {expected_target}",
            request.target
        ));
    }
    if request.payload != expected_payload {
        return Err("stage75 VLESS HTTPUpgrade payload mismatch".to_owned());
    }
    let response = vless::response_payload_bytes(&request.payload);
    stream
        .write_all(&response)
        .map_err(|err| format!("stage75 write VLESS HTTPUpgrade echo failed: {err}"))?;

    summary.httpupgrade_request_count += 1;
    summary.http_status_101_count += 1;
    summary.request_header_count += 1;
    summary.response_header_count += 1;
    summary.empty_addons_count += 1;
    summary.tcp_command_count += 1;
    summary.target_metadata_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(expected_target.to_owned());
    summary.httpupgrade_hosts.push(expected_host.to_owned());
    summary.httpupgrade_paths.push(expected_path.to_owned());
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
