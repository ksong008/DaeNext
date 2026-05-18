use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::http_proxy::{self, HttpConnectOptions, request as http_request};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_TARGET: &str = "stage57.example:443";
const DEFAULT_HOST_OVERRIDE: &str = "front.stage57.example:443";
const DEFAULT_USERNAME: &str = "user";
const DEFAULT_PASSWORD: &str = "pass";
const DEFAULT_PAYLOAD: &[u8] = b"stage57-http-connect-ping";
const DEFAULT_RESPONSE: &[u8] = DEFAULT_PAYLOAD;

pub(crate) fn run_stage57_http_connect_dataplane_admission(args: &[String]) -> RunnerOutput {
    let opts = match Stage57Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage57_report(&opts);
    let passed = report["http_connect_smoke_passed"]
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
struct Stage57Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    target: String,
    host_override: String,
    username: String,
    password: String,
    payload: Vec<u8>,
    response: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage57Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            target: DEFAULT_TARGET.to_owned(),
            host_override: DEFAULT_HOST_OVERRIDE.to_owned(),
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

impl Stage57Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage57 --benchmark-iters")?, arg)?;
                }
                "--target" => opts.target = next_value(&mut iter, "stage57 --target")?,
                "--host-override" => {
                    opts.host_override = next_value(&mut iter, "stage57 --host-override")?;
                }
                "--username" => opts.username = next_value(&mut iter, "stage57 --username")?,
                "--password" => opts.password = next_value(&mut iter, "stage57 --password")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage57 --payload")?.into_bytes();
                }
                "--response" => {
                    opts.response = next_value(&mut iter, "stage57 --response")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage57 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage57 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--target=") => {
                    opts.target = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--host-override=") => {
                    opts.host_override = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage57 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage57 --benchmark-iters must be greater than zero",
            ));
        }
        if opts.response.len() != opts.payload.len() {
            return Err(RunnerOutput::usage(
                "stage57 --response length must match --payload length because this gate validates CONNECT payload echo semantics",
            ));
        }
        Ok(opts)
    }
}

fn stage57_report(opts: &Stage57Options) -> Value {
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let response_ascii = String::from_utf8_lossy(&opts.response).to_string();
    let mut report = json!({
        "name": "stage57-http-connect-dataplane-admission",
        "stage": "stage57",
        "evidence_class": "opt-in-protocol-http-connect-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_smoke_passed": false,
        "http_connect_true_dataplane_admitted": false,
        "https_proxy_tls_underlay_admitted": false,
        "http_proxy_protocol_partial_admitted": false,
        "http_connect_request_observed": false,
        "http_proxy_auth_observed": false,
        "http_connect_payload_roundtrip_recorded": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "http_connect_contract": {
            "protocol": "HTTP proxy",
            "scope": "HTTP CONNECT loopback true dataplane",
            "proxy": null,
            "target": opts.target,
            "host_override": opts.host_override,
            "username_password_auth_required": true,
            "expected_status": 200,
            "payload_ascii": payload_ascii,
            "response_ascii": response_ascii,
            "https_proxy_tls_underlay_deferred": "HTTPS proxy requires shared TLS/uTLS/ALPN transport gate",
            "udp_unsupported": true,
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
            "scope": "HTTP CONNECT plus Basic auth plus payload roundtrip over Rust underlay socket",
            "go_matched_default_daemon_baseline_recorded": false,
            "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
        },
        "protocol_matrix": {
            "socks5_protocol_true_dataplane_admitted": true,
            "http_connect_true_dataplane_admitted": false,
            "https_proxy_tls_underlay_admitted": false,
            "shadowsocks_aead_true_dataplane_admitted": false,
            "vmess_vless_trojan_shared_transport_admitted": false,
            "quic_h3_session_protocols_admitted": false
        },
        "remaining_blockers": [
            "HTTPS proxy shared TLS/uTLS/ALPN underlay is still incomplete",
            "Shadowsocks/SS2022, Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS, and shared transport true dataplanes are still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
        "validation_commands": [
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage57/http_connect_dataplane_admission.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage57_http_connect_dataplane_gate.json",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage57 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage57 -- --nocapture",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage57-http-connect-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
            "git diff --check"
        ],
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage57-item343",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.12",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.2",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8",
            "rust/crates/dae-outbound/src/http_proxy/dataplane.rs",
            "rust/crates/dae-outbound/src/http_proxy/request.rs",
            "rust/crates/dae-datapath/src/tcp_direct.rs"
        ]
    });

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage57 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage57_smoke(opts) {
        Ok(outcome) => apply_stage57_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage57Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: HttpConnectServerSummary,
    elapsed_ns: u128,
    ns_per_connect: f64,
    exchange_count: usize,
    payload_len: usize,
    response_len: usize,
    last_status: u16,
}

fn run_stage57_smoke(opts: &Stage57Options) -> Result<Stage57Outcome, String> {
    let (proxy_addr, listener_report, handle) = spawn_http_connect_proxy(opts)?;
    let mut last_dial_report = None;
    let mut last_status = 0;
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
        .map_err(|err| format!("stage57 magic_tcp_connect failed: {err}"))?;
        let mut options = HttpConnectOptions::connect(&opts.target);
        options.host_override = opts.host_override.clone();
        options.username = opts.username.clone();
        options.password = opts.password.clone();
        let report = http_proxy::connect_exchange_over_stream(
            &mut connected.stream,
            &proxy_addr.to_string(),
            &options,
            &opts.payload,
        )
        .map_err(|err| format!("stage57 http connect exchange failed: {err}"))?;
        if report.status != 200 {
            return Err(format!("stage57 http status mismatch: {}", report.status));
        }
        if report.echoed_payload != opts.response {
            return Err("stage57 http connect payload response mismatch".to_owned());
        }
        last_status = report.status;
        last_dial_report = Some(connected.report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage57 http proxy thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage57 http proxy accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage57Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage57 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_connect: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        response_len: opts.response.len(),
        last_status,
    })
}

fn apply_stage57_outcome(report: &mut Value, outcome: Stage57Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.connect_count == outcome.exchange_count
        && outcome.server_summary.auth_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["http_connect_smoke_passed"] = json!(passed);
    report["http_connect_true_dataplane_admitted"] = json!(passed);
    report["http_proxy_protocol_partial_admitted"] = json!(passed);
    report["http_connect_request_observed"] = json!(outcome.server_summary.connect_count > 0);
    report["http_proxy_auth_observed"] = json!(outcome.server_summary.auth_count > 0);
    report["http_connect_payload_roundtrip_recorded"] =
        json!(outcome.server_summary.payload_roundtrip_count > 0);
    report["http_connect_contract"]["proxy"] = json!(outcome.last_dial_report.peer_addr);
    report["http_connect_contract"]["observed_status"] = json!(outcome.last_status);
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
        "connect_count": outcome.server_summary.connect_count,
        "auth_count": outcome.server_summary.auth_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "connect_authorities": outcome.server_summary.connect_authorities,
        "host_headers": outcome.server_summary.host_headers,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_connect"] = json!(outcome.ns_per_connect);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["response_len"] = json!(outcome.response_len);
    report["protocol_matrix"]["http_connect_true_dataplane_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct HttpConnectServerSummary {
    accepted: usize,
    connect_count: usize,
    auth_count: usize,
    payload_roundtrip_count: usize,
    connect_authorities: Vec<String>,
    host_headers: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_http_connect_proxy(
    opts: &Stage57Options,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<HttpConnectServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage57 bind loopback http proxy failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage57 http proxy local_addr failed: {err}"))?;
    let proxy_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage57 http proxy listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage57 http proxy nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let expected_authority = if opts.host_override.is_empty() {
        opts.target.clone()
    } else {
        opts.host_override.clone()
    };
    let expected_auth = http_request::basic_auth_header(&opts.username, &opts.password)
        .ok_or_else(|| "stage57 expected basic auth header is empty".to_owned())?;
    let payload = opts.payload.clone();
    let response = opts.response.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_http_connects(
            listener,
            iterations,
            &expected_authority,
            &expected_auth,
            &payload,
            &response,
            timeout,
        )
    });
    Ok((proxy_addr, listener_report, handle))
}

fn accept_http_connects(
    listener: TcpListener,
    iterations: usize,
    expected_authority: &str,
    expected_auth: &str,
    payload: &[u8],
    response: &[u8],
    timeout: Duration,
) -> Result<HttpConnectServerSummary, String> {
    let mut summary = HttpConnectServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage57 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage57 server set write timeout failed: {err}"))?;
                handle_http_connect(
                    &mut stream,
                    expected_authority,
                    expected_auth,
                    payload,
                    response,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage57 http proxy timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage57 http proxy accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_http_connect(
    stream: &mut TcpStream,
    expected_authority: &str,
    expected_auth: &str,
    payload: &[u8],
    response: &[u8],
    summary: &mut HttpConnectServerSummary,
) -> Result<(), String> {
    let head = read_http_head(stream)?;
    let text = std::str::from_utf8(&head)
        .map_err(|err| format!("stage57 http request is not utf8: {err}"))?;
    let (first_line, headers) = parse_http_head(text)?;
    let mut first = first_line.split_whitespace();
    let method = first.next().unwrap_or_default();
    let authority = first.next().unwrap_or_default();
    let version = first.next().unwrap_or_default();
    if method != "CONNECT" || authority != expected_authority || version != "HTTP/1.1" {
        return Err(format!("stage57 bad CONNECT line: {first_line}"));
    }
    let host = header_value(&headers, "host").unwrap_or_default();
    if host != expected_authority {
        return Err(format!(
            "stage57 host header mismatch: got {host}, want {expected_authority}"
        ));
    }
    let auth = header_value(&headers, "proxy-authorization").unwrap_or_default();
    if auth != expected_auth {
        return Err(format!(
            "stage57 proxy auth mismatch: got {auth}, want {expected_auth}"
        ));
    }
    summary.connect_count += 1;
    summary.auth_count += 1;
    summary.connect_authorities.push(authority.to_owned());
    summary.host_headers.push(host);

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|err| format!("stage57 write 200 failed: {err}"))?;
    let mut got_payload = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut got_payload)
        .map_err(|err| format!("stage57 payload read failed: {err}"))?;
    if got_payload != payload {
        return Err("stage57 http payload mismatch at proxy".to_owned());
    }
    stream
        .write_all(response)
        .map_err(|err| format!("stage57 payload response failed: {err}"))?;
    summary.payload_roundtrip_count += 1;
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&got_payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(response).to_string());
    Ok(())
}

fn read_http_head(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|err| format!("stage57 read http head failed: {err}"))?;
        if n == 0 {
            return Err("stage57 incomplete http request head".to_owned());
        }
        out.extend_from_slice(&buf[..n]);
        if out.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(out);
        }
        if out.len() > 8192 {
            return Err("stage57 http request head too large".to_owned());
        }
    }
}

fn parse_http_head(text: &str) -> Result<(&str, Vec<(String, String)>), String> {
    let (head, _) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "stage57 missing http header terminator".to_owned())?;
    let mut lines = head.split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| "stage57 missing request line".to_owned())?;
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    Ok((first, headers))
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.clone())
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
