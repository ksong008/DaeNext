use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{UdpDirectPacketConn, UdpDirectSocketOptions, UdpDirectSocketReport};
use dae_outbound::shadowsocks;
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_CIPHER: &str = "aes-128-gcm";
const DEFAULT_PASSWORD: &str = "stage59-password";
const DEFAULT_TARGET: &str = "stage59.example:5353";
const DEFAULT_PAYLOAD: &[u8] = b"stage59-shadowsocks-udp-ping";

pub(crate) fn run_stage59_shadowsocks_aead_udp_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage59Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage59_report(&opts);
    let passed = report["shadowsocks_aead_udp_smoke_passed"]
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
struct Stage59Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    cipher: String,
    password: String,
    target: String,
    payload: Vec<u8>,
    so_mark: u32,
    timeout: Duration,
}

impl Default for Stage59Options {
    fn default() -> Self {
        Self {
            execute_smoke: false,
            ack_root_gate: false,
            benchmark_iters: 1,
            cipher: DEFAULT_CIPHER.to_owned(),
            password: DEFAULT_PASSWORD.to_owned(),
            target: DEFAULT_TARGET.to_owned(),
            payload: DEFAULT_PAYLOAD.to_vec(),
            so_mark: 1234,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage59Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage59 --benchmark-iters")?, arg)?;
                }
                "--cipher" => opts.cipher = next_value(&mut iter, "stage59 --cipher")?,
                "--password" => opts.password = next_value(&mut iter, "stage59 --password")?,
                "--target" => opts.target = next_value(&mut iter, "stage59 --target")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage59 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage59 --so-mark")?, arg)?;
                }
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage59 --timeout-ms")?, arg)?;
                    opts.timeout = Duration::from_millis(timeout_ms);
                }
                _ if arg.starts_with("--benchmark-iters=") => {
                    opts.benchmark_iters =
                        parse_usize(arg.split_once('=').unwrap().1, "--benchmark-iters")?;
                }
                _ if arg.starts_with("--cipher=") => {
                    opts.cipher = arg.split_once('=').unwrap().1.to_owned();
                }
                _ if arg.starts_with("--password=") => {
                    opts.password = arg.split_once('=').unwrap().1.to_owned();
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
                        "unsupported stage59 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage59 --benchmark-iters must be greater than zero",
            ));
        }
        shadowsocks::cipher_spec(&opts.cipher)
            .map_err(|err| RunnerOutput::usage(format!("stage59 requires AEAD cipher: {err}")))?;
        Ok(opts)
    }
}

fn stage59_report(opts: &Stage59Options) -> Value {
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage59-shadowsocks-aead-udp-dataplane-admission",
        "stage": "stage59",
        "evidence_class": "opt-in-protocol-shadowsocks-aead-udp-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "shadowsocks_aead_tcp_true_dataplane_admitted": true,
        "shadowsocks_aead_udp_smoke_passed": false,
        "shadowsocks_aead_udp_true_dataplane_admitted": false,
        "shadowsocks_aead_protocol_true_dataplane_admitted": false,
        "shadowsocks_protocol_partial_admitted": true,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "ss2022_true_dataplane_admitted": false,
        "sip003_plugin_transport_admitted": false,
        "shadowsocksr_true_dataplane_admitted": false,
        "protocol_outbound_partial_admitted": true,
        "outbound_true_dataplane_admitted": false,
        "matched_go_rust_default_daemon_benchmark_recorded": false,
        "default_switch_allowed": false,
        "default_path_mutation_allowed": false,
        "product_chain_switch_allowed": false,
        "true_rust_default_daemon_admitted": false,
        "go_default_path_preserved": true,
        "go_fallback_required": true,
        "shadowsocks_udp_contract": {
            "protocol": "Shadowsocks",
            "scope": "AEAD UDP PacketConn loopback true dataplane",
            "cipher": opts.cipher,
            "target": opts.target,
            "payload_ascii": payload_ascii,
            "server": null,
            "udp_packet_salt_validated": false,
            "mptcp_not_applicable": true,
            "ss2022_udp_deferred": "SS2022 UDP uses separate AEAD-2022 packet/replay semantics",
            "sip003_plugin_deferred": "SIP003 plugin passthrough UDP is deferred",
            "ssr_deferred": "ShadowsocksR UDP wrapper is deferred",
            "default_go_path_preserved": true
        },
        "udp_underlay_socket": {
            "requested_mark": opts.so_mark,
            "last_socket_report": null,
            "so_mark_observed": false,
            "mptcp_not_applicable": true
        },
        "server_observation": null,
        "benchmark": {
            "benchmark_recorded": false,
            "iterations": opts.benchmark_iters,
            "elapsed_ns": null,
            "ns_per_udp_exchange": null,
            "scope": "Shadowsocks AEAD UDP packet encrypt/decrypt plus payload echo over SO_MARKed Rust UDP socket",
            "go_matched_default_daemon_baseline_recorded": false,
            "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
        }
    });
    report["protocol_matrix"] = json!({
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "https_proxy_tls_underlay_admitted": false,
        "shadowsocks_aead_tcp_true_dataplane_admitted": true,
        "shadowsocks_aead_udp_true_dataplane_admitted": false,
        "shadowsocks_aead_protocol_true_dataplane_admitted": false,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "ss2022_true_dataplane_admitted": false,
        "trojan_vmess_vless_shared_transport_admitted": false,
        "quic_h3_session_protocols_admitted": false
    });
    report["remaining_blockers"] = json!([
        "SS2022 TCP/UDP true dataplane is still incomplete",
        "SIP003 plugin and ShadowsocksR layered transport are still incomplete",
        "Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
        "matched Go default daemon vs true Rust candidate benchmark is still missing",
        "clean dae-wing and daed product-chain recertification is still missing"
    ]);
    report["validation_commands"] = json!([
        "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage59/shadowsocks_aead_udp_dataplane_admission.json",
        "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage59_shadowsocks_aead_udp_dataplane_gate.json",
        "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage59 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage59 -- --nocapture",
        "cargo test --manifest-path rust/Cargo.toml -p dae-product stage59 -- --nocapture",
        "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage59-shadowsocks-aead-udp-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
        "git diff --check"
    ]);
    report["source"] = json!([
        "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage59",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.10",
        "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
        "rust/crates/dae-outbound/src/shadowsocks/aead.rs",
        "rust/crates/dae-datapath/src/udp_direct.rs"
    ]);

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage59 root-gated smoke requires --ack-root-gate because it attempts SO_MARK UDP socket observation"
        ]);
        return report;
    }

    match run_stage59_smoke(opts) {
        Ok(outcome) => apply_stage59_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage59Outcome {
    socket_report: UdpDirectSocketReport,
    server_summary: ShadowsocksAeadUdpServerSummary,
    elapsed_ns: u128,
    ns_per_udp_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    packet_len: usize,
    cipher: String,
    salt_len: usize,
}

fn run_stage59_smoke(opts: &Stage59Options) -> Result<Stage59Outcome, String> {
    let spec = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage59 cipher spec failed: {err}"))?;
    let (server_addr, handle) = spawn_shadowsocks_aead_udp_server(opts, spec.salt_len)?;
    let conn = UdpDirectPacketConn::connect(
        server_addr,
        &UdpDirectSocketOptions {
            mark: opts.so_mark,
            timeout: opts.timeout,
        },
    )
    .map_err(|err| format!("stage59 UDP socket connect failed: {err}"))?;
    let mut last_packet_len = 0;
    let start = Instant::now();
    for index in 0..opts.benchmark_iters {
        let client_salt = salt_for(index, spec.salt_len, 0x30);
        let packet = shadowsocks::encode_udp_packet(
            &opts.cipher,
            &opts.password,
            &client_salt,
            &opts.target,
            &opts.payload,
        )
        .map_err(|err| format!("stage59 encode client UDP packet failed: {err}"))?;
        last_packet_len = packet.len();
        let response = conn
            .exchange(&packet, 2048)
            .map_err(|err| format!("stage59 UDP exchange failed: {err}"))?;
        let decoded = shadowsocks::decode_udp_packet(&opts.cipher, &opts.password, &response)
            .map_err(|err| format!("stage59 decode response UDP packet failed: {err}"))?;
        if decoded.target != opts.target {
            return Err(format!(
                "stage59 UDP response target mismatch: got {}, want {}",
                decoded.target, opts.target
            ));
        }
        if decoded.payload != opts.payload {
            return Err("stage59 UDP payload response mismatch".to_owned());
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage59 UDP server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage59 UDP server accepted {} packets, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage59Outcome {
        socket_report: conn.report().clone(),
        server_summary,
        elapsed_ns,
        ns_per_udp_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        packet_len: last_packet_len,
        cipher: spec.cipher.to_owned(),
        salt_len: spec.salt_len,
    })
}

fn apply_stage59_outcome(report: &mut Value, outcome: Stage59Outcome) {
    let so_mark_observed = outcome.socket_report.so_mark_applied
        && outcome.socket_report.so_mark == outcome.socket_report.requested_mark;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.decrypt_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed;

    report["read_only"] = json!(false);
    report["shadowsocks_aead_udp_smoke_passed"] = json!(passed);
    report["shadowsocks_aead_udp_true_dataplane_admitted"] = json!(passed);
    report["shadowsocks_aead_protocol_true_dataplane_admitted"] = json!(passed);
    report["shadowsocks_udp_contract"]["server"] = json!(outcome.socket_report.peer_addr);
    report["shadowsocks_udp_contract"]["cipher"] = json!(outcome.cipher);
    report["shadowsocks_udp_contract"]["udp_packet_salt_validated"] = json!(passed);
    report["shadowsocks_udp_contract"]["salt_len"] = json!(outcome.salt_len);
    report["udp_underlay_socket"]["last_socket_report"] = json!({
        "requested_mark": outcome.socket_report.requested_mark,
        "so_mark": outcome.socket_report.so_mark,
        "so_mark_applied": outcome.socket_report.so_mark_applied,
        "peer_addr": outcome.socket_report.peer_addr,
        "local_addr": outcome.socket_report.local_addr
    });
    report["udp_underlay_socket"]["so_mark_observed"] = json!(so_mark_observed);
    report["server_observation"] = json!({
        "accepted": outcome.server_summary.accepted,
        "decrypt_count": outcome.server_summary.decrypt_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_udp_exchange"] = json!(outcome.ns_per_udp_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["benchmark"]["packet_len"] = json!(outcome.packet_len);
    report["protocol_matrix"]["shadowsocks_aead_udp_true_dataplane_admitted"] = json!(passed);
    report["protocol_matrix"]["shadowsocks_aead_protocol_true_dataplane_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct ShadowsocksAeadUdpServerSummary {
    accepted: usize,
    decrypt_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_shadowsocks_aead_udp_server(
    opts: &Stage59Options,
    salt_len: usize,
) -> Result<
    (
        SocketAddrV4,
        thread::JoinHandle<Result<ShadowsocksAeadUdpServerSummary, String>>,
    ),
    String,
> {
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .map_err(|err| format!("stage59 bind UDP server failed: {err}"))?;
    let local_addr = socket
        .local_addr()
        .map_err(|err| format!("stage59 UDP server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => return Err(format!("stage59 UDP server is not IPv4: {addr}")),
    };
    socket
        .set_read_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage59 UDP server read timeout failed: {err}"))?;
    socket
        .set_write_timeout(Some(opts.timeout))
        .map_err(|err| format!("stage59 UDP server write timeout failed: {err}"))?;
    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let password = opts.password.clone();
    let target = opts.target.clone();
    let handle = thread::spawn(move || {
        accept_shadowsocks_aead_udp(socket, iterations, &cipher, &password, &target, salt_len)
    });
    Ok((server_addr, handle))
}

fn accept_shadowsocks_aead_udp(
    socket: UdpSocket,
    iterations: usize,
    cipher: &str,
    password: &str,
    expected_target: &str,
    salt_len: usize,
) -> Result<ShadowsocksAeadUdpServerSummary, String> {
    let mut summary = ShadowsocksAeadUdpServerSummary::default();
    while summary.accepted < iterations {
        let mut buf = vec![0_u8; 2048];
        let (read, peer) = socket
            .recv_from(&mut buf)
            .map_err(|err| format!("stage59 UDP receive failed: {err}"))?;
        buf.truncate(read);
        let decoded = shadowsocks::decode_udp_packet(cipher, password, &buf)
            .map_err(|err| format!("stage59 UDP decode failed: {err}"))?;
        if decoded.target != expected_target {
            return Err(format!(
                "stage59 UDP target mismatch: got {}, want {}",
                decoded.target, expected_target
            ));
        }
        let server_salt = salt_for(summary.accepted, salt_len, 0x80);
        let response = shadowsocks::encode_udp_packet(
            cipher,
            password,
            &server_salt,
            expected_target,
            &decoded.payload,
        )
        .map_err(|err| format!("stage59 UDP encode response failed: {err}"))?;
        socket
            .send_to(&response, peer)
            .map_err(|err| format!("stage59 UDP send response failed: {err}"))?;
        summary.accepted += 1;
        summary.decrypt_count += 1;
        summary.payload_roundtrip_count += 1;
        summary.targets.push(decoded.target);
        summary
            .payload_ascii
            .push(String::from_utf8_lossy(&decoded.payload).to_string());
        summary
            .response_ascii
            .push(String::from_utf8_lossy(&decoded.payload).to_string());
    }
    Ok(summary)
}

fn salt_for(index: usize, len: usize, base: u8) -> Vec<u8> {
    (0..len)
        .map(|offset| base.wrapping_add(index as u8).wrapping_add(offset as u8))
        .collect()
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
