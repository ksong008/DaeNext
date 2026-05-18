use std::io::{ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_tcp_connect,
};
use dae_outbound::shadowsocks::{self, AeadTcpSalts};
use serde_json::{Value, json};

use crate::runner::RunnerOutput;

const DEFAULT_CIPHER: &str = "aes-128-gcm";
const DEFAULT_PASSWORD: &str = "stage58-password";
const DEFAULT_TARGET: &str = "stage58.example:443";
const DEFAULT_PAYLOAD: &[u8] = b"stage58-shadowsocks-aead-ping";

pub(crate) fn run_stage58_shadowsocks_aead_tcp_dataplane_admission(
    args: &[String],
) -> RunnerOutput {
    let opts = match Stage58Options::parse(args) {
        Ok(opts) => opts,
        Err(output) => return output,
    };
    let report = stage58_report(&opts);
    let passed = report["shadowsocks_aead_tcp_smoke_passed"]
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
struct Stage58Options {
    execute_smoke: bool,
    ack_root_gate: bool,
    benchmark_iters: usize,
    cipher: String,
    password: String,
    target: String,
    payload: Vec<u8>,
    so_mark: u32,
    mptcp: bool,
    timeout: Duration,
}

impl Default for Stage58Options {
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
            mptcp: true,
            timeout: Duration::from_secs(3),
        }
    }
}

impl Stage58Options {
    fn parse(args: &[String]) -> Result<Self, RunnerOutput> {
        let mut opts = Self::default();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--execute-smoke" => opts.execute_smoke = true,
                "--ack-root-gate" => opts.ack_root_gate = true,
                "--benchmark-iters" => {
                    opts.benchmark_iters =
                        parse_usize(&next_value(&mut iter, "stage58 --benchmark-iters")?, arg)?;
                }
                "--cipher" => opts.cipher = next_value(&mut iter, "stage58 --cipher")?,
                "--password" => opts.password = next_value(&mut iter, "stage58 --password")?,
                "--target" => opts.target = next_value(&mut iter, "stage58 --target")?,
                "--payload" => {
                    opts.payload = next_value(&mut iter, "stage58 --payload")?.into_bytes();
                }
                "--so-mark" => {
                    opts.so_mark = parse_u32(&next_value(&mut iter, "stage58 --so-mark")?, arg)?;
                }
                "--mptcp" => opts.mptcp = true,
                "--no-mptcp" => opts.mptcp = false,
                "--timeout-ms" => {
                    let timeout_ms =
                        parse_u64(&next_value(&mut iter, "stage58 --timeout-ms")?, arg)?;
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
                        "unsupported stage58 argument: {arg}"
                    )));
                }
            }
        }
        if opts.benchmark_iters == 0 {
            return Err(RunnerOutput::usage(
                "stage58 --benchmark-iters must be greater than zero",
            ));
        }
        shadowsocks::cipher_spec(&opts.cipher)
            .map_err(|err| RunnerOutput::usage(format!("stage58 requires AEAD cipher: {err}")))?;
        Ok(opts)
    }
}

fn stage58_report(opts: &Stage58Options) -> Value {
    let payload_ascii = String::from_utf8_lossy(&opts.payload).to_string();
    let mut report = json!({
        "name": "stage58-shadowsocks-aead-tcp-dataplane-admission",
        "stage": "stage58",
        "evidence_class": "opt-in-protocol-shadowsocks-aead-tcp-true-dataplane-smoke",
        "execute_smoke": opts.execute_smoke,
        "read_only": !opts.execute_smoke,
        "blocked": false,
        "blockers": [],
        "socks5_protocol_true_dataplane_admitted": true,
        "http_connect_true_dataplane_admitted": true,
        "shadowsocks_aead_tcp_smoke_passed": false,
        "shadowsocks_aead_tcp_true_dataplane_admitted": false,
        "shadowsocks_protocol_partial_admitted": false,
        "shadowsocks_protocol_true_dataplane_admitted": false,
        "ss2022_true_dataplane_admitted": false,
        "shadowsocks_udp_true_dataplane_admitted": false,
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
        "shadowsocks_contract": {
            "protocol": "Shadowsocks",
            "scope": "AEAD TCP loopback true dataplane",
            "cipher": opts.cipher,
            "target": opts.target,
            "payload_ascii": payload_ascii,
            "password_source": "local-stage58-fixture",
            "server": null,
            "aead_tcp_salts_validated": false,
            "ss2022_deferred": "SS2022 TCP/UDP true dataplane requires the AEAD-2022 protocol framing gate",
            "udp_deferred": "Shadowsocks UDP PacketConn true dataplane is not admitted by this TCP gate",
            "sip003_plugin_deferred": "SIP003 plugin/simple-obfs/v2ray-plugin shared transports are deferred",
            "ssr_deferred": "ShadowsocksR requires obfs plus stream cipher plus SSR protocol wrapper",
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
            "ns_per_aead_tcp_exchange": null,
            "scope": "Shadowsocks AEAD TCP client initial plus encrypted payload echo over Rust underlay socket",
            "go_matched_default_daemon_baseline_recorded": false,
            "go_baseline_gap": "all outbound protocols, daemon default lifecycle, and product-chain gates are not closed"
        },
        "protocol_matrix": {
            "socks5_protocol_true_dataplane_admitted": true,
            "http_connect_true_dataplane_admitted": true,
            "https_proxy_tls_underlay_admitted": false,
            "shadowsocks_aead_tcp_true_dataplane_admitted": false,
            "shadowsocks_protocol_true_dataplane_admitted": false,
            "ss2022_true_dataplane_admitted": false,
            "trojan_vmess_vless_shared_transport_admitted": false,
            "quic_h3_session_protocols_admitted": false
        },
        "remaining_blockers": [
            "SS2022 TCP/UDP true dataplane is still incomplete",
            "Shadowsocks UDP PacketConn true dataplane is still incomplete",
            "SIP003 plugin and ShadowsocksR layered transport are still incomplete",
            "Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS, HTTPS proxy, and shared transport true dataplanes are still incomplete",
            "matched Go default daemon vs true Rust candidate benchmark is still missing",
            "clean dae-wing and daed product-chain recertification is still missing"
        ],
        "validation_commands": [
            "python3 -m json.tool testdata/rebuild-golden/engine/runtime_stage58/shadowsocks_aead_tcp_dataplane_admission.json",
            "python3 -m json.tool testdata/rebuild-golden/product/daemon/stage58_shadowsocks_aead_tcp_dataplane_gate.json",
            "cargo test --manifest-path rust/Cargo.toml -p dae-cli stage58 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-product stage58 -- --nocapture",
            "cargo test --manifest-path rust/Cargo.toml -p dae-outbound stage18_shadowsocks_aead_tcp_dataplane_echoes_payload -- --nocapture",
            "cargo run --manifest-path rust/Cargo.toml -p dae-cli --bin dae-cli-optin --quiet -- runtime stage58-shadowsocks-aead-tcp-dataplane-admission --execute-smoke --ack-root-gate --benchmark-iters 10",
            "git diff --check"
        ],
        "source": [
            "DAEX_RUST_REBUILD_PLAN_2026-05-16.md:stage58",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.10",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.3",
            "DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:33.8",
            "rust/crates/dae-outbound/src/shadowsocks/aead.rs",
            "rust/crates/dae-outbound/src/shadowsocks/ss2022.rs",
            "rust/crates/dae-datapath/src/tcp_direct.rs"
        ]
    });

    if !opts.execute_smoke {
        return report;
    }
    if !opts.ack_root_gate {
        report["blocked"] = json!(true);
        report["blockers"] = json!([
            "stage58 root-gated smoke requires --ack-root-gate because it attempts SO_MARK/MPTCP underlay socket observation"
        ]);
        return report;
    }

    match run_stage58_smoke(opts) {
        Ok(outcome) => apply_stage58_outcome(&mut report, outcome),
        Err(err) => {
            report["blocked"] = json!(true);
            report["blockers"] = json!([err]);
        }
    }
    report
}

#[derive(Debug)]
struct Stage58Outcome {
    listener_report: TcpLoopbackListenerReport,
    last_dial_report: TcpDirectDialReport,
    server_summary: ShadowsocksAeadServerSummary,
    elapsed_ns: u128,
    ns_per_aead_tcp_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
    cipher: String,
    client_salt_len: usize,
    server_salt_len: usize,
}

fn run_stage58_smoke(opts: &Stage58Options) -> Result<Stage58Outcome, String> {
    let spec = shadowsocks::cipher_spec(&opts.cipher)
        .map_err(|err| format!("stage58 cipher spec failed: {err}"))?;
    let (server_addr, listener_report, handle) =
        spawn_shadowsocks_aead_server(opts, spec.salt_len)?;
    let mut last_dial_report = None;
    let start = Instant::now();
    for index in 0..opts.benchmark_iters {
        let mut connected = magic_tcp_connect(
            server_addr,
            &TcpDirectDialOptions {
                mark: opts.so_mark,
                mptcp: opts.mptcp,
                timeout: opts.timeout,
            },
        )
        .map_err(|err| format!("stage58 magic_tcp_connect failed: {err}"))?;
        let client_salt = salt_for(index, spec.salt_len, 0x20);
        let server_salt = salt_for(index, spec.salt_len, 0x70);
        let report = shadowsocks::tcp_exchange_over_stream(
            &mut connected.stream,
            &server_addr.to_string(),
            &opts.cipher,
            &opts.password,
            &opts.target,
            &opts.payload,
            AeadTcpSalts {
                client: &client_salt,
                server: &server_salt,
            },
        )
        .map_err(|err| format!("stage58 shadowsocks AEAD TCP exchange failed: {err}"))?;
        if report.echoed_payload != opts.payload {
            return Err("stage58 shadowsocks AEAD payload response mismatch".to_owned());
        }
        last_dial_report = Some(connected.report);
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage58 shadowsocks server thread panicked".to_owned())??;
    if server_summary.accepted != opts.benchmark_iters {
        return Err(format!(
            "stage58 shadowsocks server accepted {} connections, want {}",
            server_summary.accepted, opts.benchmark_iters
        ));
    }
    Ok(Stage58Outcome {
        listener_report,
        last_dial_report: last_dial_report
            .ok_or_else(|| "stage58 missing underlay dial report".to_owned())?,
        server_summary,
        elapsed_ns,
        ns_per_aead_tcp_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
        cipher: spec.cipher.to_owned(),
        client_salt_len: spec.salt_len,
        server_salt_len: spec.salt_len,
    })
}

fn apply_stage58_outcome(report: &mut Value, outcome: Stage58Outcome) {
    let so_mark_observed = outcome.last_dial_report.so_mark_applied
        && outcome.last_dial_report.so_mark == outcome.last_dial_report.requested_mark;
    let mptcp_status_recorded = outcome.last_dial_report.mptcp_socket_attempted
        || !outcome.last_dial_report.requested_mptcp;
    let server_complete = outcome.server_summary.accepted == outcome.exchange_count
        && outcome.server_summary.decrypt_count == outcome.exchange_count
        && outcome.server_summary.payload_roundtrip_count == outcome.exchange_count;
    let passed = server_complete && so_mark_observed && mptcp_status_recorded;

    report["read_only"] = json!(false);
    report["shadowsocks_aead_tcp_smoke_passed"] = json!(passed);
    report["shadowsocks_aead_tcp_true_dataplane_admitted"] = json!(passed);
    report["shadowsocks_protocol_partial_admitted"] = json!(passed);
    report["shadowsocks_contract"]["server"] = json!(outcome.last_dial_report.peer_addr);
    report["shadowsocks_contract"]["cipher"] = json!(outcome.cipher);
    report["shadowsocks_contract"]["aead_tcp_salts_validated"] = json!(passed);
    report["shadowsocks_contract"]["client_salt_len"] = json!(outcome.client_salt_len);
    report["shadowsocks_contract"]["server_salt_len"] = json!(outcome.server_salt_len);
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
        "decrypt_count": outcome.server_summary.decrypt_count,
        "payload_roundtrip_count": outcome.server_summary.payload_roundtrip_count,
        "targets": outcome.server_summary.targets,
        "payload_ascii": outcome.server_summary.payload_ascii,
        "response_ascii": outcome.server_summary.response_ascii
    });
    report["benchmark"]["benchmark_recorded"] = json!(passed);
    report["benchmark"]["elapsed_ns"] = json!(outcome.elapsed_ns);
    report["benchmark"]["ns_per_aead_tcp_exchange"] = json!(outcome.ns_per_aead_tcp_exchange);
    report["benchmark"]["payload_len"] = json!(outcome.payload_len);
    report["protocol_matrix"]["shadowsocks_aead_tcp_true_dataplane_admitted"] = json!(passed);
}

#[derive(Debug, Default)]
struct ShadowsocksAeadServerSummary {
    accepted: usize,
    decrypt_count: usize,
    payload_roundtrip_count: usize,
    targets: Vec<String>,
    payload_ascii: Vec<String>,
    response_ascii: Vec<String>,
}

fn spawn_shadowsocks_aead_server(
    opts: &Stage58Options,
    salt_len: usize,
) -> Result<
    (
        SocketAddrV4,
        TcpLoopbackListenerReport,
        thread::JoinHandle<Result<ShadowsocksAeadServerSummary, String>>,
    ),
    String,
> {
    let (listener, listener_report) = bind_loopback_tcp_listener(opts.mptcp)
        .map_err(|err| format!("stage58 bind loopback shadowsocks server failed: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("stage58 shadowsocks server local_addr failed: {err}"))?;
    let server_addr = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(addr) => {
            return Err(format!("stage58 shadowsocks listener is not IPv4: {addr}"));
        }
    };
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("stage58 shadowsocks nonblocking failed: {err}"))?;

    let iterations = opts.benchmark_iters;
    let cipher = opts.cipher.clone();
    let password = opts.password.clone();
    let target = opts.target.clone();
    let timeout = opts.timeout;
    let handle = thread::spawn(move || {
        accept_shadowsocks_aead(
            listener, iterations, &cipher, &password, &target, salt_len, timeout,
        )
    });
    Ok((server_addr, listener_report, handle))
}

fn accept_shadowsocks_aead(
    listener: TcpListener,
    iterations: usize,
    cipher: &str,
    password: &str,
    expected_target: &str,
    salt_len: usize,
    timeout: Duration,
) -> Result<ShadowsocksAeadServerSummary, String> {
    let mut summary = ShadowsocksAeadServerSummary::default();
    let deadline = Instant::now() + timeout.saturating_mul(iterations as u32 + 2);
    while summary.accepted < iterations {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|err| format!("stage58 server set read timeout failed: {err}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|err| format!("stage58 server set write timeout failed: {err}"))?;
                let server_salt = salt_for(summary.accepted, salt_len, 0x70);
                handle_shadowsocks_aead(
                    &mut stream,
                    cipher,
                    password,
                    expected_target,
                    &server_salt,
                    &mut summary,
                )?;
                summary.accepted += 1;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(format!(
                    "stage58 shadowsocks server timed out after accepting {} of {} connections",
                    summary.accepted, iterations
                ));
            }
            Err(err) => return Err(format!("stage58 shadowsocks accept failed: {err}")),
        }
    }
    Ok(summary)
}

fn handle_shadowsocks_aead(
    stream: &mut TcpStream,
    cipher: &str,
    password: &str,
    expected_target: &str,
    server_salt: &[u8],
    summary: &mut ShadowsocksAeadServerSummary,
) -> Result<(), String> {
    let (target, request_payload) =
        shadowsocks::read_client_initial_from_stream(stream, cipher, password)
            .map_err(|err| format!("stage58 read client initial failed: {err}"))?;
    let target_authority = target.authority();
    if target_authority != expected_target {
        return Err(format!(
            "stage58 shadowsocks target mismatch: got {target_authority}, want {expected_target}"
        ));
    }
    let response =
        shadowsocks::encode_server_payload(cipher, password, server_salt, &request_payload)
            .map_err(|err| format!("stage58 encode server payload failed: {err}"))?;
    stream
        .write_all(&response)
        .map_err(|err| format!("stage58 write encrypted response failed: {err}"))?;
    summary.decrypt_count += 1;
    summary.payload_roundtrip_count += 1;
    summary.targets.push(target_authority);
    summary
        .payload_ascii
        .push(String::from_utf8_lossy(&request_payload).to_string());
    summary
        .response_ascii
        .push(String::from_utf8_lossy(&request_payload).to_string());
    Ok(())
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
