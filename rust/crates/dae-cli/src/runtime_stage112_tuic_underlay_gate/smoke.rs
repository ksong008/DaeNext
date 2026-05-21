use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{UdpDirectPacketConn, UdpDirectSocketOptions, UdpDirectSocketReport};
use dae_outbound::shared_transport;
use serde_json::{Value, json};

use super::options::Stage112Options;

pub(super) struct Stage112Outcome {
    endpoint: SocketAddrV4,
    socket_report: UdpDirectSocketReport,
    server_summary: TuicUdpServerSummary,
    elapsed_ns: u128,
    ns_per_exchange: f64,
    exchange_count: usize,
    payload_len: usize,
}

#[derive(Debug)]
struct TuicUdpServerSummary {
    received: usize,
    parsed: usize,
    echoed: usize,
    last_flow_id: u32,
    last_datagram_id: u32,
}

pub(super) fn run_stage112_smoke(opts: &Stage112Options) -> Result<Stage112Outcome, String> {
    let (endpoint, handle) = spawn_stage112_udp_echo_server(opts.benchmark_iters, opts.timeout)?;
    let conn = UdpDirectPacketConn::connect(
        endpoint,
        &UdpDirectSocketOptions {
            mark: opts.so_mark,
            timeout: opts.timeout,
        },
    )
    .map_err(|err| format!("stage112 UDP underlay connect failed: {err}"))?;
    let start = Instant::now();
    for i in 0..opts.benchmark_iters {
        let options = shared_transport::QuicH3HarnessOptions::new(
            112,
            i as u32 + 1,
            "tuic",
            opts.so_mark,
            opts.mptcp,
        );
        let packet = shared_transport::quic_h3_datagram_packet(&options, &opts.payload)
            .map_err(|err| format!("stage112 build UDP datagram failed: {err}"))?;
        let echoed = conn
            .exchange(&packet, packet.len())
            .map_err(|err| format!("stage112 UDP underlay exchange failed: {err}"))?;
        let parsed = shared_transport::parse_quic_h3_datagram(&echoed)
            .map_err(|err| format!("stage112 parse echoed datagram failed: {err}"))?;
        if parsed.payload != opts.payload {
            return Err("stage112 TUIC UDP underlay payload mismatch".to_owned());
        }
    }
    let elapsed_ns = start.elapsed().as_nanos();
    let server_summary = handle
        .join()
        .map_err(|_| "stage112 TUIC UDP server thread panicked".to_owned())??;
    if server_summary.received != opts.benchmark_iters {
        return Err(format!(
            "stage112 TUIC UDP server received {}, want {}",
            server_summary.received, opts.benchmark_iters
        ));
    }
    Ok(Stage112Outcome {
        endpoint,
        socket_report: conn.report().clone(),
        server_summary,
        elapsed_ns,
        ns_per_exchange: elapsed_ns as f64 / opts.benchmark_iters as f64,
        exchange_count: opts.benchmark_iters,
        payload_len: opts.payload.len(),
    })
}

fn spawn_stage112_udp_echo_server(
    exchange_count: usize,
    timeout: Duration,
) -> Result<
    (
        SocketAddrV4,
        thread::JoinHandle<Result<TuicUdpServerSummary, String>>,
    ),
    String,
> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|err| format!("stage112 UDP echo bind failed: {err}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("stage112 UDP echo timeout failed: {err}"))?;
    let endpoint = match socket
        .local_addr()
        .map_err(|err| format!("stage112 UDP echo local addr failed: {err}"))?
    {
        std::net::SocketAddr::V4(addr) => addr,
        std::net::SocketAddr::V6(_) => {
            return Err("stage112 UDP echo unexpectedly bound IPv6".to_owned());
        }
    };
    let handle = thread::spawn(move || {
        let mut summary = TuicUdpServerSummary {
            received: 0,
            parsed: 0,
            echoed: 0,
            last_flow_id: 0,
            last_datagram_id: 0,
        };
        let mut buf = [0_u8; 2048];
        for _ in 0..exchange_count {
            let (n, peer) = socket
                .recv_from(&mut buf)
                .map_err(|err| format!("stage112 UDP echo recv failed: {err}"))?;
            summary.received += 1;
            let parsed = shared_transport::parse_quic_h3_datagram(&buf[..n])
                .map_err(|err| format!("stage112 UDP echo parse failed: {err}"))?;
            summary.parsed += 1;
            summary.last_flow_id = parsed.flow_id;
            summary.last_datagram_id = parsed.datagram_id;
            socket
                .send_to(&buf[..n], peer)
                .map_err(|err| format!("stage112 UDP echo send failed: {err}"))?;
            summary.echoed += 1;
        }
        Ok(summary)
    });
    Ok((endpoint, handle))
}

pub(super) fn apply_stage112_outcome(report: &mut Value, outcome: Stage112Outcome) {
    let so_mark_observed = outcome.socket_report.so_mark_applied
        && outcome.socket_report.so_mark == outcome.socket_report.requested_mark;
    let server_complete = outcome.server_summary.received == outcome.exchange_count
        && outcome.server_summary.parsed == outcome.exchange_count
        && outcome.server_summary.echoed == outcome.exchange_count;
    let passed = server_complete && so_mark_observed;

    report["read_only"] = json!(false);
    report["tuic_udp_underlay_socket_smoke_passed"] = json!(passed);
    report["tuic_udp_underlay_socket_admitted"] = json!(passed);
    report["tuic_so_mark_loopback_observed"] = json!(so_mark_observed);
    report["underlay_socket"]["listener"] = json!({
        "local_addr": outcome.endpoint.to_string()
    });
    report["underlay_socket"]["last_socket_report"] = json!({
        "requested_mark": outcome.socket_report.requested_mark,
        "so_mark": outcome.socket_report.so_mark,
        "so_mark_applied": outcome.socket_report.so_mark_applied,
        "peer_addr": outcome.socket_report.peer_addr,
        "local_addr": outcome.socket_report.local_addr
    });
    report["underlay_socket"]["so_mark_observed"] = json!(so_mark_observed);
    report["server_observation"] = json!({
        "received": outcome.server_summary.received,
        "parsed": outcome.server_summary.parsed,
        "echoed": outcome.server_summary.echoed,
        "last_flow_id": outcome.server_summary.last_flow_id,
        "last_datagram_id": outcome.server_summary.last_datagram_id,
        "payload_len": outcome.payload_len
    });
    report["benchmark"] = json!({
        "benchmark_recorded": passed,
        "iterations": outcome.exchange_count,
        "elapsed_ns": outcome.elapsed_ns,
        "ns_per_tuic_udp_underlay_exchange": outcome.ns_per_exchange,
        "scope": "local UDP underlay datagram echo with TUIC TCP-request UDP-underlay, SO_MARK, and MPTCP-drop contract checks; not a full TUIC QUIC client dataplane",
        "go_matched_default_daemon_baseline_recorded": false,
        "go_baseline_gap": "full TUIC QUIC handshake/auth/datagram behavior, outbound registry/group semantics, daemon default lifecycle, and product-chain gates are not closed"
    });
    report["protocol_matrix"]["tuic_udp_underlay_socket_admitted"] = json!(passed);
}
