use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dae_datapath::{
    TcpDirectDialOptions, TcpDirectDialReport, TcpLoopbackListenerReport,
    bind_loopback_tcp_listener, magic_network_bytes, magic_tcp_connect,
};
use dae_netutil::parse_magic_network;
use serde_json::{Value, json};

use super::super::ProductionRuntimeOwnerOptions;
use super::super::command::{CommandSpec, run_observation_command};
use super::{
    CLIENT_NETNS, DEFAULT_ACTIVE_TCP_TARGET_IP, DEFAULT_ACTIVE_TCP_TARGET_PORT, RELAY_TCP_PAYLOAD,
    RELAY_TCP_RESPONSE, TCP_PAYLOAD, TCP_RESPONSE,
};

pub(in crate::production_runtime_owner) fn run_active_tcp_probe(
    listener: TcpListener,
    options: &ProductionRuntimeOwnerOptions,
) -> (Value, Value, bool, bool) {
    let target = format!(
        "{}:{}",
        options.active_tcp_target_ip, options.active_tcp_target_port
    );
    let accept_handle = thread::spawn(move || tcp_accept_probe(listener));
    thread::sleep(Duration::from_millis(100));
    let client = run_client_probe(&target);
    let accept = accept_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "accept thread panicked"}));
    let original_destination_observed = accept["local_addr"].as_str() == Some(target.as_str());
    let tcp_reply_path_succeeded = client["stdout"]
        .as_str()
        .is_some_and(|stdout| stdout.contains("active-tcp-tproxy-ack"));
    (
        accept,
        client,
        original_destination_observed,
        tcp_reply_path_succeeded,
    )
}

fn tcp_accept_probe(listener: TcpListener) -> Value {
    match tcp_accept_probe_inner(listener) {
        Ok(value) => value,
        Err(err) => json!({"status": "fail", "error": err}),
    }
}

fn tcp_accept_probe_inner(listener: TcpListener) -> Result<Value, String> {
    listener
        .set_nonblocking(false)
        .map_err(|err| format!("set listener blocking: {err}"))?;
    let (mut stream, peer) = listener.accept().map_err(|err| format!("accept: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| format!("set read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| format!("set write timeout: {err}"))?;
    let local = stream
        .local_addr()
        .map_err(|err| format!("local_addr: {err}"))?;
    let mut buf = [0_u8; 64];
    let n = stream
        .read(&mut buf)
        .map_err(|err| format!("read: {err}"))?;
    if &buf[..n] != TCP_PAYLOAD {
        return Err(format!(
            "unexpected payload: {}",
            String::from_utf8_lossy(&buf[..n])
        ));
    }
    stream
        .write_all(TCP_RESPONSE)
        .map_err(|err| format!("write response: {err}"))?;
    Ok(json!({
        "status": "pass",
        "local_addr": local.to_string(),
        "peer_addr": peer.to_string(),
        "payload": String::from_utf8_lossy(TCP_PAYLOAD),
        "response": String::from_utf8_lossy(TCP_RESPONSE),
    }))
}

fn run_client_probe(target: &str) -> Value {
    let script = format!(
        "import socket,sys\ns=socket.create_connection(({target_ip:?},{target_port}),3)\ns.settimeout(3)\ns.sendall(b\"active-tcp-tproxy-ping\")\ndata=s.recv(64)\nprint(data.decode('ascii','replace'))\ns.close()\nsys.exit(0 if data == b\"active-tcp-tproxy-ack\" else 2)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_ACTIVE_TCP_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_ACTIVE_TCP_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        ["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

#[allow(clippy::type_complexity)]
pub(in crate::production_runtime_owner) fn run_active_tcp_relay_probe(
    listener: TcpListener,
    options: &ProductionRuntimeOwnerOptions,
) -> (Value, Value, Value, Value, Value, bool, bool, bool, bool) {
    let target = format!(
        "{}:{}",
        options.active_tcp_target_ip, options.active_tcp_target_port
    );
    let iterations = options.active_tcp_benchmark_iters;
    let (upstream_listener, upstream_listener_report) = match bind_loopback_tcp_listener(
        options.active_tcp_mptcp && options.active_tcp_upstream_mptcp,
    ) {
        Ok(value) => value,
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to bind upstream listener: {err}")}),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_addr = match upstream_listener.local_addr() {
        Ok(SocketAddr::V4(addr)) => addr,
        Ok(addr) => {
            return (
                json!({"status": "fail", "error": format!("unexpected upstream address family: {addr}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
        Err(err) => {
            return (
                json!({"status": "fail", "error": format!("failed to read upstream address: {err}")}),
                upstream_listener_json(&upstream_listener_report),
                Value::Null,
                Value::Null,
                Value::Null,
                false,
                false,
                false,
                false,
            );
        }
    };
    let upstream_handle = thread::spawn(move || {
        upstream_echo_probe(
            upstream_listener,
            upstream_listener_report,
            iterations,
            RELAY_TCP_PAYLOAD,
            RELAY_TCP_RESPONSE,
        )
    });
    let relay_target = target.clone();
    let mark = options.active_tcp_so_mark;
    let mptcp = options.active_tcp_mptcp;
    let accept_handle = thread::spawn(move || {
        tcp_relay_accept_probe(
            listener,
            upstream_addr,
            &relay_target,
            mark,
            mptcp,
            iterations,
        )
    });
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let client = run_client_relay_probe(&target, iterations);
    let accept = accept_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "relay accept thread panicked"}));
    let upstream = upstream_handle
        .join()
        .unwrap_or_else(|_| json!({"status": "fail", "error": "upstream thread panicked"}));
    let elapsed = started.elapsed();
    let original_destination_observed =
        accept["first_local_addr"].as_str() == Some(target.as_str());
    let outbound_relay_succeeded = accept["status"].as_str() == Some("pass")
        && upstream["status"].as_str() == Some("pass")
        && client["status"].as_str() == Some("pass")
        && client["stdout"]
            .as_str()
            .is_some_and(|stdout| stdout.contains("active-tcp-relay-ack-count="));
    let outbound_dial = accept["last_outbound_dial"].clone();
    let so_mark_observed = outbound_dial["so_mark"].as_u64() == Some(mark as u64)
        && outbound_dial["so_mark_applied"].as_bool().unwrap_or(false);
    let mptcp_observed = !mptcp
        || outbound_dial["mptcp_protocol_observed"]
            .as_bool()
            .unwrap_or(false)
        || outbound_dial["mptcp_info_available"]
            .as_bool()
            .unwrap_or(false);
    let benchmark = if iterations > 1 && outbound_relay_succeeded {
        json!({
            "status": "pass",
            "iterations": iterations,
            "elapsed_ns": elapsed.as_nanos(),
            "ns_per_connection": elapsed.as_nanos() as f64 / iterations as f64,
            "scope": "daemon-owned active TCP ingress plus Rust direct outbound relay loopback benchmark",
            "go_matched_default_daemon_baseline_recorded": false,
        })
    } else {
        json!({
            "status": if iterations > 1 { "fail" } else { "skipped" },
            "iterations": iterations,
            "reason": if iterations > 1 { "relay smoke failed" } else { "benchmark-iters is 1" },
        })
    };
    (
        accept,
        upstream,
        client,
        outbound_dial,
        benchmark,
        original_destination_observed,
        outbound_relay_succeeded,
        so_mark_observed,
        mptcp_observed,
    )
}

fn tcp_relay_accept_probe(
    listener: TcpListener,
    upstream_addr: SocketAddrV4,
    target: &str,
    mark: u32,
    mptcp: bool,
    iterations: u32,
) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let started = Instant::now();
    let magic_network = magic_network_bytes("tcp", mark, mptcp);
    let parsed_magic = parse_magic_network(&magic_network).ok();
    let mut first_local_addr = None;
    let mut first_peer_addr = None;
    let mut last_outbound_dial = Value::Null;
    let mut relayed_connections = 0_u32;
    let mut bytes_client_to_outbound = 0_usize;
    let mut bytes_outbound_to_client = 0_usize;
    for _ in 0..iterations {
        let (mut inbound, peer) = match accept_with_deadline(&listener, Duration::from_secs(4)) {
            Ok(accepted) => accepted,
            Err(err) => return json!({"status": "fail", "error": err.to_string()}),
        };
        let _ = inbound.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = inbound.set_write_timeout(Some(Duration::from_secs(2)));
        let local_addr = inbound.local_addr().map(|addr| addr.to_string()).ok();
        if first_local_addr.is_none() {
            first_local_addr = local_addr.clone();
            first_peer_addr = Some(peer.to_string());
        }
        let mut payload = vec![0_u8; RELAY_TCP_PAYLOAD.len()];
        if let Err(err) = inbound.read_exact(&mut payload) {
            return json!({"status": "fail", "error": format!("read inbound payload: {err}")});
        }
        if payload != RELAY_TCP_PAYLOAD {
            return json!({
                "status": "fail",
                "error": "unexpected inbound payload",
                "payload": String::from_utf8_lossy(&payload).to_string(),
            });
        }
        let mut outbound = match magic_tcp_connect(
            upstream_addr,
            &TcpDirectDialOptions {
                mark,
                mptcp,
                timeout: Duration::from_secs(3),
            },
        ) {
            Ok(conn) => conn,
            Err(err) => return json!({"status": "fail", "error": format!("outbound dial: {err}")}),
        };
        if let Err(err) = outbound.stream.write_all(&payload) {
            return json!({"status": "fail", "error": format!("write outbound payload: {err}")});
        }
        let mut response = vec![0_u8; RELAY_TCP_RESPONSE.len()];
        if let Err(err) = outbound.stream.read_exact(&mut response) {
            return json!({"status": "fail", "error": format!("read outbound response: {err}")});
        }
        if response != RELAY_TCP_RESPONSE {
            return json!({
                "status": "fail",
                "error": "unexpected outbound response",
                "response": String::from_utf8_lossy(&response).to_string(),
            });
        }
        if let Err(err) = inbound.write_all(&response) {
            return json!({"status": "fail", "error": format!("write client response: {err}")});
        }
        bytes_client_to_outbound += payload.len();
        bytes_outbound_to_client += response.len();
        relayed_connections += 1;
        last_outbound_dial = tcp_direct_dial_report_json(&outbound.report);
    }
    let passed = relayed_connections == iterations
        && first_local_addr.as_deref() == Some(target)
        && last_outbound_dial["so_mark"].as_u64() == Some(mark as u64)
        && last_outbound_dial["so_mark_applied"]
            .as_bool()
            .unwrap_or(false)
        && (!mptcp
            || last_outbound_dial["mptcp_protocol_observed"]
                .as_bool()
                .unwrap_or(false)
            || last_outbound_dial["mptcp_info_available"]
                .as_bool()
                .unwrap_or(false));
    json!({
        "status": if passed { "pass" } else { "fail" },
        "iterations": iterations,
        "relayed_connections": relayed_connections,
        "first_peer_addr": first_peer_addr,
        "first_local_addr": first_local_addr,
        "bytes_client_to_outbound": bytes_client_to_outbound,
        "bytes_outbound_to_client": bytes_outbound_to_client,
        "magic_network": {
            "encoded_len": magic_network.len(),
            "parsed_network": parsed_magic
                .as_ref()
                .and_then(|value| value.network_str().ok()),
            "parsed_mark": parsed_magic.as_ref().map(|value| value.mark),
            "parsed_mptcp": parsed_magic.as_ref().map(|value| value.mptcp),
        },
        "last_outbound_dial": last_outbound_dial,
        "elapsed_ns": started.elapsed().as_nanos(),
    })
}

fn upstream_echo_probe(
    listener: TcpListener,
    report: TcpLoopbackListenerReport,
    iterations: u32,
    expected_payload: &'static [u8],
    response_payload: &'static [u8],
) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "listener": upstream_listener_json(&report), "error": err.to_string()});
    }
    let mut accepted = 0_u32;
    for _ in 0..iterations {
        let (mut conn, peer) = match accept_with_deadline(&listener, Duration::from_secs(4)) {
            Ok(accepted) => accepted,
            Err(err) => {
                return json!({
                    "status": "fail",
                    "listener": upstream_listener_json(&report),
                    "accepted": accepted,
                    "error": err.to_string(),
                });
            }
        };
        let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = conn.set_write_timeout(Some(Duration::from_secs(2)));
        let mut payload = vec![0_u8; expected_payload.len()];
        if let Err(err) = conn.read_exact(&mut payload) {
            return json!({"status": "fail", "listener": upstream_listener_json(&report), "accepted": accepted, "error": format!("read payload from {peer}: {err}")});
        }
        if payload != expected_payload {
            return json!({
                "status": "fail",
                "listener": upstream_listener_json(&report),
                "accepted": accepted,
                "error": "unexpected upstream payload",
                "payload": String::from_utf8_lossy(&payload).to_string(),
            });
        }
        if let Err(err) = conn.write_all(response_payload) {
            return json!({"status": "fail", "listener": upstream_listener_json(&report), "accepted": accepted, "error": format!("write response to {peer}: {err}")});
        }
        accepted += 1;
    }
    json!({
        "status": "pass",
        "listener": upstream_listener_json(&report),
        "accepted": accepted,
        "iterations": iterations,
    })
}

fn run_client_relay_probe(target: &str, iterations: u32) -> Value {
    let script = format!(
        "import socket,sys\nok=0\nfor i in range({iterations}):\n    s=socket.create_connection(({target_ip:?},{target_port}),3)\n    s.settimeout(3)\n    s.sendall(b\"active-tcp-relay-ping\")\n    data=s.recv(64)\n    s.close()\n    if data != b\"active-tcp-relay-ack\":\n        print(data.decode('ascii','replace'))\n        sys.exit(2)\n    ok += 1\nprint(f\"active-tcp-relay-ack-count={{ok}}\")\nsys.exit(0)\n",
        target_ip = target
            .split(':')
            .next()
            .unwrap_or(DEFAULT_ACTIVE_TCP_TARGET_IP),
        target_port = target
            .split(':')
            .nth(1)
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(DEFAULT_ACTIVE_TCP_TARGET_PORT),
    );
    run_observation_command(CommandSpec::new(
        "ip",
        ["netns", "exec", CLIENT_NETNS, "python3", "-c", &script],
    ))
}

fn accept_with_deadline(
    listener: &TcpListener,
    timeout: Duration,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err),
        }
    }
}

fn upstream_listener_json(report: &TcpLoopbackListenerReport) -> Value {
    json!({
        "requested_mptcp": report.requested_mptcp,
        "mptcp_socket_created": report.mptcp_socket_created,
        "fallback_used": report.fallback_used,
        "socket_protocol": report.socket_protocol,
        "local_addr": report.local_addr,
    })
}

fn tcp_direct_dial_report_json(report: &TcpDirectDialReport) -> Value {
    json!({
        "requested_mark": report.requested_mark,
        "requested_mptcp": report.requested_mptcp,
        "mptcp_socket_attempted": report.mptcp_socket_attempted,
        "mptcp_socket_created": report.mptcp_socket_created,
        "mptcp_connect_fallback_used": report.mptcp_connect_fallback_used,
        "socket_protocol": report.socket_protocol,
        "so_mark": report.so_mark,
        "so_mark_applied": report.so_mark_applied,
        "mptcp_info_available": report.mptcp_info_available,
        "mptcp_fallen_back": report.mptcp_fallen_back,
        "mptcp_protocol_observed": report.mptcp_protocol_observed,
        "peer_addr": report.peer_addr,
        "local_addr": report.local_addr,
    })
}
