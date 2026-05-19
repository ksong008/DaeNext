use super::super::*;

pub(in crate::runtime_stage50_tcp_gate) fn tcp_accept_probe(listener: TcpListener) -> Value {
    if let Err(err) = listener.set_nonblocking(true) {
        return json!({"status": "fail", "error": err.to_string()});
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let (mut stream, peer) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return json!({"status": "fail", "error": err.to_string()}),
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let local_addr = stream.local_addr().map(|addr| addr.to_string()).ok();
    let mut buf = vec![0_u8; TCP_PAYLOAD.len()];
    let read_status = stream.read_exact(&mut buf);
    let write_status = if read_status.is_ok() {
        stream.write_all(TCP_RESPONSE)
    } else {
        Ok(())
    };
    let passed = read_status.is_ok() && write_status.is_ok() && buf == TCP_PAYLOAD;
    json!({
        "status": if passed { "pass" } else { "fail" },
        "peer_addr": peer.to_string(),
        "local_addr": local_addr,
        "payload_matched": buf == TCP_PAYLOAD,
        "read_error": read_status.err().map(|err| err.to_string()),
        "write_error": write_status.err().map(|err| err.to_string()),
    })
}

pub(in crate::runtime_stage50_tcp_gate) fn tcp_relay_accept_probe(
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
        let mut payload = vec![0_u8; STAGE51_TCP_PAYLOAD.len()];
        if let Err(err) = inbound.read_exact(&mut payload) {
            return json!({"status": "fail", "error": format!("read inbound payload: {err}")});
        }
        if payload != STAGE51_TCP_PAYLOAD {
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
        let mut response = vec![0_u8; STAGE51_TCP_RESPONSE.len()];
        if let Err(err) = outbound.stream.read_exact(&mut response) {
            return json!({"status": "fail", "error": format!("read outbound response: {err}")});
        }
        if response != STAGE51_TCP_RESPONSE {
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

pub(in crate::runtime_stage50_tcp_gate) fn tcp_route_table_group_relay_accept_probe(
    listener: TcpListener,
    upstream_addr: SocketAddrV4,
    dial_target: &str,
    original_target: &str,
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
        let mut payload = vec![0_u8; STAGE52_TCP_PAYLOAD.len()];
        if let Err(err) = inbound.read_exact(&mut payload) {
            return json!({"status": "fail", "error": format!("read inbound payload: {err}")});
        }
        if payload != STAGE52_TCP_PAYLOAD {
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
        let mut response = vec![0_u8; STAGE52_TCP_RESPONSE.len()];
        if let Err(err) = outbound.stream.read_exact(&mut response) {
            return json!({"status": "fail", "error": format!("read outbound response: {err}")});
        }
        if response != STAGE52_TCP_RESPONSE {
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
        && first_local_addr.as_deref() == Some(original_target)
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
        "dial_target": dial_target,
        "actual_upstream_addr": upstream_addr.to_string(),
        "dial_target_used_as_actual_socket_target": dial_target == upstream_addr.to_string(),
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
