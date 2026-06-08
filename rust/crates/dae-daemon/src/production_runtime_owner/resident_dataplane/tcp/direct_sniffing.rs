fn handle_direct_tcp_connection(
    inbound: &mut TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpDirectSelection,
    stop: &AtomicBool,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let mut direct = open_direct_tcp_connection(
        &selection.route.dial_target,
        selection.route.final_mark,
        selection.mptcp,
    )?;
    let stats = relay_tcp_direct(inbound, &mut direct.stream, stop, &sniff.payload, metrics)?;
    Ok(direct_tcp_finished_event(
        peer,
        original_dst,
        &selection,
        sniff,
        direct.target,
        &direct.report,
        &stats,
        "per-connection-thread-legacy",
    ))
}

async fn handle_direct_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: TcpDirectSelection,
    stop: Arc<AtomicBool>,
    sniff: &TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
) -> Result<Value, String> {
    let direct = open_direct_tcp_connection_async(
        selection.route.dial_target.clone(),
        selection.route.final_mark,
        selection.mptcp,
    )
    .await?;
    let DirectTcpConnection {
        stream,
        report,
        target,
    } = direct;
    let mut direct_stream = TokioTcpStream::from_std(stream)
        .map_err(|err| format!("adopt async direct TCP stream: {err}"))?;
    let stats =
        relay_tcp_direct_async(inbound, &mut direct_stream, stop, &sniff.payload, metrics).await?;
    Ok(direct_tcp_finished_event(
        peer,
        original_dst,
        &selection,
        sniff,
        target,
        &report,
        &stats,
        "async-direct",
    ))
}

fn direct_tcp_finished_event(
    peer: SocketAddr,
    original_dst: SocketAddrV4,
    selection: &TcpDirectSelection,
    sniff: &TcpSniffReport,
    direct_target: SocketAddrV4,
    direct_report: &TcpDirectDialReport,
    stats: &DirectTcpRelayStats,
    execution: &'static str,
) -> Value {
    let mut event = json!({
        "event": "tcp_connection_finished",
        "outbound_kind": "direct",
        "peer": peer.to_string(),
        "original_dst": original_dst.to_string(),
        "dial_target": &selection.route.dial_target,
        "dial_ip": selection.route.dial_ip,
        "initial_outbound": selection.route.initial_outbound,
        "final_outbound": selection.route.final_outbound,
        "final_mark": selection.route.final_mark,
        "userspace_route_executed": selection.route.userspace_route_executed,
        "userspace_route_must": selection.route.userspace_route_must,
        "sniffed_domain": &sniff.domain,
        "sniff_error": &sniff.error,
        "direct_target": direct_target.to_string(),
        "direct_peer_addr": &direct_report.peer_addr,
        "direct_local_addr": &direct_report.local_addr,
        "direct_so_mark": direct_report.so_mark,
        "direct_so_mark_applied": direct_report.so_mark_applied,
        "direct_mptcp_requested": direct_report.requested_mptcp,
        "direct_mptcp_socket_attempted": direct_report.mptcp_socket_attempted,
        "direct_mptcp_socket_created": direct_report.mptcp_socket_created,
        "direct_mptcp_connect_fallback_used": direct_report.mptcp_connect_fallback_used,
        "bytes_client_to_direct": stats.client_to_direct,
        "bytes_direct_to_client": stats.direct_to_client,
    });
    append_tcp_execution_fields(&mut event, execution);
    append_tcp_route_log_fields(&mut event, &selection.route, "direct", "fixed", "direct");
    event
}

fn append_tcp_route_log_fields(
    event: &mut Value,
    route: &TcpRouteSelection,
    outbound: &str,
    policy: &str,
    dialer: &str,
) {
    event["network"] = json!("tcp4");
    event["outbound"] = json!(outbound);
    event["policy"] = json!(policy);
    event["dialer"] = json!(dialer);
    event["sniffed"] = event["sniffed_domain"].clone();
    event["ip"] = event["original_dst"].clone();
    event["pid"] = json!(route.log_metadata.pid);
    event["dscp"] = json!(route.log_metadata.dscp);
    event["pname"] = json!(&route.log_metadata.pname);
    event["mac"] = json!(&route.log_metadata.mac);
}

fn sniff_initial_tcp_payload(
    inbound: &mut TcpStream,
    timeout: Duration,
) -> Result<TcpSniffReport, String> {
    if timeout.is_zero() {
        return Ok(TcpSniffReport {
            payload: Vec::new(),
            domain: String::new(),
            error: None,
        });
    }

    let started = Instant::now();
    let mut payload = Vec::new();
    let mut buf = [0_u8; 4096];
    let mut last_error = None;
    loop {
        loop {
            match inbound.read(&mut buf) {
                Ok(0) => {
                    return Ok(TcpSniffReport {
                        payload,
                        domain: String::new(),
                        error: last_error,
                    });
                }
                Ok(read) => {
                    payload.extend_from_slice(&buf[..read]);
                    if payload.len() > TCP_SNIFF_BUFFER_LIMIT {
                        return Ok(TcpSniffReport {
                            payload,
                            domain: String::new(),
                            error: Some(format!(
                                "sniffing skipped after buffered payload exceeded {TCP_SNIFF_BUFFER_LIMIT} bytes"
                            )),
                        });
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(format!("read inbound TCP for sniffing: {err}")),
            }
        }

        if !payload.is_empty() {
            match sniff_tcp(&payload) {
                Ok(domain) => {
                    return Ok(TcpSniffReport {
                        payload,
                        domain,
                        error: None,
                    });
                }
                Err(err) if sniff_needs_more(&err) && started.elapsed() < timeout => {
                    last_error = Some(err.to_string());
                }
                Err(err) => {
                    return Ok(TcpSniffReport {
                        payload,
                        domain: String::new(),
                        error: Some(err.to_string()),
                    });
                }
            }
        }

        if started.elapsed() >= timeout {
            return Ok(TcpSniffReport {
                payload,
                domain: String::new(),
                error: last_error.or_else(|| Some("sniffing timeout".to_owned())),
            });
        }
        thread::sleep(RESIDENT_IDLE_SLEEP);
    }
}

async fn sniff_initial_tcp_payload_async(
    inbound: &mut TokioTcpStream,
    timeout: Duration,
) -> Result<TcpSniffReport, String> {
    if timeout.is_zero() {
        return Ok(TcpSniffReport {
            payload: Vec::new(),
            domain: String::new(),
            error: None,
        });
    }

    let deadline = time::Instant::now() + timeout;
    let mut payload = Vec::new();
    let mut buf = [0_u8; 4096];
    let mut last_error = None;
    loop {
        let now = time::Instant::now();
        if now >= deadline {
            return Ok(TcpSniffReport {
                payload,
                domain: String::new(),
                error: last_error.or_else(|| Some("sniffing timeout".to_owned())),
            });
        }
        match time::timeout(
            deadline.saturating_duration_since(now),
            inbound.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain: String::new(),
                    error: last_error,
                });
            }
            Ok(Ok(read)) => {
                payload.extend_from_slice(&buf[..read]);
                if payload.len() > TCP_SNIFF_BUFFER_LIMIT {
                    return Ok(TcpSniffReport {
                        payload,
                        domain: String::new(),
                        error: Some(format!(
                            "sniffing skipped after buffered payload exceeded {TCP_SNIFF_BUFFER_LIMIT} bytes"
                        )),
                    });
                }
            }
            Ok(Err(err)) => return Err(format!("read inbound TCP for async sniffing: {err}")),
            Err(_) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain: String::new(),
                    error: last_error.or_else(|| Some("sniffing timeout".to_owned())),
                });
            }
        }

        match sniff_tcp(&payload) {
            Ok(domain) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain,
                    error: None,
                });
            }
            Err(err) if sniff_needs_more(&err) => {
                last_error = Some(err.to_string());
            }
            Err(err) => {
                return Ok(TcpSniffReport {
                    payload,
                    domain: String::new(),
                    error: Some(err.to_string()),
                });
            }
        }
    }
}

fn sniff_needs_more(err: &SniffingError) -> bool {
    matches!(err, SniffingError::NeedMore) || err.to_string().contains("need more")
}

fn process_name(raw: &[u8; 16]) -> Option<String> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    (end > 0).then(|| String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn mac_string(raw: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]
    )
}

fn ipv4_mapped_ip_bytes(addr: Ipv4Addr) -> BpfIpBytes {
    let mut out = [0_u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&addr.octets());
    BpfIpBytes { u6_addr8: out }
}

fn bytes_of<T>(value: &T) -> &[u8] {
    unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

fn bytes_of_mut<T>(value: &mut T) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>()) }
}
