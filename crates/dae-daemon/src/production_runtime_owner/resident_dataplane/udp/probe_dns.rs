use super::*;
use std::net::{IpAddr, Ipv4Addr};

const RESIDENT_PROXY_UDP_BRIDGE_PACKET_CAPACITY: usize = 64 * 1024;

pub(in crate::production_runtime_owner::resident_dataplane) struct ResidentProxyUdpBridge {
    local_addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    last_error: Arc<Mutex<Option<String>>>,
}

impl ResidentProxyUdpBridge {
    pub(in crate::production_runtime_owner::resident_dataplane) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn last_error(
        &self,
    ) -> Option<String> {
        self.last_error.lock().ok().and_then(|error| error.clone())
    }

    pub(in crate::production_runtime_owner::resident_dataplane) async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut task) = self.task.take() {
            tokio::select! {
                _ = &mut task => {}
                _ = time::sleep(RESIDENT_IDLE_SLEEP) => {
                    task.abort();
                    let _ = task.await;
                }
            }
        }
    }
}

impl Drop for ResidentProxyUdpBridge {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn open_resident_proxy_udp_bridge_async(
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
) -> Result<ResidentProxyUdpBridge, String> {
    let socket = tokio::net::UdpSocket::bind(resident_proxy_udp_bridge_bind_addr())
        .await
        .map_err(|err| format!("bind resident proxy UDP bridge socket: {err}"))?;
    let local_addr = socket
        .local_addr()
        .map_err(|err| format!("read resident proxy UDP bridge local address: {err}"))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let last_error = Arc::new(Mutex::new(None));
    let task_error = Arc::clone(&last_error);
    let task = tokio::spawn(async move {
        resident_proxy_udp_bridge_loop(proxy, original_dst, socket, shutdown_rx, task_error).await;
    });
    Ok(ResidentProxyUdpBridge {
        local_addr,
        shutdown: Some(shutdown_tx),
        task: Some(task),
        last_error,
    })
}

fn resident_proxy_udp_bridge_bind_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

async fn resident_proxy_udp_bridge_loop(
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    socket: tokio::net::UdpSocket,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    last_error: Arc<Mutex<Option<String>>>,
) {
    let mut executor = UdpSessionExecutor::new_proxy_packet(&proxy);
    let mut buf = vec![0_u8; RESIDENT_PROXY_UDP_BRIDGE_PACKET_CAPACITY];
    let mut last_peer = None;
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            received = socket.recv_from(&mut buf) => {
                let (read, peer) = match received {
                    Ok(received) => received,
                    Err(err) => {
                        record_resident_proxy_udp_bridge_error(
                            &last_error,
                            format!("receive resident proxy UDP bridge packet: {err}"),
                        );
                        continue;
                    }
                };
                last_peer = Some(peer);
                let payload = buf[..read].to_vec();
                match executor.execute_proxy_packet(&proxy, original_dst, &payload).await {
                    Ok((_, response)) if response.reply_forwarded => {
                        if let Err(err) =
                            send_resident_proxy_udp_bridge_response(&socket, peer, response).await
                        {
                            record_resident_proxy_udp_bridge_error(&last_error, err);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => record_resident_proxy_udp_bridge_error(&last_error, err),
                }
            }
            _ = time::sleep(RESIDENT_IDLE_SLEEP), if last_peer.is_some() => {
                let Some(peer) = last_peer else {
                    continue;
                };
                match executor.poll_response().await {
                    Ok(Some((_, response))) => {
                        if let Err(err) =
                            send_resident_proxy_udp_bridge_response(&socket, peer, response).await
                        {
                            record_resident_proxy_udp_bridge_error(&last_error, err);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => record_resident_proxy_udp_bridge_error(&last_error, err),
                }
            }
        }
    }
    executor.shutdown().await;
}

async fn send_resident_proxy_udp_bridge_response(
    socket: &tokio::net::UdpSocket,
    peer: SocketAddr,
    response: UdpExchangeResult,
) -> Result<(), String> {
    socket
        .send_to(&response.payload, peer)
        .await
        .map(|_| ())
        .map_err(|err| format!("send resident proxy UDP bridge response: {err}"))
}

fn record_resident_proxy_udp_bridge_error(last_error: &Arc<Mutex<Option<String>>>, err: String) {
    if let Ok(mut last_error) = last_error.lock() {
        *last_error = Some(err);
    }
}

pub(crate) async fn probe_resident_proxy_udp_async(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> serde_json::Value {
    let started = Instant::now();
    let handler = resident_udp_handler_name(&proxy.handler);
    let packet_semantics = udp_packet_semantics_for_destination(proxy, original_dst);
    let mut executor = UdpSessionExecutor::new_proxy_packet(proxy);
    let dns = ResidentDnsPlan::asis(proxy.mark);
    let mut exchange = executor
        .execute(&dns, proxy, original_dst, payload)
        .await
        .map(|(_, response)| response);
    if let Ok(response) = &exchange
        && !response.reply_forwarded
    {
        exchange = wait_for_udp_probe_response(&mut executor).await;
    }
    executor.shutdown().await;
    match exchange {
        Ok(response) => {
            let payload_match = response.payload == payload;
            let mut report = json!({
                "status": if payload_match { "pass" } else { "fail" },
                "ok": payload_match,
                "protocol_closed": false,
                "handler": handler,
                "request_len": payload.len(),
                "response_len": response.payload.len(),
                "payload_match": payload_match,
                "elapsed_ms": started.elapsed().as_millis(),
                "graphId": proxy.graph_id,
                "packetSession": udp_probe_packet_session_value(proxy, original_dst, handler, packet_semantics),
            });
            response.append_execution_fields(&mut report, handler, &proxy.graph_id);
            if let Some(tls_underlay) = response.tls_underlay {
                report["tls_underlay"] = json!(tls_underlay);
            }
            if let Some(quic_underlay) = response.quic_underlay {
                report["quic_underlay"] = json!(quic_underlay);
            }
            report
        }
        Err(err)
            if matches!(
                proxy.handler,
                ResidentProxyProtocolPlan::HttpProxyTcp { .. }
            ) =>
        {
            json!({
                "status": "protocol-closed",
                "ok": true,
                "protocol_closed": true,
                "handler": handler,
                "request_len": payload.len(),
                "response_len": 0,
                "payload_match": false,
                "elapsed_ms": started.elapsed().as_millis(),
                "error": err,
                "graphId": proxy.graph_id,
                "packetSession": udp_probe_packet_session_value(proxy, original_dst, handler, packet_semantics),
            })
        }
        Err(err) => json!({
            "status": "fail",
            "ok": false,
            "protocol_closed": false,
            "handler": handler,
            "request_len": payload.len(),
            "response_len": 0,
            "payload_match": false,
            "elapsed_ms": started.elapsed().as_millis(),
            "graphId": proxy.graph_id,
            "packetSession": udp_probe_packet_session_value(proxy, original_dst, handler, packet_semantics),
            "error": err,
        }),
    }
}

async fn wait_for_udp_probe_response(
    executor: &mut UdpSessionExecutor,
) -> Result<UdpExchangeResult, String> {
    let started = Instant::now();
    loop {
        if let Some((_, response)) = executor.poll_response().await? {
            return Ok(response);
        }
        if started.elapsed() >= RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err("receive UDP probe response timeout".to_owned());
        }
        time::sleep(RESIDENT_IDLE_SLEEP).await;
    }
}

pub(crate) async fn probe_resident_proxy_dns_udp_async(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    lookup_host: &str,
) -> Result<(), String> {
    let id = fastrand::u16(0..=u16::MAX);
    let query = build_dns_a_query(id, lookup_host)?;
    let mut executor = UdpSessionExecutor::new_proxy_packet(proxy);
    let dns = ResidentDnsPlan::asis(proxy.mark);
    let (_, response) = executor.execute(&dns, proxy, original_dst, &query).await?;
    executor.shutdown().await;
    dns_a_response_has_answer(id, &response.payload)
}

pub(in crate::production_runtime_owner::resident_dataplane) async fn forward_resident_proxy_dns_udp_async(
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut executor = UdpSessionExecutor::new_proxy_packet(&proxy);
    let exchange = execute_forced_dns_proxy_payload(&mut executor, &proxy, original_dst, payload)
        .await
        .map(|(_, response)| response.payload);
    executor.shutdown().await;
    exchange
}

async fn execute_forced_dns_proxy_payload(
    executor: &mut UdpSessionExecutor,
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    payload: &[u8],
) -> Result<(&'static str, UdpExchangeResult), String> {
    let (event, response) = executor
        .execute_proxy_packet(proxy, original_dst, payload)
        .await?;
    if response.reply_forwarded {
        return Ok((event, response.into_independent_datagram()));
    }
    let started = Instant::now();
    loop {
        if started.elapsed() >= RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err("receive proxied DNS UDP response timeout".to_owned());
        }
        match executor.poll_response().await? {
            Some((event, response)) => return Ok((event, response.into_independent_datagram())),
            None => time::sleep(RESIDENT_IDLE_SLEEP).await,
        }
    }
}

pub(crate) fn build_dns_a_query(id: u16, lookup_host: &str) -> Result<Vec<u8>, String> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_qname(&mut query, lookup_host)?;
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

pub(crate) fn encode_dns_qname(out: &mut Vec<u8>, lookup_host: &str) -> Result<(), String> {
    let lookup_host = lookup_host.trim_end_matches('.');
    if lookup_host.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in lookup_host.split('.') {
        if label.is_empty() {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: empty label"
            ));
        }
        if label.len() > 63 {
            return Err(format!(
                "invalid DNS lookup host {lookup_host}: label exceeds 63 bytes"
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

pub(crate) fn dns_a_response_has_answer(query_id: u16, response: &[u8]) -> Result<(), String> {
    if response.len() < 12 {
        return Err(format!("DNS response too short: {} bytes", response.len()));
    }
    let response_id = u16::from_be_bytes([response[0], response[1]]);
    if response_id != query_id {
        return Err(format!(
            "DNS response id mismatch: got {response_id}, expected {query_id}"
        ));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS response is not a response packet".to_owned());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("DNS response rcode={rcode}"));
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Err("DNS response has no answer records".to_owned());
    }
    let mut offset = 12_usize;
    for _ in 0..qdcount {
        skip_dns_name(response, &mut offset)?;
        if response.len().saturating_sub(offset) < 4 {
            return Err("DNS response question section truncated".to_owned());
        }
        offset += 4;
    }
    for _ in 0..ancount {
        skip_dns_name(response, &mut offset)?;
        if response.len().saturating_sub(offset) < 10 {
            return Err("DNS response answer section truncated".to_owned());
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if response.len().saturating_sub(offset) < rdlen {
            return Err("DNS response answer data truncated".to_owned());
        }
        if record_type == 1 && class == 1 && rdlen == 4 {
            return Ok(());
        }
        offset += rdlen;
    }
    Err("DNS response has no A answer records".to_owned())
}

pub(crate) fn skip_dns_name(packet: &[u8], offset: &mut usize) -> Result<(), String> {
    let mut jumps = 0_usize;
    loop {
        if *offset >= packet.len() {
            return Err("DNS name truncated".to_owned());
        }
        let len = packet[*offset];
        if len & 0xc0 == 0xc0 {
            if packet.len().saturating_sub(*offset) < 2 {
                return Err("DNS compressed name pointer truncated".to_owned());
            }
            *offset += 2;
            return Ok(());
        }
        if len & 0xc0 != 0 {
            return Err(format!("unsupported DNS name label marker: 0x{len:02x}"));
        }
        *offset += 1;
        if len == 0 {
            return Ok(());
        }
        let len = len as usize;
        if packet.len().saturating_sub(*offset) < len {
            return Err("DNS name label truncated".to_owned());
        }
        *offset += len;
        jumps += 1;
        if jumps > 128 {
            return Err("DNS name too deep".to_owned());
        }
    }
}
