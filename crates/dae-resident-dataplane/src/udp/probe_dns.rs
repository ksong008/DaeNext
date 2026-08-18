use super::*;
use std::net::{IpAddr, Ipv4Addr};

use crate::ProxyDnsRequestContext;
use dae_resident_transport::encode_dns_qname;

const RESIDENT_PROXY_UDP_BRIDGE_PACKET_CAPACITY: usize = 64 * 1024;

mod shutdown;
#[cfg(test)]
mod test_observation;
#[cfg(test)]
pub(crate) use self::test_observation::ResidentProxyUdpBridgeTestObservation;

pub(crate) struct ResidentProxyUdpBridge {
    local_addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    last_error: Arc<Mutex<Option<String>>>,
}

impl ResidentProxyUdpBridge {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|error| error.clone())
    }

    #[cfg(test)]
    pub(crate) async fn shutdown(mut self) {
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

    #[cfg(test)]
    pub(crate) async fn shutdown_and_join(mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|error| format!("join resident proxy UDP bridge task: {error}"))?;
        }
        Ok(())
    }

    pub(crate) async fn shutdown_and_join_until(
        mut self,
        deadline: time::Instant,
    ) -> Result<ResidentOwnedTaskShutdownCompletion, String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(task) = self.task.take() else {
            return Ok(ResidentOwnedTaskShutdownCompletion::Joined);
        };
        shutdown::join_bridge_task_until(task, deadline).await
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

pub(crate) async fn open_resident_proxy_udp_bridge_async(
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> Result<ResidentProxyUdpBridge, String> {
    let owner_registries = ResidentTransportOwnerRegistries::new(
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
    )
    .with_anytls(anytls_owner_registry);
    #[cfg(test)]
    {
        open_resident_proxy_udp_bridge_inner(
            binding,
            original_dst,
            owner_registries,
            owner_deadline,
            None,
        )
        .await
    }
    #[cfg(not(test))]
    {
        open_resident_proxy_udp_bridge_inner(
            binding,
            original_dst,
            owner_registries,
            owner_deadline,
        )
        .await
    }
}

#[cfg(test)]
pub(crate) async fn open_resident_proxy_udp_bridge_with_test_observation_async(
    proxy: Arc<ResidentProxyPlan>,
    original_dst: SocketAddr,
    observation: Arc<ResidentProxyUdpBridgeTestObservation>,
) -> Result<ResidentProxyUdpBridge, String> {
    let generation = proxy.execution_plan().runtime_generation();
    let binding = if generation.get() == 0 {
        ResidentProxyBinding::control_plane(proxy)
    } else {
        ResidentProxyBinding::resident(proxy, generation)
    }?;
    open_resident_proxy_udp_bridge_inner(
        binding,
        original_dst,
        ResidentTransportOwnerRegistries::default(),
        None,
        Some(observation),
    )
    .await
}

async fn open_resident_proxy_udp_bridge_inner(
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    owner_registries: ResidentTransportOwnerRegistries,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    #[cfg(test)] test_observation: Option<Arc<ResidentProxyUdpBridgeTestObservation>>,
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
    let hysteria2_owner_registry = owner_registries.hysteria2();
    let tuic_owner_registry = owner_registries.tuic();
    let juicity_owner_registry = owner_registries.juicity();
    let anytls_owner_registry = owner_registries.anytls();
    #[cfg(test)]
    let socket_guard = test_observation
        .as_ref()
        .map(ResidentProxyUdpBridgeTestObservation::socket_guard);
    #[cfg(test)]
    let task_guard = test_observation
        .as_ref()
        .map(ResidentProxyUdpBridgeTestObservation::task_guard);
    let task = tokio::spawn(inherit_quic_endpoint_observation(async move {
        #[cfg(test)]
        let _socket_guard = socket_guard;
        #[cfg(test)]
        let _task_guard = task_guard;
        #[cfg(test)]
        resident_proxy_udp_bridge_loop(
            binding,
            original_dst,
            socket,
            shutdown_rx,
            task_error,
            hysteria2_owner_registry,
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
            owner_deadline,
            test_observation,
        )
        .await;
        #[cfg(not(test))]
        resident_proxy_udp_bridge_loop(
            binding,
            original_dst,
            socket,
            shutdown_rx,
            task_error,
            hysteria2_owner_registry,
            tuic_owner_registry,
            juicity_owner_registry,
            anytls_owner_registry,
            owner_deadline,
        )
        .await;
    }));
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

#[allow(clippy::too_many_arguments)]
async fn resident_proxy_udp_bridge_loop(
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    socket: tokio::net::UdpSocket,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    last_error: Arc<Mutex<Option<String>>>,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    #[cfg(test)] test_observation: Option<Arc<ResidentProxyUdpBridgeTestObservation>>,
) {
    let mut executor = UdpSessionExecutor::new_proxy_packet_with_optional_transport_owner(
        binding.clone(),
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
    );
    if let Some(deadline) = owner_deadline {
        executor.set_owner_acquisition_deadline(deadline);
    }
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
                #[cfg(test)]
                let execution = test_observation::observe_execution(
                    test_observation.as_ref(),
                    executor.execute_proxy_packet(&binding, original_dst, &payload),
                ).await;
                #[cfg(not(test))]
                let execution = executor
                    .execute_proxy_packet(&binding, original_dst, &payload)
                    .await;
                match execution {
                    Ok((_, response)) if response.reply_forwarded => {
                        if let Err(err) =
                            send_resident_proxy_udp_bridge_response(
                                &socket,
                                peer,
                                original_dst,
                                response,
                            )
                            .await
                        {
                            record_resident_proxy_udp_bridge_error(&last_error, err);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => record_resident_proxy_udp_bridge_error(&last_error, err),
                }
            }
            response = executor.wait_response(), if last_peer.is_some() => {
                let Some(peer) = last_peer else {
                    continue;
                };
                match response {
                    Ok(Some((_, response))) => {
                        if let Err(err) =
                            send_resident_proxy_udp_bridge_response(
                                &socket,
                                peer,
                                original_dst,
                                response,
                            )
                            .await
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
    expected_source: SocketAddr,
    mut response: UdpExchangeResult,
) -> Result<(), String> {
    let expectation = response.fixed_target_expectation(expected_source);
    let payload = take_udp_response_for_fixed_target(&mut response, expectation)?;
    socket
        .send_to(&payload, peer)
        .await
        .map(|_| ())
        .map_err(|err| format!("send resident proxy UDP bridge response: {err}"))
}

fn record_resident_proxy_udp_bridge_error(last_error: &Arc<Mutex<Option<String>>>, err: String) {
    if let Ok(mut last_error) = last_error.lock() {
        *last_error = Some(err);
    }
}

#[cfg(test)]
#[path = "probe_dns/shutdown_tests.rs"]
mod shutdown_tests;

pub(crate) const RESIDENT_UDP_PROBE_PUBLIC_ERROR: &str =
    "resident UDP probe failed; protected detail redacted";

#[allow(clippy::too_many_arguments)]
pub(crate) async fn probe_resident_proxy_udp_async(
    binding: ResidentProxyBinding,
    original_dst: SocketAddr,
    payload: &[u8],
    include_response_hex: bool,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    anytls_owner_registry: Option<AnyTlsOwnerRegistryHandle>,
) -> serde_json::Value {
    let started = Instant::now();
    let proxy = binding.plan();
    let agreement = binding.execution().udp.agreement();
    let handler = resident_udp_proxy_handler_name(proxy);
    let packet_semantics = agreement.packet_semantics();
    if let Some(reason) = agreement.unsupported_reason() {
        return json!({
            "status": "protocol-closed",
            "ok": true,
            "protocol_closed": true,
            "relay_available": false,
            "negative_path_ready": true,
            "agreement_disposition": agreement.disposition().as_str(),
            "handler": handler,
            "request_len": payload.len(),
            "response_len": 0,
            "payload_match": false,
            "elapsed_ms": started.elapsed().as_millis(),
            "error": reason,
            "graphId": proxy.graph_id,
            "packetSession": udp_probe_packet_session_value(
                proxy,
                original_dst,
                handler,
                packet_semantics,
            ),
        });
    }
    let mut executor = UdpSessionExecutor::new_proxy_packet_with_optional_transport_owner(
        binding.clone(),
        hysteria2_owner_registry,
        tuic_owner_registry,
        juicity_owner_registry,
        anytls_owner_registry,
    );
    let dns = ResidentDnsDispatcher::asis(binding.effective_socket_mark());
    let mut exchange = executor
        .execute(&dns, &binding, original_dst, payload)
        .await
        .map(|(_, response)| response);
    if let Ok(response) = &exchange
        && !response.reply_forwarded
    {
        exchange = wait_for_udp_probe_response(&mut executor).await;
    }
    executor.shutdown().await;
    let exchange = exchange.and_then(|mut response| {
        let expectation = response.fixed_target_expectation(original_dst);
        let payload = take_udp_response_for_fixed_target(&mut response, expectation)?;
        Ok((response, payload))
    });
    match exchange {
        Ok((response, response_payload)) => {
            let payload_match = response_payload == payload;
            let mut report = json!({
                "status": if payload_match { "pass" } else { "fail" },
                "ok": payload_match,
                "protocol_closed": false,
                "relay_available": true,
                "negative_path_ready": false,
                "agreement_disposition": agreement.disposition().as_str(),
                "handler": handler,
                "request_len": payload.len(),
                "response_len": response_payload.len(),
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
            if include_response_hex {
                report["responsePayloadHex"] = json!(udp_probe_hex_encode(&response_payload));
            }
            report
        }
        Err(_) => json!({
            "status": "fail",
            "ok": false,
            "protocol_closed": false,
            "relay_available": false,
            "negative_path_ready": false,
            "agreement_disposition": agreement.disposition().as_str(),
            "handler": handler,
            "request_len": payload.len(),
            "response_len": 0,
            "payload_match": false,
            "elapsed_ms": started.elapsed().as_millis(),
            "graphId": proxy.graph_id,
            "packetSession": udp_probe_packet_session_value(proxy, original_dst, handler, packet_semantics),
            "reasonId": "udp-probe-exchange-failed",
            "error": RESIDENT_UDP_PROBE_PUBLIC_ERROR,
        }),
    }
}

fn udp_probe_hex_encode(payload: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(payload.len() * 2);
    for byte in payload {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn wait_for_udp_probe_response(
    executor: &mut UdpSessionExecutor,
) -> Result<UdpExchangeResult, String> {
    executor
        .wait_response_with_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, "receive UDP probe response")
        .await
        .map(|(_, response)| response)
}

pub(crate) async fn probe_resident_proxy_dns_udp_with_forwarder_async(
    forwarder: Arc<ResidentProxyDnsUdpForwarder>,
    lookup_host: &str,
) -> Result<(), String> {
    let id = fastrand::u16(0..=u16::MAX);
    let query = build_dns_a_query(id, lookup_host)?;
    let response = forwarder
        .exchange_with_context(
            &query,
            ProxyDnsRequestContext::from_timeout(RESIDENT_UDP_RESPONSE_TIMEOUT),
        )
        .await
        .map_err(|error| error.to_string())?;
    dns_a_response_has_answer(id, &response)
}

fn take_udp_response_for_fixed_target(
    response: &mut UdpExchangeResult,
    expectation: UdpFixedTargetExpectation,
) -> Result<Vec<u8>, String> {
    response
        .take_fixed_target_payload(expectation)
        .into_payload()
        .map_err(|reason| {
            format!(
                "drop UDP response that violates fixed-target identity: {}",
                reason.label()
            )
        })
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
