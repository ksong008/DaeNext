#[derive(Debug)]
struct UdpExchangeResult {
    payload: Vec<u8>,
    legacy_execution: &'static str,
    tls_underlay: Option<&'static str>,
    quic_underlay: Option<&'static str>,
}

impl UdpExchangeResult {
    fn new(payload: Vec<u8>, legacy_execution: &'static str) -> Self {
        Self {
            payload,
            legacy_execution,
            tls_underlay: None,
            quic_underlay: None,
        }
    }

    fn with_tls_underlay(mut self, tls_underlay: &'static str) -> Self {
        self.tls_underlay = Some(tls_underlay);
        self
    }

    fn with_quic_underlay(mut self, quic_underlay: &'static str) -> Self {
        self.quic_underlay = Some(quic_underlay);
        self
    }

    fn append_execution_fields(
        &self,
        value: &mut serde_json::Value,
        protocol_framing: &str,
        graph_id: &str,
    ) {
        let mut descriptor = udp_execution_descriptor(self.legacy_execution)
            .with_protocol_framing(protocol_framing)
            .with_graph_id(graph_id);
        if let Some(tls_underlay) = self.tls_underlay {
            descriptor = descriptor.with_security_underlay(tls_underlay);
        }
        if let Some(quic_underlay) = self.quic_underlay {
            descriptor = descriptor.with_transport_underlay(quic_underlay);
        }
        append_runtime_execution_descriptor(value, descriptor);
    }
}

fn handle_udp_packet(
    proxy_group: Arc<ResidentProxyGroupPlan>,
    dns: Arc<ResidentDnsPlan>,
    packet: UdpOriginalDstPacket,
    original_dst: SocketAddrV4,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
) {
    let request_len = packet.payload.len();
    let peer = packet.peer;
    metrics.add_upload(request_len);
    let proxy = match proxy_group.select_proxy_for_udp() {
        Ok(proxy) => proxy,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_exchange_failed",
                    "peer": peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "error": err,
                    "proxy_group": proxy_group.group_name,
                    "group_policy": proxy_group.group_policy_name(),
                    "network": "udp4",
                    "outbound": proxy_group.group_name,
                    "policy": proxy_group.group_policy_name(),
                }),
            );
            return;
        }
    };
    let exchange = if original_dst.port() == 53 {
        handle_resident_dns_udp(&dns, original_dst, &packet.payload).map(|response| {
            (
                "udp_dns_packet_finished",
                UdpExchangeResult::new(response, "resident-dns-udp"),
            )
        })
    } else {
        exchange_proxy_udp(&proxy, original_dst, &packet.payload)
            .map(|response| ("udp_packet_finished", response))
    };
    match exchange {
        Ok((event, response)) => match send_udp_reply(original_dst, peer, &response.payload) {
            Ok(()) => {
                metrics.add_download(response.payload.len());
                let handler = resident_udp_handler_name(&proxy.handler);
                let mut event_json = json!({
                    "event": event,
                    "peer": peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "request_len": request_len,
                    "response_len": response.payload.len(),
                    "proxy_group": proxy.group_name,
                    "group_policy": proxy.group_policy,
                    "node_tag": proxy.node_tag,
                    "network": "udp4",
                    "outbound": proxy.group_name,
                    "policy": proxy.group_policy,
                    "dialer": proxy.node_tag,
                    "sniffed": "",
                    "ip": original_dst.to_string(),
                    "protocol": proxy.protocol,
                    "handler": handler,
                    "graphId": proxy.graph_id,
                    "packetSession": udp_packet_session_value(&proxy, &peer.to_string(), &original_dst.to_string(), handler),
                });
                response.append_execution_fields(&mut event_json, handler, &proxy.graph_id);
                if let Some(tls_underlay) = response.tls_underlay {
                    event_json["tls_underlay"] = json!(tls_underlay);
                }
                if let Some(quic_underlay) = response.quic_underlay {
                    event_json["quic_underlay"] = json!(quic_underlay);
                }
                append_event(&event_file, &event_lock, event_json)
            }
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_reply_failed", "peer": peer.to_string(), "original_dst": original_dst.to_string(), "error": err}),
            ),
        },
        Err(err) => {
            let handler = resident_udp_handler_name(&proxy.handler);
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_exchange_failed",
                    "peer": peer.to_string(),
                    "original_dst": original_dst.to_string(),
                    "error": err,
                    "protocol": proxy.protocol,
                    "handler": handler,
                    "proxy_group": proxy.group_name,
                    "group_policy": proxy.group_policy,
                    "node_tag": proxy.node_tag,
                    "network": "udp4",
                    "outbound": proxy.group_name,
                    "policy": proxy.group_policy,
                    "dialer": proxy.node_tag,
                    "ip": original_dst.to_string(),
                    "graphId": proxy.graph_id,
                    "packetSession": udp_packet_session_value(&proxy, &peer.to_string(), &original_dst.to_string(), handler),
                }),
            )
        }
    }
}
