use super::*;
#[derive(Debug)]
pub(super) struct UdpExchangeResult {
    pub(super) payload: Vec<u8>,
    pub(super) execution_label: &'static str,
    pub(super) tls_underlay: Option<&'static str>,
    pub(super) quic_underlay: Option<&'static str>,
    pub(super) session_executor: Option<&'static str>,
    pub(super) underlay_reuse: Option<&'static str>,
}

impl UdpExchangeResult {
    pub(super) fn new(payload: Vec<u8>, execution_label: &'static str) -> Self {
        Self {
            payload,
            execution_label,
            tls_underlay: None,
            quic_underlay: None,
            session_executor: None,
            underlay_reuse: None,
        }
    }

    pub(super) fn with_tls_underlay(mut self, tls_underlay: &'static str) -> Self {
        self.tls_underlay = Some(tls_underlay);
        self
    }

    pub(super) fn with_quic_underlay(mut self, quic_underlay: &'static str) -> Self {
        self.quic_underlay = Some(quic_underlay);
        self
    }

    pub(super) fn with_session_executor(mut self, session_executor: &'static str) -> Self {
        self.session_executor = Some(session_executor);
        self
    }

    pub(super) fn with_underlay_reuse(mut self, underlay_reuse: &'static str) -> Self {
        self.underlay_reuse = Some(underlay_reuse);
        self
    }

    pub(super) fn append_execution_fields(
        &self,
        value: &mut serde_json::Value,
        protocol_framing: &str,
        graph_id: &str,
    ) {
        let mut descriptor = udp_execution_descriptor(self.execution_label)
            .with_protocol_framing(protocol_framing)
            .with_session_ownership("manager-owned")
            .with_graph_id(graph_id);
        if let Some(tls_underlay) = self.tls_underlay {
            descriptor = descriptor.with_security_underlay(tls_underlay);
        }
        if let Some(quic_underlay) = self.quic_underlay {
            descriptor = descriptor.with_transport_underlay(quic_underlay);
        }
        append_runtime_execution_descriptor(value, descriptor);
    }

    pub(super) fn append_session_fields(&self, value: &mut serde_json::Value) {
        if let Some(session_executor) = self.session_executor {
            value["sessionExecutor"] = json!(session_executor);
        }
        if let Some(underlay_reuse) = self.underlay_reuse {
            value["underlayReuse"] = json!(underlay_reuse);
        }
    }
}

pub(super) fn append_udp_proxy_selection_failed(
    event_file: &PathBuf,
    event_lock: &Arc<Mutex<()>>,
    peer: SocketAddr,
    original_dst: SocketAddr,
    err: String,
    proxy_group: &ResidentProxyGroupPlan,
) {
    let network = udp_network_name(original_dst);
    append_event(
        event_file,
        event_lock,
        json!({
            "event": "udp_exchange_failed",
            "peer": resident_socket_addr_display(peer),
            "original_dst": resident_socket_addr_display(original_dst),
            "error": err,
            "proxy_group": proxy_group.group_name,
            "group_policy": proxy_group.group_policy_name(),
            "network": network,
            "outbound": proxy_group.group_name,
            "policy": proxy_group.group_policy_name(),
        }),
    );
}

pub(super) fn record_udp_exchange_result(
    proxy: ResidentProxyPlan,
    packet: UdpOriginalDstPacket,
    original_dst: SocketAddr,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    exchange: Result<(&'static str, UdpExchangeResult), String>,
) {
    let request_len = packet.payload.len();
    let peer = packet.peer;
    metrics.add_upload(request_len);
    match exchange {
        Ok((event, response)) => match send_udp_reply(original_dst, peer, &response.payload) {
            Ok(()) => {
                metrics.add_download(response.payload.len());
                let handler = resident_udp_handler_name(&proxy.handler);
                let packet_semantics =
                    udp_packet_semantics_for_destination(&proxy.handler, original_dst);
                let network = udp_network_name(original_dst);
                let mut event_json = json!({
                    "event": event,
                    "peer": resident_socket_addr_display(peer),
                    "original_dst": resident_socket_addr_display(original_dst),
                    "request_len": request_len,
                    "response_len": response.payload.len(),
                    "proxy_group": proxy.group_name,
                    "group_policy": proxy.group_policy,
                    "node_tag": proxy.node_tag,
                    "network": network,
                    "outbound": proxy.group_name,
                    "policy": proxy.group_policy,
                    "dialer": proxy.node_tag,
                    "sniffed": "",
                    "ip": resident_socket_addr_display(original_dst),
                    "protocol": proxy.protocol,
                    "handler": handler,
                    "graphId": proxy.graph_id,
                    "packetSession": udp_packet_session_value(&proxy, peer, original_dst, handler, packet_semantics),
                });
                response.append_execution_fields(&mut event_json, handler, &proxy.graph_id);
                if let Some(tls_underlay) = response.tls_underlay {
                    event_json["tls_underlay"] = json!(tls_underlay);
                }
                if let Some(quic_underlay) = response.quic_underlay {
                    event_json["quic_underlay"] = json!(quic_underlay);
                }
                response.append_session_fields(&mut event_json);
                append_event(&event_file, &event_lock, event_json)
            }
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({"event": "udp_reply_failed", "peer": resident_socket_addr_display(peer), "original_dst": resident_socket_addr_display(original_dst), "error": err}),
            ),
        },
        Err(err) => {
            let handler = resident_udp_handler_name(&proxy.handler);
            let packet_semantics =
                udp_packet_semantics_for_destination(&proxy.handler, original_dst);
            let network = udp_network_name(original_dst);
            append_event(
                &event_file,
                &event_lock,
                json!({
                    "event": "udp_exchange_failed",
                    "peer": resident_socket_addr_display(peer),
                    "original_dst": resident_socket_addr_display(original_dst),
                    "error": err,
                    "protocol": proxy.protocol,
                    "handler": handler,
                    "proxy_group": proxy.group_name,
                    "group_policy": proxy.group_policy,
                    "node_tag": proxy.node_tag,
                    "network": network,
                    "outbound": proxy.group_name,
                    "policy": proxy.group_policy,
                    "dialer": proxy.node_tag,
                    "ip": resident_socket_addr_display(original_dst),
                    "graphId": proxy.graph_id,
                    "packetSession": udp_packet_session_value(&proxy, peer, original_dst, handler, packet_semantics),
                }),
            )
        }
    }
}

fn udp_network_name(addr: SocketAddr) -> &'static str {
    resident_udp_network_name(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_exchange_result_uses_structured_session_execution_fields() {
        let mut event = json!({
            "packetSession": {
                "schemaVersion": 1,
                "manager": "resident-udp-session-manager",
                "packetSemantics": "dns",
            },
        });
        let result = UdpExchangeResult::new(Vec::new(), "resident-dns-udp")
            .with_session_executor("tokio-dns-datagram")
            .with_underlay_reuse("not-required-independent-datagram");
        result.append_execution_fields(&mut event, "resident-dns", "resident-graph:test");
        result.append_session_fields(&mut event);

        assert_eq!(event["packetSession"]["schemaVersion"], 1);
        assert_eq!(
            event["packetSession"]["manager"],
            "resident-udp-session-manager"
        );
        assert_eq!(event["packetSession"]["packetSemantics"], "dns");
        assert_eq!(event["executionDescriptor"]["schemaVersion"], 1);
        assert!(
            event["executionDescriptor"]["executor"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            event["executionDescriptor"]["capability"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(event["executionDescriptor"]["network"], "udp");
        assert_eq!(event["executionDescriptor"]["packetSemantics"], "dns");
        assert_eq!(
            event["executionDescriptor"]["sessionOwnership"],
            "manager-owned"
        );
        assert_eq!(
            event["executionDescriptor"]["protocolFraming"],
            "resident-dns"
        );
        assert_eq!(
            event["executionDescriptor"]["graphId"],
            "resident-graph:test"
        );
        assert_eq!(event["sessionExecutor"], "tokio-dns-datagram");
        assert_eq!(event["underlayReuse"], "not-required-independent-datagram");
    }
}
