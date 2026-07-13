// UDP packet handlers keep transport-specific context and event metrics explicit.
#![allow(clippy::too_many_arguments)]

use super::*;
use serde_json::Value;
#[derive(Debug)]
pub(super) struct UdpExchangeResult {
    pub(super) payload: Vec<u8>,
    pub(super) execution_label: &'static str,
    pub(super) tls_underlay: Option<&'static str>,
    pub(super) quic_underlay: Option<&'static str>,
    pub(super) session_executor: Option<&'static str>,
    pub(super) underlay_reuse: Option<&'static str>,
    pub(super) session_ownership: &'static str,
    pub(super) reply_forwarded: bool,
}

const UDP_SESSION_OWNERSHIP_MANAGER_OWNED: &str = "manager-owned";
const UDP_SESSION_OWNERSHIP_INDEPENDENT_DATAGRAM: &str = "independent-datagram";

impl UdpExchangeResult {
    pub(super) fn new(payload: Vec<u8>, execution_label: &'static str) -> Self {
        Self {
            payload,
            execution_label,
            tls_underlay: None,
            quic_underlay: None,
            session_executor: None,
            underlay_reuse: None,
            session_ownership: UDP_SESSION_OWNERSHIP_MANAGER_OWNED,
            reply_forwarded: true,
        }
    }

    pub(super) fn pending_response(execution_label: &'static str) -> Self {
        Self {
            payload: Vec::new(),
            execution_label,
            tls_underlay: None,
            quic_underlay: None,
            session_executor: None,
            underlay_reuse: None,
            session_ownership: UDP_SESSION_OWNERSHIP_MANAGER_OWNED,
            reply_forwarded: false,
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

    pub(super) fn with_session_ownership(mut self, session_ownership: &'static str) -> Self {
        self.session_ownership = session_ownership;
        self
    }

    pub(super) fn into_independent_datagram(self) -> Self {
        self.with_session_ownership(UDP_SESSION_OWNERSHIP_INDEPENDENT_DATAGRAM)
    }

    pub(super) fn append_execution_fields(
        &self,
        value: &mut serde_json::Value,
        protocol_framing: &str,
        graph_id: &str,
    ) {
        let mut descriptor = udp_execution_descriptor(self.execution_label)
            .with_protocol_framing(protocol_framing)
            .with_session_ownership(self.session_ownership)
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

#[derive(Clone, Copy)]
enum UdpExchangeSessionScope {
    ManagedSession,
}

impl UdpExchangeSessionScope {
    const fn include_packet_session(self) -> bool {
        matches!(self, Self::ManagedSession)
    }
}

pub(super) fn resident_dns_udp_exchange_result(
    response: Vec<u8>,
) -> (&'static str, UdpExchangeResult) {
    ("udp_dns_packet_finished", resident_dns_udp_result(response))
}

fn resident_dns_udp_result(response: Vec<u8>) -> UdpExchangeResult {
    UdpExchangeResult::new(response, "resident-dns-udp")
        .with_session_executor("tokio-dns-datagram")
        .with_underlay_reuse("not-required-independent-datagram")
}

pub(super) async fn record_udp_exchange_result(
    proxy: &ResidentProxyPlan,
    packet: UdpOriginalDstPacket,
    original_dst: SocketAddr,
    dscp: u8,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_reply: &UdpReplyHandle,
    exchange: Result<(&'static str, UdpExchangeResult), String>,
) {
    record_udp_session_exchange_result(
        proxy,
        packet.peer,
        original_dst,
        packet.payload.len(),
        true,
        Some(dscp),
        event_file,
        event_lock,
        metrics,
        udp_reply,
        exchange,
        UdpExchangeSessionScope::ManagedSession,
    )
    .await;
}

pub(super) async fn record_udp_session_response_result(
    proxy: &ResidentProxyPlan,
    peer: SocketAddr,
    original_dst: SocketAddr,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_reply: &UdpReplyHandle,
    exchange: Result<(&'static str, UdpExchangeResult), String>,
) {
    record_udp_session_exchange_result(
        proxy,
        peer,
        original_dst,
        0,
        false,
        None,
        event_file,
        event_lock,
        metrics,
        udp_reply,
        exchange,
        UdpExchangeSessionScope::ManagedSession,
    )
    .await;
}

async fn record_udp_session_exchange_result(
    proxy: &ResidentProxyPlan,
    peer: SocketAddr,
    original_dst: SocketAddr,
    request_len: usize,
    count_upload: bool,
    dscp: Option<u8>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    udp_reply: &UdpReplyHandle,
    exchange: Result<(&'static str, UdpExchangeResult), String>,
    session_scope: UdpExchangeSessionScope,
) {
    if count_upload {
        metrics.add_upload(request_len);
    }
    match exchange {
        Ok((event, mut response)) => {
            let response_len = response.payload.len();
            if response.reply_forwarded {
                if let Err(err) = udp_reply
                    .send(original_dst, peer, std::mem::take(&mut response.payload))
                    .await
                {
                    if err.should_log() {
                        append_event(
                            &event_file,
                            &event_lock,
                            json!({"event": "udp_reply_failed", "peer": resident_socket_addr_display(peer), "original_dst": resident_socket_addr_display(original_dst), "error": err.to_string()}),
                        );
                    }
                    return;
                }
                metrics.add_download(response_len);
            }
            let handler = resident_udp_proxy_handler_name(proxy);
            let packet_semantics = udp_packet_semantics_for_destination(proxy, original_dst);
            let network = udp_network_name(original_dst);
            let mut event_json = udp_exchange_base_event(
                event,
                proxy,
                peer,
                original_dst,
                handler,
                packet_semantics,
                network,
                true,
                session_scope,
            );
            if let Some(map) = event_json.as_object_mut() {
                map.insert("request_len".to_owned(), Value::from(request_len));
                map.insert("response_len".to_owned(), Value::from(response_len));
                map.insert(
                    "reply_forwarded".to_owned(),
                    Value::from(response.reply_forwarded),
                );
                if let Some(dscp) = dscp {
                    map.insert("dscp".to_owned(), Value::from(dscp));
                }
            }
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
        Err(err) => {
            let handler = resident_udp_proxy_handler_name(proxy);
            let packet_semantics = udp_packet_semantics_for_destination(proxy, original_dst);
            let network = udp_network_name(original_dst);
            let mut event_json = udp_exchange_base_event(
                "udp_exchange_failed",
                proxy,
                peer,
                original_dst,
                handler,
                packet_semantics,
                network,
                false,
                session_scope,
            );
            if let Some(map) = event_json.as_object_mut() {
                map.insert("error".to_owned(), Value::String(err));
                if let Some(dscp) = dscp {
                    map.insert("dscp".to_owned(), Value::from(dscp));
                }
            }
            append_event(&event_file, &event_lock, event_json)
        }
    }
}

fn udp_network_name(addr: SocketAddr) -> &'static str {
    resident_udp_network_name(addr)
}

fn udp_exchange_base_event(
    event: &str,
    proxy: &ResidentProxyPlan,
    peer: SocketAddr,
    original_dst: SocketAddr,
    handler: &'static str,
    packet_semantics: UdpPacketSemantics,
    network: &'static str,
    include_sniffed: bool,
    session_scope: UdpExchangeSessionScope,
) -> Value {
    let mut map = serde_json::Map::with_capacity(18);
    map.insert("event".to_owned(), Value::String(event.to_owned()));
    map.insert(
        "peer".to_owned(),
        Value::String(resident_socket_addr_display(peer)),
    );
    map.insert(
        "original_dst".to_owned(),
        Value::String(resident_socket_addr_display(original_dst)),
    );
    map.insert(
        "proxy_group".to_owned(),
        Value::String(proxy.group_name.clone()),
    );
    map.insert(
        "group_policy".to_owned(),
        Value::String(proxy.group_policy.clone()),
    );
    map.insert("node_tag".to_owned(), Value::String(proxy.node_tag.clone()));
    map.insert("network".to_owned(), Value::String(network.to_owned()));
    map.insert(
        "outbound".to_owned(),
        Value::String(proxy.group_name.clone()),
    );
    map.insert(
        "policy".to_owned(),
        Value::String(proxy.group_policy.clone()),
    );
    map.insert("dialer".to_owned(), Value::String(proxy.node_tag.clone()));
    if include_sniffed {
        map.insert("sniffed".to_owned(), Value::String(String::new()));
    }
    map.insert(
        "ip".to_owned(),
        Value::String(resident_socket_addr_display(original_dst)),
    );
    map.insert(
        "protocol".to_owned(),
        Value::String(proxy.protocol.to_owned()),
    );
    map.insert("handler".to_owned(), Value::String(handler.to_owned()));
    map.insert("graphId".to_owned(), Value::String(proxy.graph_id.clone()));
    if session_scope.include_packet_session() {
        map.insert(
            "packetSession".to_owned(),
            udp_packet_session_value(proxy, peer, original_dst, handler, packet_semantics),
        );
    }
    Value::Object(map)
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
            UDP_SESSION_OWNERSHIP_MANAGER_OWNED
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

    #[test]
    fn udp_exchange_result_can_report_independent_datagram_ownership() {
        let mut event = json!({});
        let result = UdpExchangeResult::new(Vec::new(), "resident-dns-udp")
            .with_session_ownership(UDP_SESSION_OWNERSHIP_INDEPENDENT_DATAGRAM);
        result.append_execution_fields(&mut event, "resident-dns", "resident-graph:test");

        assert_eq!(
            event["executionDescriptor"]["sessionOwnership"],
            UDP_SESSION_OWNERSHIP_INDEPENDENT_DATAGRAM
        );
    }
}
