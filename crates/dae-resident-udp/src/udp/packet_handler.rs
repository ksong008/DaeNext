// UDP packet handlers keep transport-specific context and event metrics explicit.
#![allow(clippy::too_many_arguments)]

use super::*;
use serde_json::Value;

#[derive(Clone, Copy)]
enum UdpExchangeSessionScope {
    ManagedSession,
}

impl UdpExchangeSessionScope {
    const fn include_packet_session(self) -> bool {
        matches!(self, Self::ManagedSession)
    }
}

pub fn resident_dns_udp_exchange_result(
    original_dst: SocketAddr,
    response: Vec<u8>,
) -> (ResidentEventKind, UdpExchangeResult) {
    (
        ResidentEventKind::UdpDnsPacketFinished,
        resident_dns_udp_result(original_dst, response),
    )
}

fn resident_dns_udp_result(original_dst: SocketAddr, response: Vec<u8>) -> UdpExchangeResult {
    UdpExchangeResult::new(response, "resident-dns-udp")
        .with_session_executor("tokio-dns-datagram")
        .with_underlay_reuse("not-required-independent-datagram")
        .with_session_bound_response_identity(original_dst, None)
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
    packet_session: &Value,
    exchange: Result<(ResidentEventKind, UdpExchangeResult), String>,
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
        packet_session,
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
    packet_session: &Value,
    exchange: Result<(ResidentEventKind, UdpExchangeResult), String>,
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
        packet_session,
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
    packet_session: &Value,
    exchange: Result<(ResidentEventKind, UdpExchangeResult), String>,
    session_scope: UdpExchangeSessionScope,
) {
    if count_upload {
        metrics.add_upload(request_len);
    }
    match exchange {
        Ok((event_kind, mut response)) => {
            let (response_len, response_validation, forwarded_payload) = if response.reply_forwarded
            {
                let expectation = response.fixed_target_expectation(original_dst);
                let payload = response.take_fixed_target_payload(expectation);
                let response_len = payload.payload_len();
                let validation = payload.validation();
                (response_len, Some(validation), payload.into_payload().ok())
            } else {
                (0, None, None)
            };
            if let Some(validation) = response_validation {
                match validation {
                    UdpFixedTargetValidation::Validated => metrics.udp_response_validated(),
                    UdpFixedTargetValidation::CompatibilityUnverified => {
                        metrics.udp_response_compatibility_unverified()
                    }
                    UdpFixedTargetValidation::Dropped(_) => {
                        metrics.udp_response_dropped(response_len)
                    }
                }
                response.reply_forwarded = validation.should_forward();
            }
            if let Some(payload) = forwarded_payload {
                if let Err(err) = udp_reply.try_send_detached(original_dst, peer, payload, true) {
                    if err.should_log() {
                        append_event_with_metadata(
                            &event_file,
                            &event_lock,
                            ResidentEventMetadata::new(ResidentEventKind::UdpReplyFailed),
                            || json!({"event": ResidentEventKind::UdpReplyFailed.name(), "peer": resident_socket_addr_display(peer), "original_dst": resident_socket_addr_display(original_dst), "error": err.to_string()}),
                        );
                    }
                    return;
                }
                metrics.add_download(response_len);
            }
            append_event_with_metadata(
                &event_file,
                &event_lock,
                ResidentEventMetadata::new(event_kind).with_route_log_context(),
                || {
                    let handler = resident_udp_proxy_handler_name(proxy);
                    let network = udp_network_name(original_dst);
                    let mut event_json = udp_exchange_base_event(
                        event_kind.name(),
                        proxy,
                        peer,
                        original_dst,
                        handler,
                        network,
                        true,
                        session_scope,
                        packet_session,
                    );
                    if let Some(map) = event_json.as_object_mut() {
                        map.insert("request_len".to_owned(), Value::from(request_len));
                        map.insert("response_len".to_owned(), Value::from(response_len));
                        map.insert(
                            "reply_forwarded".to_owned(),
                            Value::from(response.reply_forwarded),
                        );
                        if let Some(validation) = response_validation {
                            map.insert(
                                "response_identity_validation".to_owned(),
                                Value::from(validation.label()),
                            );
                            if let Some(reason) = validation.drop_reason() {
                                map.insert(
                                    "response_drop_reason".to_owned(),
                                    Value::from(reason.label()),
                                );
                            }
                        }
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
                    event_json
                },
            )
        }
        Err(err) => append_event_with_metadata(
            &event_file,
            &event_lock,
            ResidentEventMetadata::new(ResidentEventKind::UdpExchangeFailed),
            || {
                let handler = resident_udp_proxy_handler_name(proxy);
                let network = udp_network_name(original_dst);
                let mut event_json = udp_exchange_base_event(
                    "udp_exchange_failed",
                    proxy,
                    peer,
                    original_dst,
                    handler,
                    network,
                    false,
                    session_scope,
                    packet_session,
                );
                if let Some(map) = event_json.as_object_mut() {
                    map.insert("error".to_owned(), Value::String(err));
                    if let Some(dscp) = dscp {
                        map.insert("dscp".to_owned(), Value::from(dscp));
                    }
                }
                event_json
            },
        ),
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
    network: &'static str,
    include_sniffed: bool,
    session_scope: UdpExchangeSessionScope,
    packet_session: &Value,
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
        map.insert("packetSession".to_owned(), packet_session.clone());
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UDP_SESSION_OWNERSHIP_MANAGER_OWNED: &str = "manager-owned";
    const UDP_SESSION_OWNERSHIP_INDEPENDENT_DATAGRAM: &str = "independent-datagram";

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
