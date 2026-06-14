use serde_json::{Map, Value, json};

use super::execution_types::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeExecutionDescriptor {
    executor: RuntimeExecutorKind,
    capability: RuntimeCapability,
    network: RuntimeNetwork,
    packet_semantics: Option<RuntimePacketSemantics>,
    security_underlay: Option<RuntimeSecurityUnderlay>,
    stream_wrapper: Option<RuntimeStreamWrapper>,
    protocol_framing: Option<String>,
    transport_underlay: Option<RuntimeTransportUnderlay>,
    session_ownership: Option<RuntimeSessionOwnership>,
    route_action: Option<RuntimeRouteAction>,
    graph_id: Option<String>,
}

impl RuntimeExecutionDescriptor {
    fn new(_label: &str, executor: &str, capability: &str, network: &str) -> Self {
        Self {
            executor: RuntimeExecutorKind::from_report_str(executor),
            capability: RuntimeCapability::from_report_str(capability),
            network: RuntimeNetwork::from_report_str(network),
            packet_semantics: None,
            security_underlay: None,
            stream_wrapper: None,
            protocol_framing: None,
            transport_underlay: None,
            session_ownership: None,
            route_action: None,
            graph_id: None,
        }
    }

    pub(super) fn with_packet_semantics(mut self, packet_semantics: &str) -> Self {
        self.packet_semantics = Some(RuntimePacketSemantics::from_report_str(packet_semantics));
        self
    }

    pub(super) fn with_security_underlay(mut self, security_underlay: &str) -> Self {
        self.security_underlay = Some(RuntimeSecurityUnderlay::from_report_str(security_underlay));
        self
    }

    pub(super) fn with_stream_wrapper(mut self, stream_wrapper: &str) -> Self {
        self.stream_wrapper = Some(RuntimeStreamWrapper::from_report_str(stream_wrapper));
        self
    }

    pub(super) fn with_protocol_framing(mut self, protocol_framing: &str) -> Self {
        if !protocol_framing.is_empty() {
            self.protocol_framing = Some(protocol_framing.to_owned());
        }
        self
    }

    pub(super) fn with_transport_underlay(mut self, transport_underlay: &str) -> Self {
        self.transport_underlay = Some(RuntimeTransportUnderlay::from_report_str(
            transport_underlay,
        ));
        self
    }

    pub(super) fn with_session_ownership(mut self, session_ownership: &str) -> Self {
        self.session_ownership = Some(RuntimeSessionOwnership::from_report_str(session_ownership));
        self
    }

    fn with_route_action(mut self, route_action: &str) -> Self {
        self.route_action = Some(RuntimeRouteAction::from_report_str(route_action));
        self
    }

    pub(super) fn with_graph_id(mut self, graph_id: &str) -> Self {
        if !graph_id.is_empty() {
            self.graph_id = Some(graph_id.to_owned());
        }
        self
    }

    pub(super) fn to_value(&self) -> Value {
        let mut descriptor = Map::new();
        descriptor.insert("schemaVersion".to_owned(), json!(1));
        descriptor.insert("executor".to_owned(), json!(self.executor.as_report_str()));
        descriptor.insert(
            "capability".to_owned(),
            json!(self.capability.as_report_str()),
        );
        descriptor.insert("network".to_owned(), json!(self.network.as_report_str()));
        if let Some(packet_semantics) = &self.packet_semantics {
            descriptor.insert(
                "packetSemantics".to_owned(),
                json!(packet_semantics.as_report_str()),
            );
        }
        if let Some(security_underlay) = &self.security_underlay {
            descriptor.insert(
                "securityUnderlay".to_owned(),
                json!(security_underlay.as_report_str()),
            );
        }
        if let Some(stream_wrapper) = &self.stream_wrapper {
            descriptor.insert(
                "streamWrapper".to_owned(),
                json!(stream_wrapper.as_report_str()),
            );
        }
        if let Some(protocol_framing) = &self.protocol_framing {
            descriptor.insert("protocolFraming".to_owned(), json!(protocol_framing));
        }
        if let Some(transport_underlay) = &self.transport_underlay {
            descriptor.insert(
                "transportUnderlay".to_owned(),
                json!(transport_underlay.as_report_str()),
            );
        }
        if let Some(session_ownership) = &self.session_ownership {
            descriptor.insert(
                "sessionOwnership".to_owned(),
                json!(session_ownership.as_report_str()),
            );
        }
        if let Some(route_action) = &self.route_action {
            descriptor.insert(
                "routeAction".to_owned(),
                json!(route_action.as_report_str()),
            );
        }
        if let Some(graph_id) = &self.graph_id {
            descriptor.insert("graphId".to_owned(), json!(graph_id));
        }
        Value::Object(descriptor)
    }
}

pub(super) fn append_runtime_execution_descriptor(
    event: &mut Value,
    descriptor: RuntimeExecutionDescriptor,
) {
    event["executionDescriptor"] = descriptor.to_value();
}

pub(super) fn tcp_execution_descriptor(label: &str) -> RuntimeExecutionDescriptor {
    match TcpExecutionLabel::from_report_str(label) {
        TcpExecutionLabel::AsyncAcceptDirect => {
            RuntimeExecutionDescriptor::new(label, "tcp-listener", "stream-ingress", "tcp")
                .with_route_action("accept")
        }
        TcpExecutionLabel::AsyncBlock => {
            RuntimeExecutionDescriptor::new(label, "route-block", "traffic-block", "tcp")
                .with_route_action("block")
        }
        TcpExecutionLabel::AsyncDirect => {
            RuntimeExecutionDescriptor::new(label, "direct-connect", "direct-stream", "tcp")
                .with_transport_underlay("tcp")
                .with_route_action("direct")
        }
        TcpExecutionLabel::AsyncProxyTls => {
            RuntimeExecutionDescriptor::new(label, "tcp-relay", "stream-transport", "tcp")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        TcpExecutionLabel::AsyncMuxTls => {
            RuntimeExecutionDescriptor::new(label, "tcp-relay", "stream-transport", "tcp")
                .with_packet_semantics("multiplexed-stream")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        TcpExecutionLabel::AsyncProxyWebSocketTls => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("websocket")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncProxyHttpUpgradeTls => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("httpupgrade")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncProxyGrpcTls => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("grpc")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncProxyMeekTls => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("meek")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncProxyXhttpH1Tls => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("xhttp")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncProxyXhttpH2Tls => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("xhttp")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncProxyXhttpH3Tls => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("xhttp")
        .with_transport_underlay("quinn-h3")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncProxyFrameTls => {
            RuntimeExecutionDescriptor::new(label, "frame-stream-relay", "stream-transport", "tcp")
                .with_stream_wrapper("frame-stream")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        TcpExecutionLabel::AsyncProxyQuicTcp => RuntimeExecutionDescriptor::new(
            label,
            "tcp-over-quic-stream",
            "stream-transport",
            "tcp",
        )
        .with_transport_underlay("quic")
        .with_route_action("proxy"),
        TcpExecutionLabel::AsyncSecureEndpointConnect => RuntimeExecutionDescriptor::new(
            label,
            "secure-endpoint-connect",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("protocol-closed")
        .with_security_underlay("standard-tls")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::PlainTcpRelay => {
            RuntimeExecutionDescriptor::new(label, "tcp-relay", "stream-transport", "tcp")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        TcpExecutionLabel::AeadTcpRelay => {
            RuntimeExecutionDescriptor::new(label, "aead-tcp-relay", "stream-transport", "tcp")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        TcpExecutionLabel::Shadowsocks2022Tcp => {
            RuntimeExecutionDescriptor::new(label, "aead-2022-tcp-relay", "stream-transport", "tcp")
                .with_security_underlay("aead-2022")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        TcpExecutionLabel::WrappedWebSocketAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("websocket")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::WrappedHttpUpgradeAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("httpupgrade")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::WrappedSecureWebSocketAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("websocket")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::WrappedSecureHttpUpgradeAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("httpupgrade")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::WrappedGrpcAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("grpc")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::PluginWrapperAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("plugin-wrapper-stream")
        .with_stream_wrapper("plugin-wrapper")
        .with_security_underlay("aead")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::PluginWrapperAead2022 => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("plugin-wrapper-stream")
        .with_stream_wrapper("plugin-wrapper")
        .with_security_underlay("aead-2022")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::PluginWrapperTlsWebSocketAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("plugin-wrapper-stream")
        .with_stream_wrapper("plugin-wrapper")
        .with_security_underlay("standard-tls")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::InnerEncryptionWebSocketAead => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("inner-encryption-stream")
        .with_stream_wrapper("websocket")
        .with_security_underlay("standard-tls")
        .with_transport_underlay("tcp")
        .with_route_action("proxy"),
        TcpExecutionLabel::Unknown => {
            RuntimeExecutionDescriptor::new(label, "runtime-event", "runtime-evidence", "tcp")
                .with_route_action("evidence")
        }
    }
}

pub(super) fn udp_execution_descriptor(label: &str) -> RuntimeExecutionDescriptor {
    match UdpExecutionLabel::from_report_str(label) {
        UdpExecutionLabel::ResidentDnsUdp => {
            RuntimeExecutionDescriptor::new(label, "dns-udp-forward", "dns-packet", "udp")
                .with_packet_semantics("dns")
                .with_route_action("dns")
        }
        UdpExecutionLabel::VlessXudp => {
            RuntimeExecutionDescriptor::new(label, "packet-relay", "packet-transport", "udp")
                .with_packet_semantics("xudp")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::UdpDatagramAead => {
            RuntimeExecutionDescriptor::new(label, "packet-relay", "packet-transport", "udp")
                .with_packet_semantics("datagram-aead")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::UdpDatagramAead2022 => {
            RuntimeExecutionDescriptor::new(label, "packet-relay", "packet-transport", "udp")
                .with_packet_semantics("datagram-aead-2022")
                .with_security_underlay("aead-2022")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::Socks5UdpAssociate => {
            RuntimeExecutionDescriptor::new(label, "udp-associate", "packet-transport", "udp")
                .with_packet_semantics("udp-associate")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::TlsUdpOverTcp | UdpExecutionLabel::AeadUdpOverTcp => {
            RuntimeExecutionDescriptor::new(label, "udp-over-stream", "packet-transport", "udp")
                .with_packet_semantics("udp-over-stream")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::FrameTlsUdpPacketStream => {
            RuntimeExecutionDescriptor::new(label, "packet-stream-relay", "packet-transport", "udp")
                .with_packet_semantics("packet-stream")
                .with_stream_wrapper("frame-stream")
                .with_transport_underlay("tcp")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::QuicUdpDatagram => {
            RuntimeExecutionDescriptor::new(label, "quic-datagram", "packet-transport", "udp")
                .with_packet_semantics("quic-datagram")
                .with_transport_underlay("quic")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::QuicUdpStreamPacket => {
            RuntimeExecutionDescriptor::new(label, "quic-stream-packet", "packet-transport", "udp")
                .with_packet_semantics("stream-packet")
                .with_transport_underlay("quic")
                .with_route_action("proxy")
        }
        UdpExecutionLabel::Unknown => {
            RuntimeExecutionDescriptor::new(label, "packet-runtime", "packet-evidence", "udp")
                .with_route_action("evidence")
        }
    }
}
