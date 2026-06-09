use serde_json::{Map, Value, json};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RuntimeExecutionDescriptor {
    executor: String,
    capability: String,
    network: String,
    packet_semantics: Option<String>,
    security_underlay: Option<String>,
    stream_wrapper: Option<String>,
    protocol_framing: Option<String>,
    transport_underlay: Option<String>,
    session_ownership: Option<String>,
    graph_id: Option<String>,
}

impl RuntimeExecutionDescriptor {
    fn new(_label: &str, executor: &str, capability: &str, network: &str) -> Self {
        Self {
            executor: executor.to_owned(),
            capability: capability.to_owned(),
            network: network.to_owned(),
            packet_semantics: None,
            security_underlay: None,
            stream_wrapper: None,
            protocol_framing: None,
            transport_underlay: None,
            session_ownership: None,
            graph_id: None,
        }
    }

    pub(super) fn with_packet_semantics(mut self, packet_semantics: &str) -> Self {
        self.packet_semantics = Some(packet_semantics.to_owned());
        self
    }

    pub(super) fn with_security_underlay(mut self, security_underlay: &str) -> Self {
        self.security_underlay = Some(security_underlay.to_owned());
        self
    }

    pub(super) fn with_stream_wrapper(mut self, stream_wrapper: &str) -> Self {
        self.stream_wrapper = Some(stream_wrapper.to_owned());
        self
    }

    pub(super) fn with_protocol_framing(mut self, protocol_framing: &str) -> Self {
        if !protocol_framing.is_empty() {
            self.protocol_framing = Some(protocol_framing.to_owned());
        }
        self
    }

    pub(super) fn with_transport_underlay(mut self, transport_underlay: &str) -> Self {
        self.transport_underlay = Some(transport_underlay.to_owned());
        self
    }

    pub(super) fn with_session_ownership(mut self, session_ownership: &str) -> Self {
        self.session_ownership = Some(session_ownership.to_owned());
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
        descriptor.insert("executor".to_owned(), json!(self.executor));
        descriptor.insert("capability".to_owned(), json!(self.capability));
        descriptor.insert("network".to_owned(), json!(self.network));
        if let Some(packet_semantics) = &self.packet_semantics {
            descriptor.insert("packetSemantics".to_owned(), json!(packet_semantics));
        }
        if let Some(security_underlay) = &self.security_underlay {
            descriptor.insert("securityUnderlay".to_owned(), json!(security_underlay));
        }
        if let Some(stream_wrapper) = &self.stream_wrapper {
            descriptor.insert("streamWrapper".to_owned(), json!(stream_wrapper));
        }
        if let Some(protocol_framing) = &self.protocol_framing {
            descriptor.insert("protocolFraming".to_owned(), json!(protocol_framing));
        }
        if let Some(transport_underlay) = &self.transport_underlay {
            descriptor.insert("transportUnderlay".to_owned(), json!(transport_underlay));
        }
        if let Some(session_ownership) = &self.session_ownership {
            descriptor.insert("sessionOwnership".to_owned(), json!(session_ownership));
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
    match label {
        "async-accept-direct" => {
            RuntimeExecutionDescriptor::new(label, "tcp-listener", "stream-ingress", "tcp")
        }
        "async-block" => {
            RuntimeExecutionDescriptor::new(label, "route-block", "traffic-block", "tcp")
        }
        "async-direct" => {
            RuntimeExecutionDescriptor::new(label, "direct-connect", "direct-stream", "tcp")
                .with_transport_underlay("tcp")
        }
        "async-proxy-tls" => {
            RuntimeExecutionDescriptor::new(label, "tcp-relay", "stream-transport", "tcp")
                .with_transport_underlay("tcp")
        }
        "async-proxy-websocket-tls" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("websocket")
        .with_transport_underlay("tcp"),
        "async-proxy-httpupgrade-tls" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("httpupgrade")
        .with_transport_underlay("tcp"),
        "async-proxy-grpc-tls" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("grpc")
        .with_transport_underlay("tcp"),
        "async-proxy-meek-tls" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("meek")
        .with_transport_underlay("tcp"),
        "async-proxy-xhttp-h2-tls" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("xhttp")
        .with_transport_underlay("tcp"),
        "async-proxy-frame-tls" => {
            RuntimeExecutionDescriptor::new(label, "frame-stream-relay", "stream-transport", "tcp")
                .with_stream_wrapper("frame-stream")
                .with_transport_underlay("tcp")
        }
        "async-proxy-quic-tcp" => RuntimeExecutionDescriptor::new(
            label,
            "tcp-over-quic-stream",
            "stream-transport",
            "tcp",
        )
        .with_transport_underlay("quic"),
        "async-secure-endpoint-connect" => RuntimeExecutionDescriptor::new(
            label,
            "secure-endpoint-connect",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("protocol-closed")
        .with_security_underlay("standard-tls")
        .with_transport_underlay("tcp"),
        "plain-tcp-relay" => {
            RuntimeExecutionDescriptor::new(label, "tcp-relay", "stream-transport", "tcp")
                .with_transport_underlay("tcp")
        }
        "aead-tcp-relay" => {
            RuntimeExecutionDescriptor::new(label, "aead-tcp-relay", "stream-transport", "tcp")
                .with_transport_underlay("tcp")
        }
        "shadowsocks-2022-tcp" => {
            RuntimeExecutionDescriptor::new(label, "aead-2022-tcp-relay", "stream-transport", "tcp")
                .with_security_underlay("aead-2022")
                .with_transport_underlay("tcp")
        }
        "wrapped-websocket-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("websocket")
        .with_transport_underlay("tcp"),
        "wrapped-httpupgrade-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("httpupgrade")
        .with_transport_underlay("tcp"),
        "wrapped-secure-websocket-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("websocket")
        .with_transport_underlay("tcp"),
        "wrapped-secure-httpupgrade-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("udp-over-stream-or-datagram")
        .with_stream_wrapper("httpupgrade")
        .with_transport_underlay("tcp"),
        "wrapped-grpc-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_stream_wrapper("grpc")
        .with_transport_underlay("tcp"),
        "plugin-wrapper-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("plugin-wrapper-stream")
        .with_stream_wrapper("plugin-wrapper")
        .with_security_underlay("aead")
        .with_transport_underlay("tcp"),
        "plugin-wrapper-aead-2022" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("plugin-wrapper-stream")
        .with_stream_wrapper("plugin-wrapper")
        .with_security_underlay("aead-2022")
        .with_transport_underlay("tcp"),
        "plugin-wrapper-tls-websocket-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("plugin-wrapper-stream")
        .with_stream_wrapper("plugin-wrapper")
        .with_security_underlay("standard-tls")
        .with_transport_underlay("tcp"),
        "inner-encryption-websocket-aead" => RuntimeExecutionDescriptor::new(
            label,
            "wrapped-stream-relay",
            "stream-transport",
            "tcp",
        )
        .with_packet_semantics("inner-encryption-stream")
        .with_stream_wrapper("websocket")
        .with_security_underlay("standard-tls")
        .with_transport_underlay("tcp"),
        _ => RuntimeExecutionDescriptor::new(label, "runtime-event", "runtime-evidence", "tcp"),
    }
}

pub(super) fn udp_execution_descriptor(label: &str) -> RuntimeExecutionDescriptor {
    match label {
        "resident-dns-udp" => {
            RuntimeExecutionDescriptor::new(label, "dns-udp-forward", "dns-packet", "udp")
                .with_packet_semantics("dns")
        }
        "vless-xudp" => {
            RuntimeExecutionDescriptor::new(label, "packet-relay", "packet-transport", "udp")
                .with_packet_semantics("xudp")
                .with_transport_underlay("tcp")
        }
        "udp-datagram-aead" => {
            RuntimeExecutionDescriptor::new(label, "packet-relay", "packet-transport", "udp")
                .with_packet_semantics("datagram-aead")
        }
        "udp-datagram-aead-2022" => {
            RuntimeExecutionDescriptor::new(label, "packet-relay", "packet-transport", "udp")
                .with_packet_semantics("datagram-aead-2022")
                .with_security_underlay("aead-2022")
        }
        "socks5-udp-associate" => {
            RuntimeExecutionDescriptor::new(label, "udp-associate", "packet-transport", "udp")
                .with_packet_semantics("udp-associate")
                .with_transport_underlay("tcp")
        }
        "tls-udp-over-tcp" | "aead-udp-over-tcp" => {
            RuntimeExecutionDescriptor::new(label, "udp-over-stream", "packet-transport", "udp")
                .with_packet_semantics("udp-over-stream")
                .with_transport_underlay("tcp")
        }
        "frame-tls-udp-packet-stream" => {
            RuntimeExecutionDescriptor::new(label, "packet-stream-relay", "packet-transport", "udp")
                .with_packet_semantics("packet-stream")
                .with_stream_wrapper("frame-stream")
                .with_transport_underlay("tcp")
        }
        "quic-udp-datagram" => {
            RuntimeExecutionDescriptor::new(label, "quic-datagram", "packet-transport", "udp")
                .with_packet_semantics("quic-datagram")
                .with_transport_underlay("quic")
        }
        "quic-udp-stream-packet" => {
            RuntimeExecutionDescriptor::new(label, "quic-stream-packet", "packet-transport", "udp")
                .with_packet_semantics("stream-packet")
                .with_transport_underlay("quic")
        }
        _ => RuntimeExecutionDescriptor::new(label, "packet-runtime", "packet-evidence", "udp"),
    }
}
