#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimeExecutorKind {
    TcpListener,
    RouteBlock,
    DirectConnect,
    TcpRelay,
    WrappedStreamRelay,
    FrameStreamRelay,
    TcpOverQuicStream,
    SecureEndpointConnect,
    AeadTcpRelay,
    Aead2022TcpRelay,
    RuntimeEvent,
    DnsUdpForward,
    PacketRelay,
    UdpAssociate,
    UdpOverStream,
    PacketStreamRelay,
    QuicDatagram,
    QuicStreamPacket,
    PacketRuntime,
    Custom(String),
}

impl RuntimeExecutorKind {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "tcp-listener" => Self::TcpListener,
            "route-block" => Self::RouteBlock,
            "direct-connect" => Self::DirectConnect,
            "tcp-relay" => Self::TcpRelay,
            "wrapped-stream-relay" => Self::WrappedStreamRelay,
            "frame-stream-relay" => Self::FrameStreamRelay,
            "tcp-over-quic-stream" => Self::TcpOverQuicStream,
            "secure-endpoint-connect" => Self::SecureEndpointConnect,
            "aead-tcp-relay" => Self::AeadTcpRelay,
            "aead-2022-tcp-relay" => Self::Aead2022TcpRelay,
            "runtime-event" => Self::RuntimeEvent,
            "dns-udp-forward" => Self::DnsUdpForward,
            "packet-relay" => Self::PacketRelay,
            "udp-associate" => Self::UdpAssociate,
            "udp-over-stream" => Self::UdpOverStream,
            "packet-stream-relay" => Self::PacketStreamRelay,
            "quic-datagram" => Self::QuicDatagram,
            "quic-stream-packet" => Self::QuicStreamPacket,
            "packet-runtime" => Self::PacketRuntime,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::TcpListener => "tcp-listener",
            Self::RouteBlock => "route-block",
            Self::DirectConnect => "direct-connect",
            Self::TcpRelay => "tcp-relay",
            Self::WrappedStreamRelay => "wrapped-stream-relay",
            Self::FrameStreamRelay => "frame-stream-relay",
            Self::TcpOverQuicStream => "tcp-over-quic-stream",
            Self::SecureEndpointConnect => "secure-endpoint-connect",
            Self::AeadTcpRelay => "aead-tcp-relay",
            Self::Aead2022TcpRelay => "aead-2022-tcp-relay",
            Self::RuntimeEvent => "runtime-event",
            Self::DnsUdpForward => "dns-udp-forward",
            Self::PacketRelay => "packet-relay",
            Self::UdpAssociate => "udp-associate",
            Self::UdpOverStream => "udp-over-stream",
            Self::PacketStreamRelay => "packet-stream-relay",
            Self::QuicDatagram => "quic-datagram",
            Self::QuicStreamPacket => "quic-stream-packet",
            Self::PacketRuntime => "packet-runtime",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimeCapability {
    StreamIngress,
    TrafficBlock,
    DirectStream,
    StreamTransport,
    RuntimeEvidence,
    DnsPacket,
    PacketTransport,
    PacketEvidence,
    Custom(String),
}

impl RuntimeCapability {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "stream-ingress" => Self::StreamIngress,
            "traffic-block" => Self::TrafficBlock,
            "direct-stream" => Self::DirectStream,
            "stream-transport" => Self::StreamTransport,
            "runtime-evidence" => Self::RuntimeEvidence,
            "dns-packet" => Self::DnsPacket,
            "packet-transport" => Self::PacketTransport,
            "packet-evidence" => Self::PacketEvidence,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::StreamIngress => "stream-ingress",
            Self::TrafficBlock => "traffic-block",
            Self::DirectStream => "direct-stream",
            Self::StreamTransport => "stream-transport",
            Self::RuntimeEvidence => "runtime-evidence",
            Self::DnsPacket => "dns-packet",
            Self::PacketTransport => "packet-transport",
            Self::PacketEvidence => "packet-evidence",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeNetwork {
    Tcp,
    Udp,
}

impl RuntimeNetwork {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "udp" => Self::Udp,
            _ => Self::Tcp,
        }
    }

    pub(super) fn as_report_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimePacketSemantics {
    UdpOverStreamOrDatagram,
    ProtocolClosed,
    PluginWrapperStream,
    InnerEncryptionStream,
    Dns,
    Xudp,
    DatagramAead,
    DatagramAead2022,
    UdpAssociate,
    UdpOverStream,
    MultiplexedStream,
    PacketStream,
    QuicDatagram,
    StreamPacket,
    Custom(String),
}

impl RuntimePacketSemantics {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "udp-over-stream-or-datagram" => Self::UdpOverStreamOrDatagram,
            "protocol-closed" => Self::ProtocolClosed,
            "plugin-wrapper-stream" => Self::PluginWrapperStream,
            "inner-encryption-stream" => Self::InnerEncryptionStream,
            "dns" => Self::Dns,
            "xudp" => Self::Xudp,
            "datagram-aead" => Self::DatagramAead,
            "datagram-aead-2022" => Self::DatagramAead2022,
            "udp-associate" => Self::UdpAssociate,
            "udp-over-stream" => Self::UdpOverStream,
            "multiplexed-stream" => Self::MultiplexedStream,
            "packet-stream" => Self::PacketStream,
            "quic-datagram" => Self::QuicDatagram,
            "stream-packet" => Self::StreamPacket,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::UdpOverStreamOrDatagram => "udp-over-stream-or-datagram",
            Self::ProtocolClosed => "protocol-closed",
            Self::PluginWrapperStream => "plugin-wrapper-stream",
            Self::InnerEncryptionStream => "inner-encryption-stream",
            Self::Dns => "dns",
            Self::Xudp => "xudp",
            Self::DatagramAead => "datagram-aead",
            Self::DatagramAead2022 => "datagram-aead-2022",
            Self::UdpAssociate => "udp-associate",
            Self::UdpOverStream => "udp-over-stream",
            Self::MultiplexedStream => "multiplexed-stream",
            Self::PacketStream => "packet-stream",
            Self::QuicDatagram => "quic-datagram",
            Self::StreamPacket => "stream-packet",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimeSecurityUnderlay {
    StandardTls,
    Aead,
    Aead2022,
    Rustls,
    Reality,
    BoringSsl,
    FingerprintAwareTls,
    Custom(String),
}

impl RuntimeSecurityUnderlay {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "standard-tls" => Self::StandardTls,
            "aead" => Self::Aead,
            "aead-2022" => Self::Aead2022,
            "rustls" => Self::Rustls,
            "reality" => Self::Reality,
            "boringssl" => Self::BoringSsl,
            "fingerprint-aware-tls" => Self::FingerprintAwareTls,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::StandardTls => "standard-tls",
            Self::Aead => "aead",
            Self::Aead2022 => "aead-2022",
            Self::Rustls => "rustls",
            Self::Reality => "reality",
            Self::BoringSsl => "boringssl",
            Self::FingerprintAwareTls => "fingerprint-aware-tls",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimeStreamWrapper {
    WebSocket,
    HttpUpgrade,
    Grpc,
    Meek,
    Xhttp,
    FrameStream,
    PluginWrapper,
    Custom(String),
}

impl RuntimeStreamWrapper {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "websocket" => Self::WebSocket,
            "httpupgrade" => Self::HttpUpgrade,
            "grpc" => Self::Grpc,
            "meek" => Self::Meek,
            "xhttp" => Self::Xhttp,
            "frame-stream" => Self::FrameStream,
            "plugin-wrapper" => Self::PluginWrapper,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::WebSocket => "websocket",
            Self::HttpUpgrade => "httpupgrade",
            Self::Grpc => "grpc",
            Self::Meek => "meek",
            Self::Xhttp => "xhttp",
            Self::FrameStream => "frame-stream",
            Self::PluginWrapper => "plugin-wrapper",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimeTransportUnderlay {
    Tcp,
    Quic,
    Quinn,
    QuinnH3,
    Custom(String),
}

impl RuntimeTransportUnderlay {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "tcp" => Self::Tcp,
            "quic" => Self::Quic,
            "quinn" => Self::Quinn,
            "quinn-h3" => Self::QuinnH3,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::Quinn => "quinn",
            Self::QuinnH3 => "quinn-h3",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimeSessionOwnership {
    ManagerOwned,
    Custom(String),
}

impl RuntimeSessionOwnership {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "manager-owned" => Self::ManagerOwned,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::ManagerOwned => "manager-owned",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimeRouteAction {
    Accept,
    Block,
    Direct,
    Proxy,
    Dns,
    Evidence,
    Custom(String),
}

impl RuntimeRouteAction {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "accept" => Self::Accept,
            "block" => Self::Block,
            "direct" => Self::Direct,
            "proxy" => Self::Proxy,
            "dns" => Self::Dns,
            "evidence" => Self::Evidence,
            value => Self::Custom(value.to_owned()),
        }
    }

    pub(super) fn as_report_str(&self) -> &str {
        match self {
            Self::Accept => "accept",
            Self::Block => "block",
            Self::Direct => "direct",
            Self::Proxy => "proxy",
            Self::Dns => "dns",
            Self::Evidence => "evidence",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TcpExecutionLabel {
    AsyncAcceptDirect,
    AsyncBlock,
    AsyncDirect,
    AsyncProxyTls,
    AsyncMuxTls,
    AsyncProxyWebSocketTls,
    AsyncProxyHttpUpgradeTls,
    AsyncProxyGrpcTls,
    AsyncProxyMeekTls,
    AsyncProxyXhttpH1Tls,
    AsyncProxyXhttpH2Tls,
    AsyncProxyXhttpH3Tls,
    AsyncProxyFrameTls,
    AsyncProxyQuicTcp,
    AsyncSecureEndpointConnect,
    PlainTcpRelay,
    AeadTcpRelay,
    Shadowsocks2022Tcp,
    WrappedWebSocketAead,
    WrappedHttpUpgradeAead,
    WrappedSecureWebSocketAead,
    WrappedSecureHttpUpgradeAead,
    WrappedGrpcAead,
    PluginWrapperAead,
    PluginWrapperAead2022,
    PluginWrapperTlsWebSocketAead,
    InnerEncryptionWebSocketAead,
    Unknown,
}

impl TcpExecutionLabel {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "async-accept-direct" => Self::AsyncAcceptDirect,
            "async-block" => Self::AsyncBlock,
            "async-direct" => Self::AsyncDirect,
            "async-proxy-tls" => Self::AsyncProxyTls,
            "async-mux-tls" => Self::AsyncMuxTls,
            "async-proxy-websocket-tls" => Self::AsyncProxyWebSocketTls,
            "async-proxy-httpupgrade-tls" => Self::AsyncProxyHttpUpgradeTls,
            "async-proxy-grpc-tls" => Self::AsyncProxyGrpcTls,
            "async-proxy-meek-tls" => Self::AsyncProxyMeekTls,
            "async-proxy-xhttp-h1-tls" => Self::AsyncProxyXhttpH1Tls,
            "async-proxy-xhttp-h2-tls" => Self::AsyncProxyXhttpH2Tls,
            "async-proxy-xhttp-h3-tls" => Self::AsyncProxyXhttpH3Tls,
            "async-proxy-frame-tls" => Self::AsyncProxyFrameTls,
            "async-proxy-quic-tcp" => Self::AsyncProxyQuicTcp,
            "async-secure-endpoint-connect" => Self::AsyncSecureEndpointConnect,
            "plain-tcp-relay" => Self::PlainTcpRelay,
            "aead-tcp-relay" => Self::AeadTcpRelay,
            "shadowsocks-2022-tcp" => Self::Shadowsocks2022Tcp,
            "wrapped-websocket-aead" => Self::WrappedWebSocketAead,
            "wrapped-httpupgrade-aead" => Self::WrappedHttpUpgradeAead,
            "wrapped-secure-websocket-aead" => Self::WrappedSecureWebSocketAead,
            "wrapped-secure-httpupgrade-aead" => Self::WrappedSecureHttpUpgradeAead,
            "wrapped-grpc-aead" => Self::WrappedGrpcAead,
            "plugin-wrapper-aead" => Self::PluginWrapperAead,
            "plugin-wrapper-aead-2022" => Self::PluginWrapperAead2022,
            "plugin-wrapper-tls-websocket-aead" => Self::PluginWrapperTlsWebSocketAead,
            "inner-encryption-websocket-aead" => Self::InnerEncryptionWebSocketAead,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpExecutionLabel {
    ResidentDnsUdp,
    VlessXudp,
    VlessUdpOverStream,
    UdpDatagramAead,
    UdpDatagramAead2022,
    Socks5UdpAssociate,
    TlsUdpOverTcp,
    AeadUdpOverTcp,
    FrameTlsUdpPacketStream,
    QuicUdpDatagram,
    QuicUdpStreamPacket,
    Unknown,
}

impl UdpExecutionLabel {
    pub(super) fn from_report_str(value: &str) -> Self {
        match value {
            "resident-dns-udp" => Self::ResidentDnsUdp,
            "vless-xudp" => Self::VlessXudp,
            "vless-udp-over-stream" => Self::VlessUdpOverStream,
            "udp-datagram-aead" => Self::UdpDatagramAead,
            "udp-datagram-aead-2022" => Self::UdpDatagramAead2022,
            "socks5-udp-associate" => Self::Socks5UdpAssociate,
            "tls-udp-over-tcp" => Self::TlsUdpOverTcp,
            "aead-udp-over-tcp" => Self::AeadUdpOverTcp,
            "frame-tls-udp-packet-stream" => Self::FrameTlsUdpPacketStream,
            "quic-udp-datagram" => Self::QuicUdpDatagram,
            "quic-udp-stream-packet" => Self::QuicUdpStreamPacket,
            _ => Self::Unknown,
        }
    }
}
