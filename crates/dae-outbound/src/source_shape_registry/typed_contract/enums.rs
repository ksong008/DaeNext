#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolFraming {
    Shadowsocks,
    ShadowsocksR,
    Trojan,
    TrojanGo,
    Vmess,
    Vless,
    Hysteria2,
    Tuic,
    Juicity,
    AnyTls,
    HttpProxy,
    ConnectUdp,
    Socks5,
    QuicFamily,
    MultiProtocol,
    ProxyEndpoint,
    SharedTransport,
    LegacyProtocol,
    NonRustNative,
    ForeignRuntime,
    NonNativeExecutor,
}

impl ProtocolFraming {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::Shadowsocks => "shadowsocks",
            Self::ShadowsocksR => "shadowsocksr",
            Self::Trojan => "trojan",
            Self::TrojanGo => "trojan-go",
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Juicity => "juicity",
            Self::AnyTls => "anytls",
            Self::HttpProxy => "http-proxy",
            Self::ConnectUdp => "connect-udp",
            Self::Socks5 => "socks5",
            Self::QuicFamily => "quic-family",
            Self::MultiProtocol => "multi-protocol",
            Self::ProxyEndpoint => "proxy-endpoint",
            Self::SharedTransport => "shared-transport",
            Self::LegacyProtocol => "legacy-protocol",
            Self::NonRustNative => "non-rust-native",
            Self::ForeignRuntime => "foreign-runtime",
            Self::NonNativeExecutor => "non-native-executor",
        }
    }

    pub fn from_report_str(value: &str) -> Option<Self> {
        match value {
            "shadowsocks" => Some(Self::Shadowsocks),
            "shadowsocksr" => Some(Self::ShadowsocksR),
            "trojan" => Some(Self::Trojan),
            "trojan-go" => Some(Self::TrojanGo),
            "vmess" => Some(Self::Vmess),
            "vless" => Some(Self::Vless),
            "hysteria2" => Some(Self::Hysteria2),
            "tuic" => Some(Self::Tuic),
            "juicity" => Some(Self::Juicity),
            "anytls" => Some(Self::AnyTls),
            "http-proxy" => Some(Self::HttpProxy),
            "connect-udp" => Some(Self::ConnectUdp),
            "socks5" => Some(Self::Socks5),
            "quic-family" => Some(Self::QuicFamily),
            "multi-protocol" => Some(Self::MultiProtocol),
            "proxy-endpoint" => Some(Self::ProxyEndpoint),
            "shared-transport" => Some(Self::SharedTransport),
            "legacy-protocol" => Some(Self::LegacyProtocol),
            "non-rust-native" => Some(Self::NonRustNative),
            "foreign-runtime" => Some(Self::ForeignRuntime),
            "non-native-executor" => Some(Self::NonNativeExecutor),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityUnderlay {
    None,
    StandardTls,
    StandardOrInsecureTls,
    StandardOrFingerprintAwareTls,
    StandardOrFingerprintAwareTlsOrReality,
    StandardOrFragmentedTls,
    TlsStreamVariants,
    TlsStreamVariantsWithoutFingerprint,
    TlsStreamVariantsOrReality,
    FingerprintAwareTls,
    FingerprintAwareTlsVariants,
    InsecureTls,
    InsecureTlsVariants,
    Reality,
    QuicTls,
    VerifiedQuicTls,
    Aead,
    Aead2022,
    PlainParentConnect,
    PlainParentConnectWithChildSecurityVariants,
    PlainOrStandardTls,
    PlainOrTlsStreamVariants,
    PlainOrTlsStreamVariantsOrReality,
    PlainOrNativeUnderlay,
    FullUtls,
    TlsFragment,
    LegacyCipher,
    NonNative,
    External,
    NonNativeExecutor,
}

impl SecurityUnderlay {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StandardTls => "standard-tls",
            Self::StandardOrInsecureTls => "standard-or-insecure-tls",
            Self::StandardOrFingerprintAwareTls => "standard-or-fingerprint-aware-tls",
            Self::StandardOrFingerprintAwareTlsOrReality => {
                "standard-or-fingerprint-aware-tls-or-reality"
            }
            Self::StandardOrFragmentedTls => "standard-or-fragmented-tls",
            Self::TlsStreamVariants => "tls-stream-variants",
            Self::TlsStreamVariantsWithoutFingerprint => "tls-stream-variants-without-fingerprint",
            Self::TlsStreamVariantsOrReality => "tls-stream-variants-or-reality",
            Self::FingerprintAwareTls => "fingerprint-aware-tls",
            Self::FingerprintAwareTlsVariants => "fingerprint-aware-tls-variants",
            Self::InsecureTls => "insecure-tls",
            Self::InsecureTlsVariants => "insecure-tls-variants",
            Self::Reality => "reality",
            Self::QuicTls => "quic-tls",
            Self::VerifiedQuicTls => "verified-quic-tls",
            Self::Aead => "aead",
            Self::Aead2022 => "aead-2022",
            Self::PlainParentConnect => "plain-parent-connect",
            Self::PlainParentConnectWithChildSecurityVariants => {
                "plain-parent-connect-with-child-security-variants"
            }
            Self::PlainOrStandardTls => "plain-or-standard-tls",
            Self::PlainOrTlsStreamVariants => "plain-or-tls-stream-variants",
            Self::PlainOrTlsStreamVariantsOrReality => "plain-or-tls-stream-variants-or-reality",
            Self::PlainOrNativeUnderlay => "plain-or-native-underlay",
            Self::FullUtls => "full-utls",
            Self::TlsFragment => "tls-fragment",
            Self::LegacyCipher => "legacy-cipher",
            Self::NonNative => "non-native",
            Self::External => "external",
            Self::NonNativeExecutor => "non-native-executor",
        }
    }

    pub fn from_report_str(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "standard-tls" => Some(Self::StandardTls),
            "standard-or-insecure-tls" => Some(Self::StandardOrInsecureTls),
            "standard-or-fingerprint-aware-tls" => Some(Self::StandardOrFingerprintAwareTls),
            "standard-or-fingerprint-aware-tls-or-reality" => {
                Some(Self::StandardOrFingerprintAwareTlsOrReality)
            }
            "standard-or-fragmented-tls" => Some(Self::StandardOrFragmentedTls),
            "tls-stream-variants" => Some(Self::TlsStreamVariants),
            "tls-stream-variants-without-fingerprint" => {
                Some(Self::TlsStreamVariantsWithoutFingerprint)
            }
            "tls-stream-variants-or-reality" => Some(Self::TlsStreamVariantsOrReality),
            "fingerprint-aware-tls" => Some(Self::FingerprintAwareTls),
            "fingerprint-aware-tls-variants" => Some(Self::FingerprintAwareTlsVariants),
            "insecure-tls" => Some(Self::InsecureTls),
            "insecure-tls-variants" => Some(Self::InsecureTlsVariants),
            "reality" => Some(Self::Reality),
            "quic-tls" => Some(Self::QuicTls),
            "verified-quic-tls" => Some(Self::VerifiedQuicTls),
            "aead" => Some(Self::Aead),
            "aead-2022" => Some(Self::Aead2022),
            "plain-parent-connect" => Some(Self::PlainParentConnect),
            "plain-parent-connect-with-child-security-variants" => {
                Some(Self::PlainParentConnectWithChildSecurityVariants)
            }
            "plain-or-standard-tls" => Some(Self::PlainOrStandardTls),
            "plain-or-tls-stream-variants" => Some(Self::PlainOrTlsStreamVariants),
            "plain-or-tls-stream-variants-or-reality" => {
                Some(Self::PlainOrTlsStreamVariantsOrReality)
            }
            "plain-or-native-underlay" => Some(Self::PlainOrNativeUnderlay),
            "full-utls" => Some(Self::FullUtls),
            "tls-fragment" => Some(Self::TlsFragment),
            "legacy-cipher" => Some(Self::LegacyCipher),
            "non-native" => Some(Self::NonNative),
            "external" => Some(Self::External),
            "non-native-executor" => Some(Self::NonNativeExecutor),
            _ => None,
        }
    }

    pub fn supports_allow_insecure(self) -> bool {
        matches!(
            self,
            Self::InsecureTls
                | Self::InsecureTlsVariants
                | Self::FingerprintAwareTlsVariants
                | Self::QuicTls
                | Self::StandardOrInsecureTls
                | Self::PlainOrStandardTls
                | Self::TlsStreamVariants
                | Self::TlsStreamVariantsWithoutFingerprint
                | Self::TlsStreamVariantsOrReality
                | Self::PlainOrTlsStreamVariants
                | Self::PlainOrTlsStreamVariantsOrReality
        )
    }

    pub fn supports_reality(self) -> bool {
        matches!(
            self,
            Self::Reality
                | Self::StandardOrFingerprintAwareTlsOrReality
                | Self::TlsStreamVariantsOrReality
                | Self::PlainOrTlsStreamVariantsOrReality
        )
    }

    pub fn supports_fingerprint_utls(self) -> bool {
        matches!(
            self,
            Self::StandardOrFingerprintAwareTls
                | Self::StandardOrFingerprintAwareTlsOrReality
                | Self::FingerprintAwareTls
                | Self::FingerprintAwareTlsVariants
                | Self::Reality
                | Self::TlsStreamVariants
                | Self::TlsStreamVariantsOrReality
                | Self::PlainOrTlsStreamVariants
                | Self::PlainOrTlsStreamVariantsOrReality
                | Self::FullUtls
        )
    }

    pub fn supports_tls_fragment(self) -> bool {
        matches!(
            self,
            Self::StandardOrFragmentedTls
                | Self::FingerprintAwareTlsVariants
                | Self::InsecureTlsVariants
                | Self::TlsFragment
                | Self::PlainParentConnectWithChildSecurityVariants
                | Self::TlsStreamVariants
                | Self::TlsStreamVariantsWithoutFingerprint
                | Self::TlsStreamVariantsOrReality
                | Self::PlainOrTlsStreamVariants
                | Self::PlainOrTlsStreamVariantsOrReality
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamWrapper {
    None,
    Websocket,
    Grpc,
    H2,
    HttpUpgrade,
    Xhttp,
    Meek,
    FrameStream,
    QuicStream,
    QuicPortHopping,
    BaselineOrPluginWrapper,
    SimpleObfsHttp,
    SimpleObfsTls,
    V2rayPluginTlsWebSocket,
    TlsWebsocketPlugin,
    ObfsTls,
    PluginWrapper,
    HttpTransport,
    ConnectUdpH2,
    ConnectUdpH3,
    NoneOrTcpHttpHeader,
    NoneOrStreamWrapper,
    WebsocketOrHttpUpgradeOrGrpc,
    Mux,
    LegacyObfs,
    NonNative,
    External,
    NonNativeExecutor,
}

impl StreamWrapper {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Websocket => "websocket",
            Self::Grpc => "grpc",
            Self::H2 => "h2",
            Self::HttpUpgrade => "httpupgrade",
            Self::Xhttp => "xhttp",
            Self::Meek => "meek",
            Self::FrameStream => "frame-stream",
            Self::QuicStream => "quic-stream",
            Self::QuicPortHopping => "quic-port-hopping",
            Self::BaselineOrPluginWrapper => "baseline-or-plugin-wrapper",
            Self::SimpleObfsHttp => "simple-obfs-http",
            Self::SimpleObfsTls => "simple-obfs-tls",
            Self::V2rayPluginTlsWebSocket => "v2ray-plugin-tls-websocket",
            Self::TlsWebsocketPlugin => "tls-websocket-plugin",
            Self::ObfsTls => "obfs-tls",
            Self::PluginWrapper => "plugin-wrapper",
            Self::HttpTransport => "http-transport",
            Self::ConnectUdpH2 => "connect-udp-h2",
            Self::ConnectUdpH3 => "connect-udp-h3",
            Self::NoneOrTcpHttpHeader => "none-or-tcp-http-header",
            Self::NoneOrStreamWrapper => "none-or-stream-wrapper",
            Self::WebsocketOrHttpUpgradeOrGrpc => "websocket-or-httpupgrade-or-grpc",
            Self::Mux => "mux",
            Self::LegacyObfs => "legacy-obfs",
            Self::NonNative => "non-native",
            Self::External => "external",
            Self::NonNativeExecutor => "non-native-executor",
        }
    }

    pub fn from_report_str(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "websocket" => Some(Self::Websocket),
            "grpc" => Some(Self::Grpc),
            "h2" => Some(Self::H2),
            "httpupgrade" => Some(Self::HttpUpgrade),
            "xhttp" => Some(Self::Xhttp),
            "meek" => Some(Self::Meek),
            "frame-stream" => Some(Self::FrameStream),
            "quic-stream" => Some(Self::QuicStream),
            "quic-port-hopping" => Some(Self::QuicPortHopping),
            "baseline-or-plugin-wrapper" => Some(Self::BaselineOrPluginWrapper),
            "simple-obfs-http" => Some(Self::SimpleObfsHttp),
            "simple-obfs-tls" => Some(Self::SimpleObfsTls),
            "v2ray-plugin-tls-websocket" => Some(Self::V2rayPluginTlsWebSocket),
            "tls-websocket-plugin" => Some(Self::TlsWebsocketPlugin),
            "obfs-tls" => Some(Self::ObfsTls),
            "plugin-wrapper" => Some(Self::PluginWrapper),
            "http-transport" => Some(Self::HttpTransport),
            "connect-udp-h2" => Some(Self::ConnectUdpH2),
            "connect-udp-h3" => Some(Self::ConnectUdpH3),
            "none-or-tcp-http-header" => Some(Self::NoneOrTcpHttpHeader),
            "none-or-stream-wrapper" => Some(Self::NoneOrStreamWrapper),
            "websocket-or-httpupgrade-or-grpc" => Some(Self::WebsocketOrHttpUpgradeOrGrpc),
            "mux" => Some(Self::Mux),
            "legacy-obfs" => Some(Self::LegacyObfs),
            "non-native" => Some(Self::NonNative),
            "external" => Some(Self::External),
            "non-native-executor" => Some(Self::NonNativeExecutor),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketSemantics {
    DatagramAead,
    DatagramAead2022,
    UdpOverStream,
    UdpOverStreamOrDatagram,
    UdpOverStreamOrProtocolClosed,
    Xudp,
    QuicDatagramOrStream,
    QuicDatagram,
    QuicPacket,
    QuicStreamPacket,
    UdpAssociate,
    ConnectUdpCapsule,
    ConnectUdpHttpDatagram,
    ProtocolClosed,
    PluginUdpPolicyClosed,
    LegacyUdpFailClosed,
    TcpStreamH2PacketUp,
    TcpStreamH3PacketUp,
    ExtendedXhttp,
    TcpResidentChain,
    TcpStreamWrapper,
    MultiplexedStream,
    PassthroughUdp,
    NonNative,
    External,
    NonNativeExecutor,
}

impl PacketSemantics {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::DatagramAead => "datagram-aead",
            Self::DatagramAead2022 => "datagram-aead-2022",
            Self::UdpOverStream => "udp-over-stream",
            Self::UdpOverStreamOrDatagram => "udp-over-stream-or-datagram",
            Self::UdpOverStreamOrProtocolClosed => "udp-over-stream-or-protocol-closed",
            Self::Xudp => "xudp",
            Self::QuicDatagramOrStream => "quic-datagram-or-stream",
            Self::QuicDatagram => "quic-datagram",
            Self::QuicPacket => "quic-packet",
            Self::QuicStreamPacket => "quic-stream-packet",
            Self::UdpAssociate => "udp-associate",
            Self::ConnectUdpCapsule => "connect-udp-capsule",
            Self::ConnectUdpHttpDatagram => "connect-udp-http-datagram",
            Self::ProtocolClosed => "protocol-closed",
            Self::PluginUdpPolicyClosed => "plugin-udp-policy-closed",
            Self::LegacyUdpFailClosed => "legacy-udp-fail-closed",
            Self::TcpStreamH2PacketUp => "tcp-stream-h2-packet-up",
            Self::TcpStreamH3PacketUp => "tcp-stream-h3-packet-up",
            Self::ExtendedXhttp => "extended-xhttp",
            Self::TcpResidentChain => "tcp-resident-chain",
            Self::TcpStreamWrapper => "tcp-stream-wrapper",
            Self::MultiplexedStream => "multiplexed-stream",
            Self::PassthroughUdp => "passthrough-udp",
            Self::NonNative => "non-native",
            Self::External => "external",
            Self::NonNativeExecutor => "non-native-executor",
        }
    }

    pub fn from_report_str(value: &str) -> Option<Self> {
        match value {
            "datagram-aead" => Some(Self::DatagramAead),
            "datagram-aead-2022" => Some(Self::DatagramAead2022),
            "udp-over-stream" => Some(Self::UdpOverStream),
            "udp-over-stream-or-datagram" => Some(Self::UdpOverStreamOrDatagram),
            "udp-over-stream-or-protocol-closed" => Some(Self::UdpOverStreamOrProtocolClosed),
            "xudp" => Some(Self::Xudp),
            "quic-datagram-or-stream" => Some(Self::QuicDatagramOrStream),
            "quic-datagram" => Some(Self::QuicDatagram),
            "quic-packet" => Some(Self::QuicPacket),
            "quic-stream-packet" => Some(Self::QuicStreamPacket),
            "udp-associate" => Some(Self::UdpAssociate),
            "connect-udp-capsule" => Some(Self::ConnectUdpCapsule),
            "connect-udp-http-datagram" => Some(Self::ConnectUdpHttpDatagram),
            "protocol-closed" => Some(Self::ProtocolClosed),
            "plugin-udp-policy-closed" => Some(Self::PluginUdpPolicyClosed),
            "legacy-udp-fail-closed" => Some(Self::LegacyUdpFailClosed),
            "tcp-stream-h2-packet-up" => Some(Self::TcpStreamH2PacketUp),
            "tcp-stream-h3-packet-up" => Some(Self::TcpStreamH3PacketUp),
            "extended-xhttp" => Some(Self::ExtendedXhttp),
            "tcp-resident-chain" => Some(Self::TcpResidentChain),
            "tcp-stream-wrapper" => Some(Self::TcpStreamWrapper),
            "multiplexed-stream" => Some(Self::MultiplexedStream),
            "passthrough-udp" => Some(Self::PassthroughUdp),
            "non-native" => Some(Self::NonNative),
            "external" => Some(Self::External),
            "non-native-executor" => Some(Self::NonNativeExecutor),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorKind {
    DatagramRelay,
    PacketOverStream,
    QuicPacketRelay,
    TcpStream,
    StreamWrapper,
    ResidentChain,
    MultiplexedStream,
    PassthroughUdp,
    PolicyClosed,
    Unsupported,
}

impl ExecutorKind {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::DatagramRelay => "datagram-relay",
            Self::PacketOverStream => "packet-over-stream",
            Self::QuicPacketRelay => "quic-packet-relay",
            Self::TcpStream => "tcp-stream",
            Self::StreamWrapper => "stream-wrapper",
            Self::ResidentChain => "resident-chain",
            Self::MultiplexedStream => "multiplexed-stream",
            Self::PassthroughUdp => "passthrough-udp",
            Self::PolicyClosed => "policy-closed",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn from_packet_semantics(packet_semantics: PacketSemantics) -> Self {
        match packet_semantics {
            PacketSemantics::DatagramAead | PacketSemantics::DatagramAead2022 => {
                Self::DatagramRelay
            }
            PacketSemantics::UdpOverStream
            | PacketSemantics::UdpOverStreamOrDatagram
            | PacketSemantics::UdpOverStreamOrProtocolClosed
            | PacketSemantics::Xudp
            | PacketSemantics::TcpStreamH2PacketUp
            | PacketSemantics::TcpStreamH3PacketUp
            | PacketSemantics::ExtendedXhttp
            | PacketSemantics::ConnectUdpCapsule
            | PacketSemantics::UdpAssociate => Self::PacketOverStream,
            PacketSemantics::QuicDatagramOrStream
            | PacketSemantics::QuicDatagram
            | PacketSemantics::QuicPacket
            | PacketSemantics::QuicStreamPacket
            | PacketSemantics::ConnectUdpHttpDatagram => Self::QuicPacketRelay,
            PacketSemantics::ProtocolClosed
            | PacketSemantics::PluginUdpPolicyClosed
            | PacketSemantics::LegacyUdpFailClosed => Self::TcpStream,
            PacketSemantics::TcpStreamWrapper => Self::StreamWrapper,
            PacketSemantics::TcpResidentChain => Self::ResidentChain,
            PacketSemantics::MultiplexedStream => Self::MultiplexedStream,
            PacketSemantics::PassthroughUdp => Self::PassthroughUdp,
            PacketSemantics::NonNative
            | PacketSemantics::External
            | PacketSemantics::NonNativeExecutor => Self::Unsupported,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceShapeState {
    Admitted,
    Blocked,
    NotSourceSupported,
}

impl SourceShapeState {
    pub fn as_report_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Blocked => "blocked",
            Self::NotSourceSupported => "not-source-supported",
        }
    }
}
