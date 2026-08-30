use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedProtocol {
    VlessStandard,
    VlessVision,
    VlessMux,
    Socks5,
    HttpProxy,
    ConnectUdpH2,
    ConnectUdpH3,
    ShadowsocksAead,
    Shadowsocks2022,
    ShadowsocksSimpleObfsHttp,
    ShadowsocksSimpleObfsTls,
    ShadowsocksV2rayPluginTlsWebSocket,
    Shadowsocks2022SimpleObfsHttp,
    ShadowsocksRHttpSimple,
    Trojan,
    TrojanInnerShadowsocks,
    AnyTls,
    VmessAead,
    Hysteria2,
    Tuic,
    Juicity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedSecurity {
    None,
    Aead,
    Aead2022,
    LegacyCipher,
    StandardTls,
    InsecureTls,
    FragmentedTls,
    FingerprintAwareTls,
    RealityBoring,
    RealityFingerprint,
    QuicTls,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializedTlsFeatures {
    pub allow_insecure: bool,
    pub fragment: bool,
    pub fingerprint: bool,
}

impl MaterializedTlsFeatures {
    pub const NONE: Self = Self::new(false, false, false);
    pub const ALLOW_INSECURE: Self = Self::new(true, false, false);
    pub const FRAGMENT: Self = Self::new(false, true, false);
    pub const FINGERPRINT: Self = Self::new(false, false, true);
    pub const ALLOW_INSECURE_FRAGMENT: Self = Self::new(true, true, false);
    pub const ALLOW_INSECURE_FINGERPRINT: Self = Self::new(true, false, true);
    pub const FRAGMENT_FINGERPRINT: Self = Self::new(false, true, true);
    pub const ALLOW_INSECURE_FRAGMENT_FINGERPRINT: Self = Self::new(true, true, true);

    pub const fn new(allow_insecure: bool, fragment: bool, fingerprint: bool) -> Self {
        Self {
            allow_insecure,
            fragment,
            fingerprint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedWrapper {
    None,
    TcpHttpHeader,
    HttpTransport,
    ConnectUdpH2,
    ConnectUdpH3,
    WebSocket,
    HttpUpgrade,
    Grpc,
    H2,
    Meek,
    Mux,
    XhttpH1,
    XhttpH2,
    XhttpH3,
    FrameStream,
    QuicStream,
    SimpleObfsHttp,
    SimpleObfsTls,
    LegacyObfs,
    V2rayPluginTlsWebSocket,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedStreamPacketTransport {
    PlainTcp,
    TlsTcp,
    TcpHttpHeaderPlain,
    TcpHttpHeaderTls,
    WebSocketPlain,
    WebSocketTls,
    HttpUpgradePlain,
    HttpUpgradeTls,
    GrpcTls,
    H2Tls,
    XhttpH1,
    XhttpH2,
    XhttpH3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedPolicyClosedReason {
    HttpConnect,
    PluginWrapper,
    ShadowsocksR,
    TrojanInnerShadowsocks,
    TrojanUnsupportedWrapper,
    VlessMux,
    VlessMeek,
    VlessUnsupportedShape,
    VmessH2,
    VmessUnsupportedShape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedUdp {
    Socks5Associate,
    ShadowsocksAead,
    Shadowsocks2022,
    Vless(MaterializedStreamPacketTransport),
    VlessVision,
    Trojan(MaterializedStreamPacketTransport),
    Vmess(MaterializedStreamPacketTransport),
    AnyTls,
    Hysteria2,
    Tuic,
    Juicity,
    ConnectUdpH2,
    ConnectUdpH3,
    PolicyClosed(MaterializedPolicyClosedReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedChain {
    Standalone,
    ParentConnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedChainUdp {
    NotChained,
    ParentStream,
    PolicyClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedXhttpMode {
    NotApplicable,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedXhttpSettings {
    NotApplicable,
    Default,
    Extended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedQuicVerification {
    NotApplicable,
    WebPki,
    Insecure,
    PinOnly,
    WebPkiAndPin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedPortHopping {
    NotApplicable,
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedSourceImport {
    Canonical,
    LegacyVmess,
    Unrecognized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaterializedPassthroughUdp {
    NotRequested,
    Requested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializedExecutionShape {
    pub protocol: MaterializedProtocol,
    pub security: MaterializedSecurity,
    pub wrapper: MaterializedWrapper,
    pub udp: MaterializedUdp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaterializedSourceShape {
    pub protocol: MaterializedProtocol,
    pub security: MaterializedSecurity,
    pub tls_features: MaterializedTlsFeatures,
    pub wrapper: MaterializedWrapper,
    pub udp: MaterializedUdp,
    pub chain: MaterializedChain,
    pub chain_udp: MaterializedChainUdp,
    pub xhttp_mode: MaterializedXhttpMode,
    pub xhttp_settings: MaterializedXhttpSettings,
    pub quic_verification: MaterializedQuicVerification,
    pub port_hopping: MaterializedPortHopping,
    pub source_import: MaterializedSourceImport,
    pub passthrough_udp: MaterializedPassthroughUdp,
}
