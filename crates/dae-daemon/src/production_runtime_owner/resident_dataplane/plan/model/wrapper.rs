use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentStreamWrapperPlan {
    None,
    HttpTransport,
    ConnectUdpH2,
    ConnectUdpH3,
    WebSocket,
    HttpUpgrade,
    Grpc,
    H2,
    Meek,
    Mux,
    Xhttp(ResidentXhttpHttpVersion),
    FrameStream,
    QuicStream,
    SimpleObfsHttp,
    SimpleObfsTls,
    LegacyObfs,
    V2rayPluginTlsWebSocket,
    Unsupported,
}

impl ResidentStreamWrapperPlan {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        match proxy.handler {
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => return Self::FrameStream,
            ResidentProxyProtocolPlan::ConnectUdpH2Tls { .. } => return Self::ConnectUdpH2,
            ResidentProxyProtocolPlan::ConnectUdpH3Tls { .. } => return Self::ConnectUdpH3,
            ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => return Self::Mux,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
            | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
            | ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => return Self::QuicStream,
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
            | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
                return Self::SimpleObfsHttp;
            }
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. } => {
                return Self::SimpleObfsTls;
            }
            ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. } => {
                return Self::V2rayPluginTlsWebSocket;
            }
            ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
                return Self::LegacyObfs;
            }
            _ => {}
        }

        match proxy.net.as_str() {
            "" | "tcp" | "udp" => Self::None,
            "http-transport" => Self::HttpTransport,
            "websocket" => Self::WebSocket,
            "httpupgrade" => Self::HttpUpgrade,
            "grpc" => Self::Grpc,
            "h2" => Self::H2,
            "meek" => Self::Meek,
            "xhttp" => Self::Xhttp(if proxy.tls == "reality" {
                ResidentXhttpHttpVersion::H2
            } else {
                ResidentXhttpHttpVersion::from_tls_alpn(&proxy.alpn)
            }),
            _ => Self::Unsupported,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn graph_label(
        self,
    ) -> &'static str {
        match self {
            Self::None => "none",
            Self::HttpTransport => "http-transport",
            Self::ConnectUdpH2 => "connect-udp-h2",
            Self::ConnectUdpH3 => "connect-udp-h3",
            Self::WebSocket => "websocket",
            Self::HttpUpgrade => "httpupgrade",
            Self::Grpc => "grpc",
            Self::H2 => "h2",
            Self::Meek => "meek",
            Self::Mux => "mux",
            Self::Xhttp(_) => "xhttp",
            Self::FrameStream => "frame-stream",
            Self::QuicStream => "quic-stream",
            Self::SimpleObfsHttp => "simple-obfs-http",
            Self::SimpleObfsTls => "simple-obfs-tls",
            Self::LegacyObfs => "legacy-obfs",
            Self::V2rayPluginTlsWebSocket => "v2ray-plugin-tls-websocket",
            Self::Unsupported => "unsupported",
        }
    }
}
