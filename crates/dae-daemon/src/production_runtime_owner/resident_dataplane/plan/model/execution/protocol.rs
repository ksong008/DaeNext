use super::super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentProtocolShape {
    VlessStandard,
    VlessVision,
    VlessMux,
    Socks5,
    HttpProxy,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentTcpRuntimeDispatch {
    Vless,
    FrameTls,
    Quic,
    Stream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentTcpProbeDispatch {
    Basic,
    Vless,
    Vmess,
    Trojan,
    AnyTls,
    Shadowsocks,
    Quic,
}

#[cfg(test)]
impl ResidentTcpRuntimeDispatch {
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::FrameTls => "frame-tls",
            Self::Quic => "quic",
            Self::Stream => "stream",
        }
    }
}

#[cfg(test)]
impl ResidentTcpProbeDispatch {
    pub(in crate::production_runtime_owner::resident_dataplane) fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Shadowsocks => "shadowsocks",
            Self::Quic => "quic",
        }
    }
}

impl ResidentProtocolShape {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        match proxy.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
                if is_xtls_rprx_vision_flow(&proxy.flow) =>
            {
                Self::VlessVision
            }
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => Self::VlessStandard,
            ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => Self::VlessMux,
            ResidentProxyProtocolPlan::Socks5Tcp { .. } => Self::Socks5,
            ResidentProxyProtocolPlan::HttpProxyTcp { .. } => Self::HttpProxy,
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => Self::ShadowsocksAead,
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => Self::Shadowsocks2022,
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. } => {
                Self::ShadowsocksSimpleObfsHttp
            }
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. } => {
                Self::ShadowsocksSimpleObfsTls
            }
            ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. } => {
                Self::ShadowsocksV2rayPluginTlsWebSocket
            }
            ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
                Self::Shadowsocks2022SimpleObfsHttp
            }
            ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
                Self::ShadowsocksRHttpSimple
            }
            ResidentProxyProtocolPlan::TrojanTcpTls { .. } => Self::Trojan,
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => {
                Self::TrojanInnerShadowsocks
            }
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => Self::AnyTls,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. } => Self::VmessAead,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => Self::Hysteria2,
            ResidentProxyProtocolPlan::TuicQuicTcp { .. } => Self::Tuic,
            ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => Self::Juicity,
        }
    }

    pub(super) fn tcp_executor_label(self, wrapper: ResidentStreamWrapperPlan) -> &'static str {
        match self {
            Self::VlessStandard => match wrapper {
                ResidentStreamWrapperPlan::WebSocket => "resident-vless-websocket-stream",
                ResidentStreamWrapperPlan::HttpUpgrade => "resident-vless-httpupgrade-stream",
                ResidentStreamWrapperPlan::Grpc => "resident-vless-grpc-stream",
                ResidentStreamWrapperPlan::H2 => "resident-vless-h2-stream",
                ResidentStreamWrapperPlan::Meek => "resident-vless-meek-stream",
                ResidentStreamWrapperPlan::Xhttp(_) => "resident-vless-xhttp-stream",
                _ => "resident-vless-tcp-stream",
            },
            Self::VlessVision => "resident-vless-vision-tcp",
            Self::VlessMux => "resident-vless-mux-tcp",
            Self::Socks5 => "resident-socks5-connect",
            Self::HttpProxy => "resident-http-connect",
            Self::ShadowsocksAead => "resident-shadowsocks-aead-stream",
            Self::Shadowsocks2022 => "resident-shadowsocks-2022-stream",
            Self::ShadowsocksSimpleObfsHttp => "resident-shadowsocks-simple-obfs-http-stream",
            Self::ShadowsocksSimpleObfsTls => "resident-shadowsocks-simple-obfs-tls-stream",
            Self::ShadowsocksV2rayPluginTlsWebSocket => {
                "resident-shadowsocks-v2ray-plugin-tls-websocket-stream"
            }
            Self::Shadowsocks2022SimpleObfsHttp => {
                "resident-shadowsocks-2022-simple-obfs-http-stream"
            }
            Self::ShadowsocksRHttpSimple => "resident-shadowsocksr-http-simple-stream",
            Self::Trojan => match wrapper {
                ResidentStreamWrapperPlan::WebSocket => "resident-trojan-websocket-tls-stream",
                ResidentStreamWrapperPlan::HttpUpgrade => "resident-trojan-httpupgrade-tls-stream",
                ResidentStreamWrapperPlan::Grpc => "resident-trojan-grpc-tls-stream",
                _ => "resident-trojan-tls-stream",
            },
            Self::TrojanInnerShadowsocks => "resident-trojan-inner-shadowsocks-stream",
            Self::AnyTls => "resident-anytls-frame-stream",
            Self::VmessAead => "resident-vmess-aead-stream",
            Self::Hysteria2 => "resident-hysteria2-quic-stream",
            Self::Tuic => "resident-tuic-quic-stream",
            Self::Juicity => "resident-juicity-quic-stream",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn runtime_dispatch(
        self,
    ) -> ResidentTcpRuntimeDispatch {
        match self {
            Self::VlessStandard | Self::VlessVision | Self::VlessMux => {
                ResidentTcpRuntimeDispatch::Vless
            }
            Self::Trojan | Self::TrojanInnerShadowsocks | Self::AnyTls => {
                ResidentTcpRuntimeDispatch::FrameTls
            }
            Self::Hysteria2 | Self::Tuic | Self::Juicity => ResidentTcpRuntimeDispatch::Quic,
            _ => ResidentTcpRuntimeDispatch::Stream,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn probe_dispatch(
        self,
    ) -> ResidentTcpProbeDispatch {
        match self {
            Self::Socks5 | Self::HttpProxy => ResidentTcpProbeDispatch::Basic,
            Self::VlessStandard | Self::VlessVision | Self::VlessMux => {
                ResidentTcpProbeDispatch::Vless
            }
            Self::VmessAead => ResidentTcpProbeDispatch::Vmess,
            Self::Trojan | Self::TrojanInnerShadowsocks => ResidentTcpProbeDispatch::Trojan,
            Self::AnyTls => ResidentTcpProbeDispatch::AnyTls,
            Self::ShadowsocksAead
            | Self::Shadowsocks2022
            | Self::ShadowsocksSimpleObfsHttp
            | Self::ShadowsocksSimpleObfsTls
            | Self::ShadowsocksV2rayPluginTlsWebSocket
            | Self::Shadowsocks2022SimpleObfsHttp
            | Self::ShadowsocksRHttpSimple => ResidentTcpProbeDispatch::Shadowsocks,
            Self::Hysteria2 | Self::Tuic | Self::Juicity => ResidentTcpProbeDispatch::Quic,
        }
    }
}
