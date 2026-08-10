use super::super::*;
use super::UdpPacketSemantics;

mod agreement;
pub(in crate::production_runtime_owner::resident_dataplane) use agreement::{
    RESIDENT_UDP_CLEANUP_OWNER, RESIDENT_UDP_CLEANUP_POLICY, ResidentUdpExecutionAgreement,
    ResidentUdpExecutionDisposition, ResidentUdpSourceContract, ResidentUdpWireIdentityContract,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentStreamPacketTransport {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentUdpPolicyClosedReason {
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

impl ResidentUdpPolicyClosedReason {
    pub(in crate::production_runtime_owner::resident_dataplane) fn executor_label(
        self,
    ) -> &'static str {
        match self {
            Self::HttpConnect => "http-connect-udp-protocol-closed",
            Self::PluginWrapper => "plugin-udp-policy-closed",
            Self::ShadowsocksR => "legacy-udp-policy-closed",
            Self::TrojanInnerShadowsocks => "inner-encryption-udp-policy-closed",
            Self::TrojanUnsupportedWrapper => "trojan-transport-udp-policy-closed",
            Self::VlessMux => "vless-mux-udp-policy-closed",
            Self::VlessMeek => "vless-meek-udp-policy-closed",
            Self::VlessUnsupportedShape => "vless-transport-udp-policy-closed",
            Self::VmessH2 => "vmess-h2-udp-policy-closed",
            Self::VmessUnsupportedShape => "vmess-transport-udp-policy-closed",
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn reason(self) -> &'static str {
        match self {
            Self::HttpConnect => "HTTP CONNECT has no UDP relay semantics in resident dataplane",
            Self::PluginWrapper => {
                "SIP003 plugin UDP is not part of the required plugin contract; resident UDP keeps plugin UDP policy-closed without alternate execution"
            }
            Self::ShadowsocksR => {
                "ShadowsocksR legacy UDP requires an SSR protocol and obfs packet executor before resident UDP can admit this shape"
            }
            Self::TrojanInnerShadowsocks => {
                "Trojan inner-encryption UDP requires inner-encrypted packet semantics before resident UDP can admit this shape"
            }
            Self::TrojanUnsupportedWrapper => {
                "Trojan UDP requires a supported stream transport before resident UDP can admit this shape"
            }
            Self::VlessMux => {
                "resident VLESS mux handler does not admit UDP packets; mux row is TCP stream scoped"
            }
            Self::VlessMeek => "VLESS Meek transport has no resident UDP packet carrier",
            Self::VlessUnsupportedShape => {
                "VLESS wrapped-stream UDP requires a matching packet-over-wrapper executor for this transport and flow combination; Encryption wrappers remain policy-closed until that executor is admitted"
            }
            Self::VmessH2 => "VMess H2 has no resident UDP packet-over-wrapper executor",
            Self::VmessUnsupportedShape => {
                "VMess UDP wrapper requires a matching packet-over-wrapper executor for this transport and security combination"
            }
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn packet_semantics(
        self,
    ) -> UdpPacketSemantics {
        match self {
            Self::PluginWrapper => UdpPacketSemantics::PluginUdpPolicyClosed,
            Self::ShadowsocksR => UdpPacketSemantics::LegacyUdpFailClosed,
            Self::VlessMux => UdpPacketSemantics::MultiplexedStream,
            _ => UdpPacketSemantics::ProtocolClosed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::production_runtime_owner::resident_dataplane) enum ResidentUdpExecutorFactory {
    Socks5Associate,
    ShadowsocksAead,
    Shadowsocks2022,
    VlessStandard(ResidentStreamPacketTransport),
    VlessVisionXudp,
    Trojan(ResidentStreamPacketTransport),
    Vmess(ResidentStreamPacketTransport),
    AnyTlsPacketStream,
    Hysteria2Datagram,
    TuicPacket,
    JuicityStreamPacket,
    PolicyClosed(ResidentUdpPolicyClosedReason),
}

impl ResidentUdpExecutorFactory {
    pub(in crate::production_runtime_owner::resident_dataplane) const fn agreement(
        self,
    ) -> ResidentUdpExecutionAgreement {
        ResidentUdpExecutionAgreement::new(self)
    }

    pub(in crate::production_runtime_owner::resident_dataplane) const fn source_contract(
        self,
    ) -> ResidentUdpSourceContract {
        use ResidentUdpWireIdentityContract as Wire;
        match self {
            Self::Socks5Associate
            | Self::ShadowsocksAead
            | Self::Trojan(_)
            | Self::JuicityStreamPacket => {
                ResidentUdpSourceContract::fixed_target(Wire::DecodedSource)
            }
            Self::Shadowsocks2022 => {
                ResidentUdpSourceContract::fixed_target(Wire::DecodedSourceAndProtocolSession)
            }
            Self::VlessStandard(_)
            | Self::VlessVisionXudp
            | Self::Vmess(_)
            | Self::AnyTlsPacketStream => {
                ResidentUdpSourceContract::fixed_target(Wire::SessionBoundTarget)
            }
            Self::Hysteria2Datagram | Self::TuicPacket => {
                ResidentUdpSourceContract::fixed_target(Wire::ProtocolSessionAndDecodedSource)
            }
            Self::PolicyClosed(_) => ResidentUdpSourceContract::policy_closed(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn uses_request_scoped_exchange(
        self,
    ) -> bool {
        match self {
            Self::JuicityStreamPacket => true,
            Self::Socks5Associate
            | Self::ShadowsocksAead
            | Self::Shadowsocks2022
            | Self::VlessStandard(_)
            | Self::VlessVisionXudp
            | Self::Trojan(_)
            | Self::Vmess(_)
            | Self::AnyTlsPacketStream
            | Self::Hysteria2Datagram
            | Self::TuicPacket
            | Self::PolicyClosed(_) => false,
        }
    }

    pub(super) fn from_proxy(
        proxy: &ResidentProxyPlan,
        wrapper: ResidentStreamWrapperPlan,
        security: ResidentSecurityUnderlayPlan,
    ) -> Self {
        use ResidentStreamPacketTransport as Stream;
        use ResidentUdpPolicyClosedReason as Closed;

        match proxy.handler {
            ResidentProxyProtocolPlan::Socks5Tcp { .. } => Self::Socks5Associate,
            ResidentProxyProtocolPlan::HttpProxyTcp { .. } => {
                Self::PolicyClosed(Closed::HttpConnect)
            }
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => Self::ShadowsocksAead,
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => Self::Shadowsocks2022,
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
            | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
            | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
            | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
                Self::PolicyClosed(Closed::PluginWrapper)
            }
            ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
                Self::PolicyClosed(Closed::ShadowsocksR)
            }
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => {
                Self::PolicyClosed(Closed::TrojanInnerShadowsocks)
            }
            ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => {
                Self::PolicyClosed(Closed::VlessMux)
            }
            ResidentProxyProtocolPlan::VlessVisionTcpTls {
                encryption: Some(_),
                ..
            } if is_xtls_rprx_vision_flow(&proxy.flow)
                || !matches!(wrapper, ResidentStreamWrapperPlan::None) =>
            {
                Self::PolicyClosed(Closed::VlessUnsupportedShape)
            }
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
                if is_xtls_rprx_vision_flow(&proxy.flow)
                    && matches!(wrapper, ResidentStreamWrapperPlan::None) =>
            {
                Self::VlessVisionXudp
            }
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } if !proxy.flow.is_empty() => {
                Self::PolicyClosed(Closed::VlessUnsupportedShape)
            }
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => match wrapper {
                ResidentStreamWrapperPlan::None
                    if security == ResidentSecurityUnderlayPlan::None =>
                {
                    Self::VlessStandard(Stream::PlainTcp)
                }
                ResidentStreamWrapperPlan::None if security.is_tls_stream() => {
                    Self::VlessStandard(Stream::TlsTcp)
                }
                ResidentStreamWrapperPlan::WebSocket
                    if security == ResidentSecurityUnderlayPlan::None =>
                {
                    Self::VlessStandard(Stream::WebSocketPlain)
                }
                ResidentStreamWrapperPlan::WebSocket if security.is_tls_stream() => {
                    Self::VlessStandard(Stream::WebSocketTls)
                }
                ResidentStreamWrapperPlan::HttpUpgrade
                    if security == ResidentSecurityUnderlayPlan::None =>
                {
                    Self::VlessStandard(Stream::HttpUpgradePlain)
                }
                ResidentStreamWrapperPlan::HttpUpgrade if security.is_tls_stream() => {
                    Self::VlessStandard(Stream::HttpUpgradeTls)
                }
                ResidentStreamWrapperPlan::Grpc if security.is_tls_stream() => {
                    Self::VlessStandard(Stream::GrpcTls)
                }
                ResidentStreamWrapperPlan::H2 if security.is_tls_stream() => {
                    Self::VlessStandard(Stream::H2Tls)
                }
                ResidentStreamWrapperPlan::Xhttp(ResidentXhttpHttpVersion::H1) => {
                    Self::VlessStandard(Stream::XhttpH1)
                }
                ResidentStreamWrapperPlan::Xhttp(ResidentXhttpHttpVersion::H2) => {
                    Self::VlessStandard(Stream::XhttpH2)
                }
                ResidentStreamWrapperPlan::Xhttp(ResidentXhttpHttpVersion::H3) => {
                    Self::VlessStandard(Stream::XhttpH3)
                }
                ResidentStreamWrapperPlan::Meek => Self::PolicyClosed(Closed::VlessMeek),
                _ => Self::PolicyClosed(Closed::VlessUnsupportedShape),
            },
            ResidentProxyProtocolPlan::TrojanTcpTls { .. } => match wrapper {
                ResidentStreamWrapperPlan::None => Self::Trojan(Stream::TlsTcp),
                ResidentStreamWrapperPlan::WebSocket => Self::Trojan(Stream::WebSocketTls),
                ResidentStreamWrapperPlan::HttpUpgrade => Self::Trojan(Stream::HttpUpgradeTls),
                ResidentStreamWrapperPlan::Grpc => Self::Trojan(Stream::GrpcTls),
                _ => Self::PolicyClosed(Closed::TrojanUnsupportedWrapper),
            },
            ResidentProxyProtocolPlan::VmessAeadTcp { .. } => match wrapper {
                ResidentStreamWrapperPlan::None
                    if security == ResidentSecurityUnderlayPlan::None =>
                {
                    Self::Vmess(Stream::PlainTcp)
                }
                ResidentStreamWrapperPlan::None if security.is_standard_tls_stream() => {
                    Self::Vmess(Stream::TlsTcp)
                }
                ResidentStreamWrapperPlan::TcpHttpHeader
                    if security == ResidentSecurityUnderlayPlan::None =>
                {
                    Self::Vmess(Stream::TcpHttpHeaderPlain)
                }
                ResidentStreamWrapperPlan::TcpHttpHeader if security.is_standard_tls_stream() => {
                    Self::Vmess(Stream::TcpHttpHeaderTls)
                }
                ResidentStreamWrapperPlan::WebSocket
                    if security == ResidentSecurityUnderlayPlan::None =>
                {
                    Self::Vmess(Stream::WebSocketPlain)
                }
                ResidentStreamWrapperPlan::WebSocket if security.is_standard_tls_stream() => {
                    Self::Vmess(Stream::WebSocketTls)
                }
                ResidentStreamWrapperPlan::HttpUpgrade
                    if security == ResidentSecurityUnderlayPlan::None =>
                {
                    Self::Vmess(Stream::HttpUpgradePlain)
                }
                ResidentStreamWrapperPlan::HttpUpgrade if security.is_standard_tls_stream() => {
                    Self::Vmess(Stream::HttpUpgradeTls)
                }
                ResidentStreamWrapperPlan::Grpc if security.is_standard_tls_stream() => {
                    Self::Vmess(Stream::GrpcTls)
                }
                ResidentStreamWrapperPlan::H2 => Self::PolicyClosed(Closed::VmessH2),
                _ => Self::PolicyClosed(Closed::VmessUnsupportedShape),
            },
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => Self::AnyTlsPacketStream,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => Self::Hysteria2Datagram,
            ResidentProxyProtocolPlan::TuicQuicTcp { .. } => Self::TuicPacket,
            ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => Self::JuicityStreamPacket,
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn executor_label(
        self,
    ) -> &'static str {
        match self {
            Self::Socks5Associate => "resident-socks5-udp-associate",
            Self::ShadowsocksAead => "resident-shadowsocks-aead-datagram",
            Self::Shadowsocks2022 => "resident-shadowsocks-2022-datagram",
            Self::VlessVisionXudp => "resident-vless-xudp",
            Self::VlessStandard(transport) => vless_executor_label(transport),
            Self::Trojan(transport) => trojan_executor_label(transport),
            Self::Vmess(transport) => vmess_executor_label(transport),
            Self::AnyTlsPacketStream => "resident-anytls-packet-stream",
            Self::Hysteria2Datagram => "resident-hysteria2-quic-datagram",
            Self::TuicPacket => "resident-tuic-quic-packet",
            Self::JuicityStreamPacket => "resident-juicity-quic-stream-packet",
            Self::PolicyClosed(reason) => reason.executor_label(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn packet_semantics(
        self,
    ) -> UdpPacketSemantics {
        match self {
            Self::Socks5Associate => UdpPacketSemantics::UdpAssociate,
            Self::ShadowsocksAead => UdpPacketSemantics::DatagramAead,
            Self::Shadowsocks2022 => UdpPacketSemantics::DatagramAead2022,
            Self::VlessVisionXudp => UdpPacketSemantics::Xudp,
            Self::VlessStandard(_)
            | Self::Trojan(_)
            | Self::Vmess(_)
            | Self::AnyTlsPacketStream => UdpPacketSemantics::UdpOverStream,
            Self::Hysteria2Datagram => UdpPacketSemantics::QuicDatagram,
            Self::TuicPacket => UdpPacketSemantics::QuicPacket,
            Self::JuicityStreamPacket => UdpPacketSemantics::QuicStreamPacket,
            Self::PolicyClosed(reason) => reason.packet_semantics(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn policy_closed(self) -> bool {
        matches!(self, Self::PolicyClosed(_))
    }

    pub(in crate::production_runtime_owner::resident_dataplane) fn policy_closed_reason(
        self,
    ) -> Option<&'static str> {
        match self {
            Self::PolicyClosed(reason) => Some(reason.reason()),
            _ => None,
        }
    }
}

fn vless_executor_label(transport: ResidentStreamPacketTransport) -> &'static str {
    match transport {
        ResidentStreamPacketTransport::PlainTcp => "resident-vless-udp-over-plain-tcp",
        ResidentStreamPacketTransport::TlsTcp => "resident-vless-udp-over-tls",
        ResidentStreamPacketTransport::TcpHttpHeaderPlain
        | ResidentStreamPacketTransport::TcpHttpHeaderTls => "vless-transport-udp-policy-closed",
        ResidentStreamPacketTransport::WebSocketPlain => "resident-vless-udp-over-websocket-plain",
        ResidentStreamPacketTransport::WebSocketTls => "resident-vless-udp-over-websocket",
        ResidentStreamPacketTransport::HttpUpgradePlain => {
            "resident-vless-udp-over-httpupgrade-plain"
        }
        ResidentStreamPacketTransport::HttpUpgradeTls => "resident-vless-udp-over-httpupgrade",
        ResidentStreamPacketTransport::GrpcTls => "resident-vless-udp-over-grpc",
        ResidentStreamPacketTransport::H2Tls => "resident-vless-udp-over-h2",
        ResidentStreamPacketTransport::XhttpH1 => "resident-vless-xhttp-h1-packet",
        ResidentStreamPacketTransport::XhttpH2 => "resident-vless-xhttp-h2-packet",
        ResidentStreamPacketTransport::XhttpH3 => "resident-vless-xhttp-h3-packet",
    }
}

fn trojan_executor_label(transport: ResidentStreamPacketTransport) -> &'static str {
    match transport {
        ResidentStreamPacketTransport::TlsTcp => "resident-trojan-udp-over-tcp",
        ResidentStreamPacketTransport::TcpHttpHeaderPlain
        | ResidentStreamPacketTransport::TcpHttpHeaderTls => "trojan-transport-udp-policy-closed",
        ResidentStreamPacketTransport::WebSocketTls => "resident-trojan-udp-over-websocket",
        ResidentStreamPacketTransport::HttpUpgradeTls => "resident-trojan-udp-over-httpupgrade",
        ResidentStreamPacketTransport::GrpcTls => "resident-trojan-udp-over-grpc",
        _ => "trojan-transport-udp-policy-closed",
    }
}

fn vmess_executor_label(transport: ResidentStreamPacketTransport) -> &'static str {
    match transport {
        ResidentStreamPacketTransport::PlainTcp => "resident-vmess-udp-over-plain-tcp",
        ResidentStreamPacketTransport::TlsTcp => "resident-vmess-udp-over-tls",
        ResidentStreamPacketTransport::TcpHttpHeaderPlain => {
            "resident-vmess-udp-over-tcp-http-header-plain"
        }
        ResidentStreamPacketTransport::TcpHttpHeaderTls => {
            "resident-vmess-udp-over-tcp-http-header-tls"
        }
        ResidentStreamPacketTransport::WebSocketPlain => "resident-vmess-udp-over-websocket-plain",
        ResidentStreamPacketTransport::WebSocketTls => "resident-vmess-udp-over-websocket",
        ResidentStreamPacketTransport::HttpUpgradePlain => {
            "resident-vmess-udp-over-httpupgrade-plain"
        }
        ResidentStreamPacketTransport::HttpUpgradeTls => "resident-vmess-udp-over-httpupgrade",
        ResidentStreamPacketTransport::GrpcTls => "resident-vmess-udp-over-grpc",
        _ => "vmess-transport-udp-policy-closed",
    }
}
