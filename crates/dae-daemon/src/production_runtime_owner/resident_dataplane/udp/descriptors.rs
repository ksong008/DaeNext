use super::*;
pub(in crate::production_runtime_owner::resident_dataplane) fn resident_udp_handler_name(
    handler: &ResidentProxyProtocolPlan,
) -> &'static str {
    match handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => "vless-vision-tcp-tls",
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => "vless-mux-tcp-tls",
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => "socks5-tcp",
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => "http-proxy-tcp",
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => "shadowsocks-aead-tcp",
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => "shadowsocks-2022-tcp",
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. } => {
            "shadowsocks-simple-obfs-http-tcp"
        }
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. } => {
            "shadowsocks-simple-obfs-tls-tcp"
        }
        ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. } => {
            "shadowsocks-v2ray-plugin-tls-websocket-tcp"
        }
        ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
            "shadowsocks-2022-simple-obfs-http-tcp"
        }
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
            "shadowsocksr-http-simple-tcp"
        }
        ResidentProxyProtocolPlan::TrojanTcpTls { .. } => "trojan-tcp-tls",
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => {
            "trojan-inner-shadowsocks-tcp-tls"
        }
        ResidentProxyProtocolPlan::AnyTlsTcpTls { .. } => "anytls-tcp-tls",
        ResidentProxyProtocolPlan::VmessAeadTcp { .. } => "vmess-aead-tcp",
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => "hysteria2-quic-tcp",
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => "tuic-quic-tcp",
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => "juicity-quic-tcp",
    }
}

pub(super) fn udp_packet_session_value(
    proxy: &ResidentProxyPlan,
    peer: SocketAddr,
    original_dst: SocketAddr,
    handler: &str,
    packet_semantics: UdpPacketSemantics,
) -> serde_json::Value {
    packet_session_value(
        UdpPacketSessionIdentity::from_socket(proxy, peer, original_dst, packet_semantics),
        Some(handler),
    )
}

pub(super) fn udp_probe_packet_session_value(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
    handler: &str,
    packet_semantics: UdpPacketSemantics,
) -> serde_json::Value {
    packet_session_value(
        UdpPacketSessionIdentity::probe(proxy, original_dst, packet_semantics),
        Some(handler),
    )
}

pub(super) fn udp_packet_semantics_for_destination(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddr,
) -> UdpPacketSemantics {
    if original_dst.port() == 53 {
        UdpPacketSemantics::Dns
    } else {
        udp_packet_semantics(proxy)
    }
}

pub(super) fn udp_packet_semantics(proxy: &ResidentProxyPlan) -> UdpPacketSemantics {
    match &proxy.handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => {
            if proxy.net == "xhttp" && proxy.flow.is_empty() {
                UdpPacketSemantics::UdpOverStream
            } else {
                UdpPacketSemantics::Xudp
            }
        }
        ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => UdpPacketSemantics::MultiplexedStream,
        ResidentProxyProtocolPlan::Socks5Tcp { .. } => UdpPacketSemantics::UdpAssociate,
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => UdpPacketSemantics::ProtocolClosed,
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp { .. } => UdpPacketSemantics::DatagramAead,
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp { .. } => {
            UdpPacketSemantics::DatagramAead2022
        }
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
            UdpPacketSemantics::PluginUdpPolicyClosed
        }
        ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => {
            UdpPacketSemantics::LegacyUdpFailClosed
        }
        ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        | ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
        | ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        | ResidentProxyProtocolPlan::VmessAeadTcp { .. } => UdpPacketSemantics::UdpOverStream,
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => UdpPacketSemantics::QuicDatagram,
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => UdpPacketSemantics::QuicPacket,
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => UdpPacketSemantics::QuicStreamPacket,
    }
}
