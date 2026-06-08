use super::*;
pub(super) fn exchange_proxy_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> Result<UdpExchangeResult, String> {
    match &proxy.handler {
        ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => {
            exchange_vless_udp(proxy, original_dst, payload)
        }
        ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher,
            password,
            salt_len,
        } => exchange_shadowsocks_udp(proxy, original_dst, payload, cipher, password, *salt_len),
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
            cipher,
            password,
            packet_nonce_len,
            ..
        } => exchange_shadowsocks_2022_udp(
            proxy,
            original_dst,
            payload,
            cipher,
            password,
            *packet_nonce_len,
        ),
        ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
        | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
        | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => Err(format!(
            "unsupported_udp_handler: resident UDP adapter dispatch selected handler {} for protocol {}; SIP003 plugin wrappers are TCP stream wrappers and UDP remains fail-closed without fallback execution",
            resident_udp_handler_name(&proxy.handler),
            proxy.protocol
        )),
        ResidentProxyProtocolPlan::Socks5Tcp { username, password } => {
            exchange_socks5_udp(proxy, original_dst, payload, username, password)
        }
        ResidentProxyProtocolPlan::TrojanTcpTls { password } => {
            exchange_trojan_udp(proxy, original_dst, payload, password)
        }
        ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => Err(format!(
            "unsupported_udp_handler: resident UDP adapter dispatch selected handler {} for protocol {}; Trojan-Go inner encryption is admitted for TCP stream relay only and UDP remains fail-closed without fallback execution",
            resident_udp_handler_name(&proxy.handler),
            proxy.protocol
        )),
        ResidentProxyProtocolPlan::VmessAeadTcp { id } => {
            exchange_vmess_udp(proxy, original_dst, payload, id)
        }
        ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } => {
            exchange_anytls_udp(proxy, original_dst, payload, auth)
        }
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            pin_sha256,
            max_rx,
            port_hop_ports,
        } => exchange_hysteria2_udp(
            proxy,
            original_dst,
            payload,
            auth,
            pin_sha256,
            *max_rx,
            port_hop_ports,
        ),
        ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid,
            password,
            alpn,
            allow_insecure,
        } => exchange_tuic_udp(
            proxy,
            original_dst,
            payload,
            uuid,
            password,
            alpn,
            *allow_insecure,
        ),
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
        } => exchange_juicity_udp(
            proxy,
            original_dst,
            payload,
            uuid,
            password,
            *allow_insecure,
            pinned_certchain_sha256,
        ),
        ResidentProxyProtocolPlan::HttpProxyTcp { .. } => Err(format!(
            "unsupported_udp_handler: resident UDP adapter dispatch selected handler {} for protocol {}; HTTP CONNECT has no UDP relay semantics and is fail-closed without fallback execution",
            resident_udp_handler_name(&proxy.handler),
            proxy.protocol
        )),
    }
}
