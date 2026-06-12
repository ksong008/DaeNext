use super::*;

impl UdpSessionExecutor {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn execute(
        &mut self,
        dns: &ResidentDnsPlan,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<(&'static str, UdpExchangeResult), String> {
        match self {
            Self::Dns => handle_resident_dns_udp_async(dns, original_dst, payload)
                .await
                .map(|response| {
                    (
                        "udp_dns_packet_finished",
                        UdpExchangeResult::new(response, "resident-dns-udp")
                            .with_session_executor("tokio-dns-datagram")
                            .with_underlay_reuse("not-required-independent-datagram"),
                    )
                }),
            Self::ShadowsocksAead(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Shadowsocks2022(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Socks5(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::VlessVision(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Trojan(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::VmessAead(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::AnyTls(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Hysteria2(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Tuic(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Juicity(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::FailClosed { reason } => Err(format!(
                "unsupported_udp_handler: {reason}; handler={}; protocol={}; policy-closed without alternate execution",
                resident_udp_handler_name(&proxy.handler),
                proxy.protocol,
            )),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn shutdown(&mut self) {
        match self {
            Self::Hysteria2(session) => session.shutdown().await,
            Self::Tuic(session) => session.shutdown().await,
            Self::Juicity(session) => session.shutdown().await,
            Self::VmessAead(session) => session.shutdown().await,
            Self::Trojan(session) => session.shutdown().await,
            Self::AnyTls(session) => session.shutdown().await,
            Self::VlessVision(session) => session.shutdown().await,
            Self::Dns
            | Self::ShadowsocksAead(_)
            | Self::Shadowsocks2022(_)
            | Self::Socks5(_)
            | Self::FailClosed { .. } => {}
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn poll_response(
        &mut self,
    ) -> Result<Option<(&'static str, UdpExchangeResult)>, String> {
        match self {
            Self::VlessVision(session) => session
                .poll_response()
                .await
                .map(|response| response.map(|response| ("udp_packet_finished", response))),
            Self::Dns
            | Self::ShadowsocksAead(_)
            | Self::Shadowsocks2022(_)
            | Self::Socks5(_)
            | Self::Trojan(_)
            | Self::VmessAead(_)
            | Self::AnyTls(_)
            | Self::Hysteria2(_)
            | Self::Tuic(_)
            | Self::Juicity(_)
            | Self::FailClosed { .. } => Ok(None),
        }
    }
}
