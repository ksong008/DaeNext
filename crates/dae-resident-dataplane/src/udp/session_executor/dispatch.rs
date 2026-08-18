use super::*;

impl UdpSessionExecutor {
    pub(in crate::udp) async fn execute(
        &mut self,
        dns: &ResidentDnsDispatcher,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<(ResidentEventKind, UdpExchangeResult), String> {
        match self {
            Self::Dns => dns
                .query_udp(original_dst, payload)
                .await
                .map(|response| resident_dns_udp_exchange_result(original_dst, response)),
            _ => {
                self.execute_proxy_packet(binding, original_dst, payload)
                    .await
            }
        }
    }

    pub(in crate::udp) async fn execute_proxy_packet(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<(ResidentEventKind, UdpExchangeResult), String> {
        let proxy = binding.plan();
        match self {
            Self::Dns => Err(
                "resident DNS UDP executor cannot be used as a proxy packet executor".to_owned(),
            ),
            Self::ShadowsocksAead(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::Shadowsocks2022(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::Socks5(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::VlessVision(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::VlessStandard(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::VlessXhttpH2(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::VlessXhttpH3(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::Trojan(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::VmessAead(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::AnyTls(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::Hysteria2(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::Tuic(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::Juicity(session) => session
                .exchange(binding, original_dst, payload)
                .await
                .map(|response| (ResidentEventKind::UdpPacketFinished, response)),
            Self::FailClosed { reason } => Err(format!(
                "unsupported_udp_handler: {reason}; handler={}; protocol={}; policy-closed without alternate execution",
                resident_udp_proxy_handler_name(proxy),
                proxy.protocol,
            )),
        }
    }

    pub(in crate::udp) async fn shutdown(&mut self) {
        match self {
            Self::Hysteria2(session) => session.shutdown().await,
            Self::Tuic(session) => session.shutdown().await,
            Self::Juicity(session) => session.shutdown().await,
            Self::VmessAead(session) => session.shutdown().await,
            Self::Trojan(session) => session.shutdown().await,
            Self::AnyTls(session) => session.shutdown().await,
            Self::VlessVision(session) => session.shutdown().await,
            Self::VlessStandard(session) => session.shutdown().await,
            Self::VlessXhttpH2(session) => session.shutdown().await,
            Self::VlessXhttpH3(session) => session.shutdown().await,
            Self::Dns
            | Self::ShadowsocksAead(_)
            | Self::Shadowsocks2022(_)
            | Self::Socks5(_)
            | Self::FailClosed { .. } => {}
        }
    }

    pub(in crate::udp) async fn poll_response(
        &mut self,
    ) -> Result<Option<(ResidentEventKind, UdpExchangeResult)>, String> {
        match self {
            Self::ShadowsocksAead(session) => session.poll_response().map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::Shadowsocks2022(session) => session.poll_response().map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::Socks5(session) => session.poll_response().map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::VlessVision(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::VlessStandard(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::VlessXhttpH2(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::VlessXhttpH3(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::Trojan(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::Hysteria2(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::Tuic(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::AnyTls(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::VmessAead(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::Juicity(session) => session.poll_response().await.map(|response| {
                response.map(|response| (ResidentEventKind::UdpPacketFinished, response))
            }),
            Self::Dns | Self::FailClosed { .. } => Ok(None),
        }
    }
}
