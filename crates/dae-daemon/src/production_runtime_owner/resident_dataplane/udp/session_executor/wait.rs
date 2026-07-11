use super::*;

impl UdpSessionExecutor {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn wait_response(
        &mut self,
    ) -> Result<Option<(&'static str, UdpExchangeResult)>, String> {
        let response = match self {
            Self::ShadowsocksAead(session) => Some(session.wait_response().await?),
            Self::Shadowsocks2022(session) => Some(session.wait_response().await?),
            Self::Socks5(session) => Some(session.wait_response().await?),
            Self::Hysteria2(session) => session.wait_response().await?,
            Self::Tuic(session) => session.wait_response().await?,
            Self::VlessVision(session) => session.wait_response().await?,
            Self::VlessStandard(session) => {
                time::sleep(RESIDENT_IDLE_SLEEP).await;
                session.poll_response().await?
            }
            Self::VlessXhttpH2(session) => {
                time::sleep(RESIDENT_IDLE_SLEEP).await;
                session.poll_response().await?
            }
            Self::VlessXhttpH3(session) => {
                time::sleep(RESIDENT_IDLE_SLEEP).await;
                session.poll_response().await?
            }
            Self::Trojan(session) => session.wait_response().await?,
            Self::AnyTls(session) => session.wait_response().await?,
            Self::VmessAead(session) => session.wait_response().await?,
            Self::Dns | Self::Juicity(_) | Self::FailClosed { .. } => {
                return std::future::pending().await;
            }
        };
        Ok(response.map(|response| ("udp_packet_finished", response)))
    }
}
