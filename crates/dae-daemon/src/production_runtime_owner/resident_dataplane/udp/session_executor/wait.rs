use super::*;

impl UdpSessionExecutor {
    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn wait_response(
        &mut self,
    ) -> Result<Option<(ResidentEventKind, UdpExchangeResult)>, String> {
        let response = match self {
            Self::ShadowsocksAead(session) => Some(session.wait_response().await?),
            Self::Shadowsocks2022(session) => Some(session.wait_response().await?),
            Self::Socks5(session) => Some(session.wait_response().await?),
            Self::Hysteria2(session) => session.wait_response().await?,
            Self::Tuic(session) => session.wait_response().await?,
            Self::VlessVision(session) => session.wait_response().await?,
            Self::VlessStandard(session) => session.wait_response().await?,
            Self::VlessXhttpH2(session) => session.wait_response().await?,
            Self::VlessXhttpH3(session) => session.wait_response().await?,
            Self::Trojan(session) => session.wait_response().await?,
            Self::AnyTls(session) => session.wait_response().await?,
            Self::VmessAead(session) => session.wait_response().await?,
            Self::Dns | Self::Juicity(_) | Self::FailClosed { .. } => {
                return std::future::pending().await;
            }
        };
        Ok(response.map(|response| (ResidentEventKind::UdpPacketFinished, response)))
    }

    pub(in crate::production_runtime_owner::resident_dataplane::udp) async fn wait_response_with_timeout(
        &mut self,
        timeout: Duration,
        label: &str,
    ) -> Result<(ResidentEventKind, UdpExchangeResult), String> {
        let deadline = time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(time::Instant::now());
            if remaining.is_zero() {
                return Err(format!("{label} timeout"));
            }
            match time::timeout(remaining, self.wait_response()).await {
                Ok(Ok(Some(response))) => return Ok(response),
                Ok(Ok(None)) => continue,
                Ok(Err(err)) => return Err(err),
                Err(_) => return Err(format!("{label} timeout")),
            }
        }
    }
}
