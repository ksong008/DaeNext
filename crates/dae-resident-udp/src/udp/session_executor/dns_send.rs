use super::*;
use std::{future::Future, pin::Pin};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// A single bounded send. It owns the writer and wire buffer, so waiting for
/// backpressure never borrows the session's response decoder or receive lease.
pub struct ProxyDnsUdpSend {
    pub reset_on_cancel: bool,
    pub future: Pin<Box<dyn Future<Output = ProxyDnsUdpSendCompletion> + Send>>,
}

pub struct ProxyDnsUdpSendCompletion {
    pub result: Result<(), String>,
    pub reset_session: bool,
    pub(in crate::udp) scratch: Option<Vec<u8>>,
}

impl ProxyDnsUdpSend {
    pub(in crate::udp) fn new(
        reset_on_cancel: bool,
        future: impl Future<Output = Result<(), String>> + Send + 'static,
    ) -> Self {
        Self {
            reset_on_cancel,
            future: Box::pin(async move {
                let result = future.await;
                ProxyDnsUdpSendCompletion {
                    reset_session: reset_on_cancel && result.is_err(),
                    result,
                    scratch: None,
                }
            }),
        }
    }

    pub(in crate::udp) fn stream<T: AsyncWrite + Unpin + Send + 'static>(
        mut writer: T,
        packet: Vec<u8>,
        recycle: bool,
    ) -> Self {
        Self {
            reset_on_cancel: true,
            future: Box::pin(async move {
                let result = async {
                    writer
                        .write_all(&packet)
                        .await
                        .map_err(|error| format!("write DNS UDP stream packet: {error}"))?;
                    writer
                        .flush()
                        .await
                        .map_err(|error| format!("flush DNS UDP stream packet: {error}"))
                }
                .await;
                ProxyDnsUdpSendCompletion {
                    reset_session: result.is_err(),
                    result,
                    scratch: recycle.then_some(packet),
                }
            }),
        }
    }
}

impl UdpSessionExecutor {
    pub fn dns_send_preparation_requires_reset(&self) -> bool {
        !matches!(
            self,
            Self::ShadowsocksAead(_) | Self::Shadowsocks2022(_) | Self::Socks5(_)
        )
    }

    /// `None` means the first packet must open the transport. There cannot be
    /// older pending requests until that opening operation completes.
    pub fn begin_dns_send(
        &mut self,
        binding: &ResidentProxyBinding,
        target: SocketAddr,
        payload: &[u8],
    ) -> Result<Option<ProxyDnsUdpSend>, String> {
        match self {
            Self::ShadowsocksAead(session) => session.begin_dns_send(target, payload),
            Self::Shadowsocks2022(session) => session.begin_dns_send(target, payload),
            Self::Socks5(session) => session.begin_dns_send(target, payload),
            Self::VlessStandard(session) => session.begin_dns_send(payload),
            Self::VlessVision(session) => session.begin_dns_send(payload),
            Self::VlessXhttpH2(session) => session.begin_dns_send(payload),
            Self::VlessXhttpH3(session) => session.begin_dns_send(payload),
            Self::Trojan(session) => session.begin_dns_send(target, payload),
            Self::VmessAead(session) => session.begin_dns_send(payload),
            Self::AnyTls(session) => session.begin_dns_send(payload),
            Self::Hysteria2(session) => session.begin_dns_send(payload),
            Self::Tuic(session) => session.begin_dns_send(payload),
            // Juicity DNS exchanges already have a request-scoped actor.
            Self::Juicity(_) | Self::Dns | Self::FailClosed { .. } => {
                let _ = binding;
                Ok(None)
            }
        }
    }

    pub fn finish_dns_send(&mut self, completion: &mut ProxyDnsUdpSendCompletion) {
        if let Some(buffer) = completion.scratch.take() {
            match self {
                Self::ShadowsocksAead(session) => session.restore_dns_send_buffer(buffer),
                Self::VmessAead(session) => session.restore_dns_send_buffer(buffer),
                Self::Trojan(session) => session.restore_dns_send_buffer(buffer),
                _ => {}
            }
        }
    }
}
