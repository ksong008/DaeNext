use std::pin::Pin;
use std::task::{Context, Poll};

use dae_outbound_quic::{
    hysteria2::{read_hysteria2_tcp_response, write_hysteria2_tcp_request},
    juicity::write_juicity_tcp_request,
    tuic::write_tuic_connect_request,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::super::plan::{ResidentProxyBinding, ResidentProxyProtocolPlan};
use super::super::super::tcp::QuicEndpointCallerClass;
use super::super::super::{
    Hysteria2OwnerRegistryHandle, Hysteria2TransportLease, JuicityOwnerRegistryHandle,
    JuicityTransportLease, TuicOwnerRegistryHandle, TuicTransportLease,
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::{NativeTcpTunnel, boxed_native_tcp_tunnel};

pub(super) async fn open_quic_stream_native_tcp_tunnel(
    binding: ResidentProxyBinding,
    target: &str,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    tuic_owner_registry: Option<TuicOwnerRegistryHandle>,
    juicity_owner_registry: Option<JuicityOwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(binding, target);
    match &selection.proxy.handler {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => {
            let owner_registry = hysteria2_owner_registry.ok_or_else(|| {
                NativeTcpProbeError::OwnerAcquire(
                    "Hysteria2 transport owner registry is unavailable for native TCP probe"
                        .to_owned(),
                )
            })?;
            let transport = owner_registry
                .acquire(selection.proxy.clone(), caller, deadline)
                .await
                .map_err(NativeTcpProbeError::OwnerAcquire)?;
            let connection = transport.connection();
            let (mut send, recv) = connection.open_bi().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("open native Hysteria2 TCP stream: {err}"))
            })?;
            write_hysteria2_tcp_request(&mut send, target)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native Hysteria2 TCP request: {err}"))
                })?;
            let mut recv = recv;
            let response = read_hysteria2_tcp_response(&mut recv)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("read native Hysteria2 TCP response: {err}"))
                })?;
            if !response.ok {
                return Err(NativeTcpProbeError::Open(format!(
                    "native Hysteria2 TCP response rejected: {}",
                    response.message
                )));
            }
            Ok(boxed_native_tcp_tunnel(
                QuicStreamNativeTcpTunnel::shared_hysteria2(send, recv, transport),
            ))
        }
        ResidentProxyProtocolPlan::TuicQuicTcp { .. } => {
            let owner_registry = tuic_owner_registry.ok_or_else(|| {
                NativeTcpProbeError::OwnerAcquire(
                    "TUIC transport owner registry is unavailable for native TCP probe".to_owned(),
                )
            })?;
            let transport = owner_registry
                .acquire(selection.proxy.clone(), caller, deadline)
                .await
                .map_err(NativeTcpProbeError::OwnerAcquire)?;
            let connection = transport.connection();
            let (mut send, recv) = connection.open_bi().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("open native TUIC TCP stream: {err}"))
            })?;
            write_tuic_connect_request(&mut send, target)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native TUIC TCP connect: {err}"))
                })?;
            Ok(boxed_native_tcp_tunnel(
                QuicStreamNativeTcpTunnel::shared_tuic(send, recv, transport),
            ))
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp { .. } => {
            let owner_registry = juicity_owner_registry.ok_or_else(|| {
                NativeTcpProbeError::OwnerAcquire(
                    "Juicity transport owner registry is unavailable for native TCP probe"
                        .to_owned(),
                )
            })?;
            let transport = owner_registry
                .acquire(selection.proxy.clone(), caller, deadline)
                .await
                .map_err(NativeTcpProbeError::OwnerAcquire)?;
            let (mut send, recv) = transport
                .open_stream(deadline)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            write_juicity_tcp_request(&mut send, target, &[])
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native Juicity TCP request: {err}"))
                })?;
            Ok(boxed_native_tcp_tunnel(
                QuicStreamNativeTcpTunnel::shared_juicity(send, recv, transport),
            ))
        }
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}

struct QuicStreamNativeTcpTunnel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _owner: QuicStreamNativeTcpOwner,
}

enum QuicStreamNativeTcpOwner {
    SharedHysteria2 { _transport: Hysteria2TransportLease },
    SharedTuic { _transport: TuicTransportLease },
    SharedJuicity { _transport: JuicityTransportLease },
}

impl QuicStreamNativeTcpTunnel {
    fn shared_hysteria2(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        transport: Hysteria2TransportLease,
    ) -> Self {
        Self {
            send,
            recv,
            _owner: QuicStreamNativeTcpOwner::SharedHysteria2 {
                _transport: transport,
            },
        }
    }

    fn shared_juicity(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        transport: JuicityTransportLease,
    ) -> Self {
        Self {
            send,
            recv,
            _owner: QuicStreamNativeTcpOwner::SharedJuicity {
                _transport: transport,
            },
        }
    }

    fn shared_tuic(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        transport: TuicTransportLease,
    ) -> Self {
        Self {
            send,
            recv,
            _owner: QuicStreamNativeTcpOwner::SharedTuic {
                _transport: transport,
            },
        }
    }
}

impl AsyncRead for QuicStreamNativeTcpTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStreamNativeTcpTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}
