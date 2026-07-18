use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use dae_outbound::{
    hysteria2::{read_hysteria2_tcp_response, write_hysteria2_tcp_request},
    juicity::{JuicityAuthStream, authenticate_juicity_connection, write_juicity_tcp_request},
    tuic::{authenticate_tuic_connection, write_tuic_connect_request},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::super::RESIDENT_CONNECT_TIMEOUT;
use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::super::tcp::{
    ObservedQuicEndpoint, QuicEndpointCallerClass, ResidentConnectedQuicEndpoint,
    open_juicity_quic_connection_candidates_async, open_tuic_quic_connection_candidates_async,
};
use super::super::super::{Hysteria2OwnerRegistryHandle, Hysteria2TransportLease};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::NativeTcpTunnel;

pub(super) async fn open_quic_stream_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
    hysteria2_owner_registry: Option<Hysteria2OwnerRegistryHandle>,
    caller: QuicEndpointCallerClass,
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    match selection.proxy.handler.clone() {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. } => {
            let owner_registry = hysteria2_owner_registry.ok_or_else(|| {
                NativeTcpProbeError::Open(
                    "Hysteria2 transport owner registry is unavailable for native TCP probe"
                        .to_owned(),
                )
            })?;
            let transport = owner_registry
                .acquire(Arc::clone(&selection.proxy), caller, deadline)
                .await
                .map_err(NativeTcpProbeError::Open)?;
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
            Ok(Box::new(QuicStreamNativeTcpTunnel::shared_hysteria2(
                send, recv, transport,
            )))
        }
        ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid,
            password,
            alpn,
            allow_insecure,
        } => {
            let ResidentConnectedQuicEndpoint {
                endpoint,
                connection,
                ..
            } = open_tuic_quic_connection_candidates_async(
                &selection.proxy,
                selection.mark,
                &alpn,
                allow_insecure,
                RESIDENT_CONNECT_TIMEOUT,
                caller,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            authenticate_tuic_connection(&connection, &uuid, &password)
                .await
                .map_err(|err| {
                    endpoint.mark_failed();
                    NativeTcpProbeError::Open(format!("authenticate native TUIC connection: {err}"))
                })?;
            endpoint.mark_ready();
            let (mut send, recv) = connection.open_bi().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("open native TUIC TCP stream: {err}"))
            })?;
            write_tuic_connect_request(&mut send, target)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native TUIC TCP connect: {err}"))
                })?;
            Ok(Box::new(QuicStreamNativeTcpTunnel::dedicated(
                send, recv, connection, endpoint, None,
            )))
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
        } => {
            let ResidentConnectedQuicEndpoint {
                endpoint,
                connection,
                ..
            } = open_juicity_quic_connection_candidates_async(
                &selection.proxy,
                selection.mark,
                allow_insecure,
                &pinned_certchain_sha256,
                RESIDENT_CONNECT_TIMEOUT,
                caller,
            )
            .await
            .map_err(NativeTcpProbeError::Open)?;
            let (_, auth_stream) = authenticate_juicity_connection(&connection, &uuid, &password)
                .await
                .map_err(|err| {
                    endpoint.mark_failed();
                    NativeTcpProbeError::Open(format!(
                        "authenticate native Juicity connection: {err}"
                    ))
                })?;
            endpoint.mark_ready();
            let (mut send, recv) = connection.open_bi().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("open native Juicity TCP stream: {err}"))
            })?;
            write_juicity_tcp_request(&mut send, target, &[])
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native Juicity TCP request: {err}"))
                })?;
            Ok(Box::new(QuicStreamNativeTcpTunnel::dedicated(
                send,
                recv,
                connection,
                endpoint,
                Some(auth_stream),
            )))
        }
        _ => Err(NativeTcpProbeError::NotAdmitted),
    }
}

struct QuicStreamNativeTcpTunnel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    owner: QuicStreamNativeTcpOwner,
}

enum QuicStreamNativeTcpOwner {
    SharedHysteria2 {
        _transport: Hysteria2TransportLease,
    },
    Dedicated {
        connection: quinn::Connection,
        endpoint: ObservedQuicEndpoint,
        _juicity_auth_stream: Option<JuicityAuthStream>,
    },
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
            owner: QuicStreamNativeTcpOwner::SharedHysteria2 {
                _transport: transport,
            },
        }
    }

    fn dedicated(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection: quinn::Connection,
        endpoint: ObservedQuicEndpoint,
        juicity_auth_stream: Option<JuicityAuthStream>,
    ) -> Self {
        Self {
            send,
            recv,
            owner: QuicStreamNativeTcpOwner::Dedicated {
                connection,
                endpoint,
                _juicity_auth_stream: juicity_auth_stream,
            },
        }
    }
}

impl Drop for QuicStreamNativeTcpTunnel {
    fn drop(&mut self) {
        if let QuicStreamNativeTcpOwner::Dedicated {
            connection,
            endpoint,
            ..
        } = &self.owner
        {
            connection.close(0_u32.into(), b"native tcp probe done");
            endpoint.close(0_u32.into(), b"native tcp probe done");
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
