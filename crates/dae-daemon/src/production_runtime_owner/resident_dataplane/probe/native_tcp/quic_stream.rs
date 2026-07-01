use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use dae_outbound::{
    hysteria2::{
        authenticate_hysteria2_connection, build_hysteria2_runtime_client_config,
        read_hysteria2_tcp_response, write_hysteria2_tcp_request,
    },
    juicity::{
        JuicityAuthStream, authenticate_juicity_connection, build_juicity_runtime_client_config,
        write_juicity_tcp_request,
    },
    tuic::{
        authenticate_tuic_connection, build_tuic_runtime_client_config, write_tuic_connect_request,
    },
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::super::plan::{ResidentProxyPlan, ResidentProxyProtocolPlan};
use super::super::super::tcp::{
    open_marked_hysteria2_quic_endpoint_for_remote, open_marked_quic_endpoint_for_remote,
    resolve_hysteria2_quic_remote_async, resolve_proxy_udp_addr_async,
};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::NativeTcpTunnel;

pub(super) async fn open_quic_stream_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    match selection.proxy.handler.clone() {
        ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            allow_insecure,
            pin_sha256,
            max_rx,
            obfs,
            port_hop_ports,
        } => {
            let remote = resolve_hysteria2_quic_remote_async(&selection.proxy, &port_hop_ports)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let mut endpoint =
                open_marked_hysteria2_quic_endpoint_for_remote(selection.mark, &obfs, remote)
                    .map_err(NativeTcpProbeError::Open)?;
            endpoint.set_default_client_config(
                build_hysteria2_runtime_client_config(allow_insecure, pin_sha256).map_err(
                    |err| {
                        NativeTcpProbeError::Open(format!(
                            "build native Hysteria2 QUIC client config: {err}"
                        ))
                    },
                )?,
            );
            let connection = endpoint
                .connect(remote, &selection.proxy.server_name)
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("connect native Hysteria2 endpoint: {err}"))
                })?
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("await native Hysteria2 connect: {err}"))
                })?;
            let auth_report = authenticate_hysteria2_connection(connection.clone(), &auth, max_rx)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "authenticate native Hysteria2 connection: {err}"
                    ))
                })?;
            if !auth_report.auth_ok {
                connection.close(0x101_u32.into(), b"native hysteria2 auth failed");
                return Err(NativeTcpProbeError::Open(format!(
                    "native Hysteria2 auth status {}",
                    auth_report.status
                )));
            }
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
                connection.close(0x101_u32.into(), b"native hysteria2 tcp rejected");
                return Err(NativeTcpProbeError::Open(format!(
                    "native Hysteria2 TCP response rejected: {}",
                    response.message
                )));
            }
            Ok(Box::new(QuicStreamNativeTcpTunnel::new(
                send, recv, connection, endpoint, None,
            )))
        }
        ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid,
            password,
            alpn,
            allow_insecure,
        } => {
            let remote = resolve_proxy_udp_addr_async(&selection.proxy)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let mut endpoint = open_marked_quic_endpoint_for_remote(selection.mark, remote)
                .map_err(NativeTcpProbeError::Open)?;
            endpoint.set_default_client_config(
                build_tuic_runtime_client_config(&alpn, allow_insecure).map_err(|err| {
                    NativeTcpProbeError::Open(format!("build native TUIC client config: {err}"))
                })?,
            );
            let connection = endpoint
                .connect(remote, &selection.proxy.server_name)
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("connect native TUIC endpoint: {err}"))
                })?
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("await native TUIC connect: {err}"))
                })?;
            authenticate_tuic_connection(&connection, &uuid, &password)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("authenticate native TUIC connection: {err}"))
                })?;
            let (mut send, recv) = connection.open_bi().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("open native TUIC TCP stream: {err}"))
            })?;
            write_tuic_connect_request(&mut send, target)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native TUIC TCP connect: {err}"))
                })?;
            Ok(Box::new(QuicStreamNativeTcpTunnel::new(
                send, recv, connection, endpoint, None,
            )))
        }
        ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
        } => {
            let remote = resolve_proxy_udp_addr_async(&selection.proxy)
                .await
                .map_err(NativeTcpProbeError::Open)?;
            let mut endpoint = open_marked_quic_endpoint_for_remote(selection.mark, remote)
                .map_err(NativeTcpProbeError::Open)?;
            endpoint.set_default_client_config(
                build_juicity_runtime_client_config(allow_insecure, &pinned_certchain_sha256)
                    .map_err(|err| {
                        NativeTcpProbeError::Open(format!(
                            "build native Juicity client config: {err}"
                        ))
                    })?,
            );
            let connection = endpoint
                .connect(remote, &selection.proxy.server_name)
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("connect native Juicity endpoint: {err}"))
                })?
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("await native Juicity connect: {err}"))
                })?;
            let (_, auth_stream) = authenticate_juicity_connection(&connection, &uuid, &password)
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!(
                        "authenticate native Juicity connection: {err}"
                    ))
                })?;
            let (mut send, recv) = connection.open_bi().await.map_err(|err| {
                NativeTcpProbeError::Open(format!("open native Juicity TCP stream: {err}"))
            })?;
            write_juicity_tcp_request(&mut send, target, &[])
                .await
                .map_err(|err| {
                    NativeTcpProbeError::Open(format!("write native Juicity TCP request: {err}"))
                })?;
            Ok(Box::new(QuicStreamNativeTcpTunnel::new(
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
    connection: quinn::Connection,
    endpoint: quinn::Endpoint,
    _juicity_auth_stream: Option<JuicityAuthStream>,
}

impl QuicStreamNativeTcpTunnel {
    fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection: quinn::Connection,
        endpoint: quinn::Endpoint,
        juicity_auth_stream: Option<JuicityAuthStream>,
    ) -> Self {
        Self {
            send,
            recv,
            connection,
            endpoint,
            _juicity_auth_stream: juicity_auth_stream,
        }
    }
}

impl Drop for QuicStreamNativeTcpTunnel {
    fn drop(&mut self) {
        self.connection
            .close(0_u32.into(), b"native tcp probe done");
        self.endpoint.close(0_u32.into(), b"native tcp probe done");
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
