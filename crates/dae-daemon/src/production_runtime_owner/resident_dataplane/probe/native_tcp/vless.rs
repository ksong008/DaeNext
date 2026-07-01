use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use dae_outbound::vless::{contract::is_xtls_rprx_vision_flow, packet};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::super::client::{
    open_async_vless_tls_client_with_flow, open_proxy_tcp_stream_async_with_flow,
};
use super::super::super::plan::ResidentProxyPlan;
use super::super::super::{VLESS_RESPONSE_VERSION, tcp::TcpProxySelection};
use super::errors::NativeTcpProbeError;
use super::target::native_tcp_probe_selection;
use super::tunnel::NativeTcpTunnel;

pub(super) async fn open_vless_native_tcp_tunnel(
    proxy: Arc<ResidentProxyPlan>,
    target: &str,
) -> Result<Box<dyn NativeTcpTunnel>, NativeTcpProbeError> {
    let selection = native_tcp_probe_selection(proxy, target);
    if !vless_native_tcp_admitted(&selection) {
        return Err(NativeTcpProbeError::NotAdmitted);
    }
    let key = selection
        .proxy
        .vless_key()
        .map_err(NativeTcpProbeError::Open)?;
    let request = packet::first_write_bytes(&key, &selection.proxy.flow, "tcp", target, false, &[])
        .map_err(|err| {
            NativeTcpProbeError::Open(format!("build native VLESS TCP request: {err}"))
        })?;

    if matches!(selection.proxy.tls.as_str(), "" | "none") {
        let mut stream = open_proxy_tcp_stream_async_with_flow(
            &selection.proxy,
            selection.mark,
            selection.mptcp,
        )
        .await
        .map_err(NativeTcpProbeError::Open)?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &request)
            .await
            .map_err(|err| {
                NativeTcpProbeError::Open(format!("write native VLESS request: {err}"))
            })?;
        return Ok(Box::new(VlessNativeTunnel::new(stream)));
    }

    let mut client =
        open_async_vless_tls_client_with_flow(&selection.proxy, selection.mark, selection.mptcp)
            .await
            .map_err(NativeTcpProbeError::Open)?;
    client
        .write_plain_all(&request, "write native VLESS TLS request")
        .await
        .map_err(NativeTcpProbeError::Open)?;
    Ok(Box::new(VlessNativeTunnel::new(client)))
}

fn vless_native_tcp_admitted(selection: &TcpProxySelection) -> bool {
    if matches!(
        selection.proxy.net.as_str(),
        "websocket" | "httpupgrade" | "grpc" | "h2" | "meek" | "xhttp"
    ) {
        return false;
    }
    !is_xtls_rprx_vision_flow(&selection.proxy.flow)
}

struct VlessNativeTunnel<S> {
    inner: S,
    stripper: VlessResponseStripper,
    pending_plain: VecDeque<u8>,
}

impl<S> VlessNativeTunnel<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            stripper: VlessResponseStripper::default(),
            pending_plain: VecDeque::new(),
        }
    }
}

impl<S> AsyncRead for VlessNativeTunnel<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.drain_pending(buf) {
            return Poll::Ready(Ok(()));
        }

        let mut raw = [0_u8; 8192];
        let mut raw_buf = ReadBuf::new(&mut raw);
        match Pin::new(&mut self.inner).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(())) => {
                let read = raw_buf.filled().len();
                if read == 0 {
                    return Poll::Ready(Ok(()));
                }
                let plain = self
                    .stripper
                    .consume(&raw[..read])
                    .map_err(std::io::Error::other)?;
                self.pending_plain.extend(plain);
                self.drain_pending(buf);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> VlessNativeTunnel<S> {
    fn drain_pending(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let to_copy = self.pending_plain.len().min(buf.remaining());
        if to_copy == 0 {
            return false;
        }
        let contiguous = self.pending_plain.make_contiguous();
        buf.put_slice(&contiguous[..to_copy]);
        self.pending_plain.drain(..to_copy);
        true
    }
}

impl<S> AsyncWrite for VlessNativeTunnel<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct VlessResponseStripper {
    header: Vec<u8>,
    done: bool,
}

impl VlessResponseStripper {
    fn consume(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Ok(input.to_vec());
        }
        self.header.extend_from_slice(input);
        if self.header.len() < 2 {
            return Ok(Vec::new());
        }
        if self.header[0] != VLESS_RESPONSE_VERSION {
            return Err(format!(
                "unexpected VLESS response version: {}",
                self.header[0]
            ));
        }
        let header_len = 2 + self.header[1] as usize;
        if self.header.len() < header_len {
            return Ok(Vec::new());
        }
        self.done = true;
        Ok(self.header.split_off(header_len))
    }
}
