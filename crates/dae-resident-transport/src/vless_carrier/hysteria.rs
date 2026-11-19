use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use dae_resident_core::RESIDENT_CONNECT_TIMEOUT;
use dae_resident_model::ResidentProxyBinding;
use dae_runtime_control::AbsoluteDeadline;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Hysteria2OwnerRegistryHandle, Hysteria2TransportLease, QuicEndpointCallerClass};

pub(super) async fn open(
    binding: &ResidentProxyBinding,
    registry: &Hysteria2OwnerRegistryHandle,
    caller: QuicEndpointCallerClass,
) -> Result<HysteriaCarrier, String> {
    if binding.chain_parent.is_some() {
        return Err("VLESS Hysteria does not support proxy chains".to_owned());
    }
    let deadline = AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT);
    let lease = registry.acquire(binding.clone(), caller, deadline).await?;
    let remaining = deadline
        .remaining_at(Instant::now())
        .ok_or("VLESS Hysteria stream deadline elapsed")?;
    let (send, recv) = tokio::time::timeout(remaining, async {
        let (mut send, recv) = lease
            .connection()
            .open_bi()
            .await
            .map_err(|error| format!("open VLESS Hysteria bidirectional stream: {error}"))?;
        // QUIC varint 0x401 selects the authenticated Xray TCP stream.
        send.write_all(&[0x44, 0x01])
            .await
            .map_err(|error| format!("write VLESS Hysteria stream type: {error}"))?;
        Ok::<_, String>((send, recv))
    })
    .await
    .map_err(|_| "VLESS Hysteria stream deadline elapsed".to_owned())??;
    Ok(HysteriaCarrier {
        send,
        recv,
        _lease: lease,
    })
}

pub(super) struct HysteriaCarrier {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _lease: Hysteria2TransportLease,
}

impl AsyncRead for HysteriaCarrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buffer)
    }
}

impl AsyncWrite for HysteriaCarrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
