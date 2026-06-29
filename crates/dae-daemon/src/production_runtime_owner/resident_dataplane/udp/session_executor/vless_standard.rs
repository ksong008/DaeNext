use super::*;
use std::future::poll_fn;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

use super::vless::vless_udp_length_frame;

#[derive(Clone, Copy)]
pub(super) enum VlessStandardUdpWrapperKind {
    PlainTcp,
    TlsTcp,
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct VlessStandardUdpOverStreamSession
{
    wrapper: VlessStandardUdpWrapperKind,
    underlay: Option<VlessStandardUdpUnderlay>,
    seq: u64,
    response_header_seen: bool,
    response_plaintext: Vec<u8>,
}

impl VlessStandardUdpOverStreamSession {
    pub(super) fn plain() -> Self {
        Self::new(VlessStandardUdpWrapperKind::PlainTcp)
    }

    pub(super) fn tls() -> Self {
        Self::new(VlessStandardUdpWrapperKind::TlsTcp)
    }

    fn new(wrapper: VlessStandardUdpWrapperKind) -> Self {
        Self {
            wrapper,
            underlay: None,
            seq: 0,
            response_header_seen: false,
            response_plaintext: Vec::new(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if !proxy.flow.is_empty() {
            return Err(
                "VLESS standard UDP-over-stream requires an empty flow; Vision uses XUDP"
                    .to_owned(),
            );
        }
        let key = proxy.vless_key()?;
        let request = if self.seq == 0 {
            packet::first_write_bytes(
                &key,
                &proxy.flow,
                "udp",
                &original_dst.to_string(),
                false,
                payload,
            )
            .map_err(|err| format!("build VLESS standard UDP first packet: {err}"))?
        } else {
            vless_udp_length_frame(payload)?
        };
        if self.underlay.is_some() {
            self.write_packet(&request).await?;
        } else {
            self.open_with_initial_packet(proxy, &request).await?;
        }
        self.seq = self.seq.saturating_add(1);
        if let Some(response) = self.poll_response().await? {
            Ok(response)
        } else {
            Ok(self.pending_response_result())
        }
    }

    async fn open_with_initial_packet(
        &mut self,
        proxy: &ResidentProxyPlan,
        initial_packet: &[u8],
    ) -> Result<(), String> {
        self.response_header_seen = false;
        self.response_plaintext.clear();
        let underlay = match self.wrapper {
            VlessStandardUdpWrapperKind::PlainTcp => {
                let mut stream = open_proxy_tcp_stream_async(proxy).await?;
                write_vless_stream_bytes(
                    &mut stream,
                    initial_packet,
                    "write VLESS plain UDP-over-stream first packet",
                )
                .await?;
                VlessStandardUdpUnderlay::PlainTcp { stream }
            }
            VlessStandardUdpWrapperKind::TlsTcp => {
                let mut client = open_async_resident_tls_client(proxy).await?;
                let tls_underlay = async_resident_tls_underlay_name(&client);
                write_vless_stream_bytes(
                    &mut client,
                    initial_packet,
                    "write VLESS TLS UDP-over-stream first packet",
                )
                .await?;
                VlessStandardUdpUnderlay::TlsTcp {
                    client,
                    tls_underlay,
                }
            }
        };
        self.underlay = Some(underlay);
        Ok(())
    }

    async fn write_packet(&mut self, payload: &[u8]) -> Result<(), String> {
        let underlay = self
            .underlay
            .as_mut()
            .ok_or_else(|| "VLESS standard UDP underlay is not initialized".to_owned())?;
        match underlay {
            VlessStandardUdpUnderlay::PlainTcp { stream } => {
                write_vless_stream_bytes(
                    stream,
                    payload,
                    "write VLESS plain UDP-over-stream packet",
                )
                .await
            }
            VlessStandardUdpUnderlay::TlsTcp { client, .. } => {
                write_vless_stream_bytes(client, payload, "write VLESS TLS UDP-over-stream packet")
                    .await
            }
        }
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        let Some(underlay) = self.underlay.as_mut() else {
            return Ok(None);
        };
        let mut buf = [0_u8; 8192];
        let Some(read) = poll_vless_standard_underlay(underlay, &mut buf).await? else {
            return Ok(None);
        };
        if read == 0 {
            return Ok(None);
        }
        self.response_plaintext.extend_from_slice(&buf[..read]);
        self.try_pop_response_payload()
            .map(|payload| payload.map(|payload| self.response_result(payload)))
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        if !self.response_header_seen {
            if self.response_plaintext.len() < 2 {
                return Ok(None);
            }
            if self.response_plaintext[0] != VLESS_RESPONSE_VERSION {
                return Err(format!(
                    "unexpected VLESS standard UDP response version: {}",
                    self.response_plaintext[0]
                ));
            }
            let header_len = 2 + self.response_plaintext[1] as usize;
            if self.response_plaintext.len() < header_len {
                return Ok(None);
            }
            self.response_plaintext.drain(..header_len);
            self.response_header_seen = true;
        }
        if self.response_plaintext.len() < 2 {
            return Ok(None);
        }
        let payload_len =
            u16::from_be_bytes([self.response_plaintext[0], self.response_plaintext[1]]) as usize;
        if self.response_plaintext.len() < 2 + payload_len {
            return Ok(None);
        }
        self.response_plaintext.drain(..2);
        Ok(Some(self.response_plaintext.drain(..payload_len).collect()))
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        let (session_executor, underlay_reuse, tls_underlay) = self.evidence_fields();
        let mut result = UdpExchangeResult::new(payload, "vless-udp-over-stream")
            .with_session_executor(session_executor)
            .with_underlay_reuse(underlay_reuse);
        if let Some(tls_underlay) = tls_underlay {
            result = result.with_tls_underlay(tls_underlay);
        }
        result
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        let (session_executor, underlay_reuse, tls_underlay) = self.evidence_fields();
        let mut result = UdpExchangeResult::pending_response("vless-udp-over-stream")
            .with_session_executor(session_executor)
            .with_underlay_reuse(underlay_reuse);
        if let Some(tls_underlay) = tls_underlay {
            result = result.with_tls_underlay(tls_underlay);
        }
        result
    }

    fn evidence_fields(&self) -> (&'static str, &'static str, Option<&'static str>) {
        self.underlay
            .as_ref()
            .map(VlessStandardUdpUnderlay::evidence_fields)
            .unwrap_or(("tokio-stream-session", "stream-reused", None))
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(mut underlay) = self.underlay.take() {
            underlay.shutdown().await;
        }
        self.response_plaintext.clear();
    }
}

enum VlessStandardUdpUnderlay {
    PlainTcp {
        stream: tokio::net::TcpStream,
    },
    TlsTcp {
        client: AsyncResidentTlsClient,
        tls_underlay: &'static str,
    },
}

impl VlessStandardUdpUnderlay {
    fn evidence_fields(&self) -> (&'static str, &'static str, Option<&'static str>) {
        match self {
            Self::PlainTcp { .. } => ("tokio-stream-session", "tcp-stream-reused", None),
            Self::TlsTcp { tls_underlay, .. } => (
                "tokio-stream-session",
                "tls-tcp-stream-reused",
                Some(*tls_underlay),
            ),
        }
    }

    async fn shutdown(&mut self) {
        match self {
            Self::PlainTcp { stream } => {
                let _ = stream.shutdown().await;
            }
            Self::TlsTcp { client, .. } => {
                client.shutdown().await;
            }
        }
    }
}

async fn poll_vless_standard_underlay(
    underlay: &mut VlessStandardUdpUnderlay,
    out: &mut [u8],
) -> Result<Option<usize>, String> {
    let mut read_buf = ReadBuf::new(out);
    poll_fn(|cx| {
        let poll_result = match underlay {
            VlessStandardUdpUnderlay::PlainTcp { stream } => {
                Pin::new(stream).poll_read(cx, &mut read_buf)
            }
            VlessStandardUdpUnderlay::TlsTcp { client, .. } => {
                Pin::new(client).poll_read(cx, &mut read_buf)
            }
        };
        match poll_result {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
            Poll::Ready(Err(err))
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                Poll::Ready(Ok(None))
            }
            Poll::Ready(Err(err)) => {
                Poll::Ready(Err(format!("read VLESS standard UDP underlay: {err}")))
            }
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}

async fn write_vless_stream_bytes<S>(
    stream: &mut S,
    payload: &[u8],
    label: &str,
) -> Result<(), String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        stream
            .write_all(payload)
            .await
            .map_err(|err| format!("{label}: {err}"))?;
        stream
            .flush()
            .await
            .map_err(|err| format!("flush {label}: {err}"))
    })
    .await
    .map_err(|_| format!("{label} timeout"))?
}
