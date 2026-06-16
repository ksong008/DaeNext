use super::*;
use std::future::poll_fn;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, ReadBuf};

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct TrojanUdpStreamSession {
    password: String,
    client: Option<AsyncResidentTlsClient>,
    opened: bool,
    tls_underlay: Option<&'static str>,
    response_plaintext: Vec<u8>,
}

impl TrojanUdpStreamSession {
    pub(super) fn new(password: String) -> Self {
        Self {
            password,
            client: None,
            opened: false,
            tls_underlay: None,
            response_plaintext: Vec::new(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if self.client.is_none() {
            let client = open_async_resident_tls_client(proxy).await?;
            self.tls_underlay = Some(async_resident_tls_underlay_name(&client));
            self.client = Some(client);
        }
        let packet = trojan_packet::udp_packet(&original_dst.to_string(), payload)
            .map_err(|err| format!("build Trojan UDP packet: {err}"))?;
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "Trojan UDP stream client is not initialized".to_owned())?;
        if self.opened {
            write_async_tls_plain_all(client, &packet, "write Trojan UDP session packet").await?;
        } else {
            let request = trojan_packet::tcp_request_header(
                &self.password,
                "udp",
                &original_dst.to_string(),
                &packet,
            )
            .map_err(|err| format!("build Trojan UDP-over-TCP request: {err}"))?;
            write_async_tls_plain_all(client, &request, "write Trojan UDP session first packet")
                .await?;
            self.opened = true;
        }
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if self.client.is_none() {
            return Ok(None);
        }
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        let mut buf = [0_u8; 2048];
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "Trojan UDP stream client is not initialized".to_owned())?;
        let mut read_buf = ReadBuf::new(&mut buf);
        let read = poll_fn(
            |cx| match Pin::new(&mut *client).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Ready(Ok(None)),
            },
        )
        .await;
        match read {
            Ok(Some(0)) | Ok(None) => Ok(None),
            Ok(Some(read)) => {
                self.response_plaintext.extend_from_slice(&buf[..read]);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(format!("read Trojan UDP session plaintext: {err}")),
        }
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some((packet, consumed)) =
            dae_outbound::trojan::decode_udp_packet_prefix(&self.response_plaintext)
                .map_err(|err| format!("decode Trojan UDP session response: {err}"))?
        else {
            return Ok(None);
        };
        self.response_plaintext.drain(..consumed);
        Ok(Some(packet.payload))
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        UdpExchangeResult::new(payload, "tls-udp-over-tcp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused")
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("tls-udp-over-tcp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused")
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.client.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trojan_udp_stream_session_pops_concatenated_response_packets() {
        let first = trojan_packet::udp_packet("1.2.3.4:443", b"one").unwrap();
        let second = trojan_packet::udp_packet("example.com:53", b"two").unwrap();
        let mut session = TrojanUdpStreamSession::new("password".to_owned());
        session.response_plaintext.extend_from_slice(&first);
        session.response_plaintext.extend_from_slice(&second);

        assert_eq!(
            session.try_pop_response_payload().unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            session.try_pop_response_payload().unwrap(),
            Some(b"two".to_vec())
        );
        assert_eq!(session.try_pop_response_payload().unwrap(), None);
    }

    #[test]
    fn trojan_udp_stream_pending_result_does_not_forward_empty_reply() {
        let session = TrojanUdpStreamSession::new("password".to_owned());
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload.is_empty());
        assert_eq!(pending.execution_label, "tls-udp-over-tcp");
    }
}
