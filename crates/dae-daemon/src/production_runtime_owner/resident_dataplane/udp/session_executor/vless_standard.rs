use super::*;

use super::vless::vless_udp_length_frame;

mod underlay;
use self::underlay::{VlessStandardUdpUnderlay, VlessStandardUdpWrapperKind};

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

    pub(super) fn websocket_plain() -> Self {
        Self::new(VlessStandardUdpWrapperKind::WebSocketPlain)
    }

    pub(super) fn websocket_tls() -> Self {
        Self::new(VlessStandardUdpWrapperKind::WebSocketTls)
    }

    pub(super) fn httpupgrade_plain() -> Self {
        Self::new(VlessStandardUdpWrapperKind::HttpUpgradePlain)
    }

    pub(super) fn httpupgrade_tls() -> Self {
        Self::new(VlessStandardUdpWrapperKind::HttpUpgradeTls)
    }

    pub(super) fn grpc_tls() -> Self {
        Self::new(VlessStandardUdpWrapperKind::GrpcTls)
    }

    pub(super) fn h2_tls() -> Self {
        Self::new(VlessStandardUdpWrapperKind::H2Tls)
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
        self.underlay =
            Some(VlessStandardUdpUnderlay::open(self.wrapper, proxy, initial_packet).await?);
        Ok(())
    }

    async fn write_packet(&mut self, payload: &[u8]) -> Result<(), String> {
        self.underlay
            .as_mut()
            .ok_or_else(|| "VLESS standard UDP underlay is not initialized".to_owned())?
            .write_packet(payload)
            .await
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        let Some(underlay) = self.underlay.as_mut() else {
            return Ok(None);
        };
        let Some(chunk) = underlay.poll_response_chunk().await? else {
            return Ok(None);
        };
        if chunk.is_empty() {
            return Ok(None);
        }
        self.response_plaintext.extend_from_slice(&chunk);
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
