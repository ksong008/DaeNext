use super::*;

mod carrier;
use self::carrier::{TrojanUdpCarrier, TrojanUdpCarrierKind};

const TROJAN_UDP_RESPONSE_BUFFER_CAPACITY: usize = UDP_DATAGRAM_RESPONSE_CAPACITY * 2;

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct TrojanUdpStreamSession {
    password: String,
    carrier_kind: TrojanUdpCarrierKind,
    carrier: Option<TrojanUdpCarrier>,
    response_plaintext: Vec<u8>,
}

impl TrojanUdpStreamSession {
    pub(super) fn tls(password: String) -> Self {
        Self::new(password, TrojanUdpCarrierKind::Tls)
    }

    pub(super) fn websocket(password: String) -> Self {
        Self::new(password, TrojanUdpCarrierKind::WebSocket)
    }

    pub(super) fn httpupgrade(password: String) -> Self {
        Self::new(password, TrojanUdpCarrierKind::HttpUpgrade)
    }

    pub(super) fn grpc(password: String) -> Self {
        Self::new(password, TrojanUdpCarrierKind::Grpc)
    }

    fn new(password: String, carrier_kind: TrojanUdpCarrierKind) -> Self {
        Self {
            password,
            carrier_kind,
            carrier: None,
            response_plaintext: Vec::new(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        let packet = trojan_packet::udp_packet(&original_dst.to_string(), payload)
            .map_err(|err| format!("build Trojan UDP packet: {err}"))?;
        let result = if let Some(carrier) = self.carrier.as_mut() {
            carrier.write_packet(&packet).await
        } else {
            let request = trojan_packet::tcp_request_header(
                &self.password,
                "udp",
                &original_dst.to_string(),
                &packet,
            )
            .map_err(|err| format!("build Trojan UDP-over-stream request: {err}"))?;
            self.carrier = Some(TrojanUdpCarrier::open(self.carrier_kind, proxy, &request).await?);
            Ok(())
        };
        if let Err(err) = result {
            self.shutdown().await;
            return Err(err);
        }
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::ReadyOnly).await
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::Wait).await
    }

    async fn read_response(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(packet) = self.try_pop_response_packet()? {
            return Ok(Some(self.response_result(packet)));
        }
        if self.carrier.is_none() && mode.waits_for_readiness() {
            return std::future::pending().await;
        }
        let Some(carrier) = self.carrier.as_mut() else {
            return Ok(None);
        };
        let Some(chunk) = carrier.read_chunk(mode).await? else {
            return Ok(None);
        };
        let new_len = self.response_plaintext.len().saturating_add(chunk.len());
        if new_len > TROJAN_UDP_RESPONSE_BUFFER_CAPACITY {
            self.shutdown().await;
            return Err(format!(
                "Trojan UDP response buffer exceeds {} bytes",
                TROJAN_UDP_RESPONSE_BUFFER_CAPACITY
            ));
        }
        self.response_plaintext.extend_from_slice(&chunk);
        self.try_pop_response_packet()
            .map(|packet| packet.map(|packet| self.response_result(packet)))
    }

    fn try_pop_response_packet(
        &mut self,
    ) -> Result<Option<dae_outbound::trojan::TrojanUdpPacket>, String> {
        let Some((packet, consumed)) =
            dae_outbound::trojan::decode_udp_packet_prefix(&self.response_plaintext)
                .map_err(|err| format!("decode Trojan UDP session response: {err}"))?
        else {
            return Ok(None);
        };
        self.response_plaintext.drain(..consumed);
        Ok(Some(packet))
    }

    fn response_result(&self, packet: dae_outbound::trojan::TrojanUdpPacket) -> UdpExchangeResult {
        let (session_executor, underlay_reuse, tls_underlay) = self.evidence_fields();
        let result = UdpExchangeResult::new(packet.payload, "tls-udp-over-tcp")
            .with_tls_underlay(tls_underlay)
            .with_session_executor(session_executor)
            .with_underlay_reuse(underlay_reuse);
        match packet.target.parse::<SocketAddr>() {
            Ok(source) => result.with_decoded_response_identity(Some(source), None),
            Err(_) => {
                result.with_rejected_response_identity(UdpResponseDropReason::MalformedIdentity)
            }
        }
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        let (session_executor, underlay_reuse, tls_underlay) = self.evidence_fields();
        UdpExchangeResult::pending_response("tls-udp-over-tcp")
            .with_tls_underlay(tls_underlay)
            .with_session_executor(session_executor)
            .with_underlay_reuse(underlay_reuse)
    }

    fn evidence_fields(&self) -> (&'static str, &'static str, &'static str) {
        self.carrier
            .as_ref()
            .map(TrojanUdpCarrier::evidence_fields)
            .unwrap_or_else(|| self.carrier_kind.evidence_fields())
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(mut carrier) = self.carrier.take() {
            carrier.shutdown().await;
        }
        self.response_plaintext.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trojan_udp_stream_session_pops_concatenated_response_packets() {
        let first = trojan_packet::udp_packet("1.2.3.4:443", b"one").unwrap();
        let second = trojan_packet::udp_packet("example.com:53", b"two").unwrap();
        let mut session = TrojanUdpStreamSession::tls("password".to_owned());
        session.response_plaintext.extend_from_slice(&first);
        session.response_plaintext.extend_from_slice(&second);

        assert_eq!(
            session
                .try_pop_response_packet()
                .unwrap()
                .map(|packet| packet.payload),
            Some(b"one".to_vec()),
        );
        assert_eq!(
            session
                .try_pop_response_packet()
                .unwrap()
                .map(|packet| packet.payload),
            Some(b"two".to_vec()),
        );
        assert_eq!(session.try_pop_response_packet().unwrap(), None);
    }

    #[test]
    fn trojan_udp_response_source_is_verified_before_forwarding() {
        let expected: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let packet = trojan_packet::udp_packet(&other.to_string(), b"response").unwrap();
        let mut session = TrojanUdpStreamSession::tls("password".to_owned());
        session.response_plaintext.extend_from_slice(&packet);
        let packet = session.try_pop_response_packet().unwrap().unwrap();
        let mut response = session.response_result(packet);
        let expectation = response.fixed_target_expectation(expected);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
        );
    }

    #[test]
    fn trojan_udp_stream_pending_result_reports_each_carrier() {
        for (session, expected_executor, expected_reuse) in [
            (
                TrojanUdpStreamSession::tls("password".to_owned()),
                "tokio-stream-session",
                "tls-stream-reused",
            ),
            (
                TrojanUdpStreamSession::websocket("password".to_owned()),
                "tokio-wrapper-stream-session",
                "tls-websocket-tunnel-reused",
            ),
            (
                TrojanUdpStreamSession::httpupgrade("password".to_owned()),
                "tokio-wrapper-stream-session",
                "tls-httpupgrade-tunnel-reused",
            ),
            (
                TrojanUdpStreamSession::grpc("password".to_owned()),
                "tokio-h2-wrapper-stream-session",
                "tls-grpc-h2-stream-reused",
            ),
        ] {
            let pending = session.pending_response_result();
            assert!(!pending.reply_forwarded);
            assert!(pending.payload_for_test().is_empty());
            assert_eq!(pending.execution_label, "tls-udp-over-tcp");
            assert_eq!(pending.session_executor, Some(expected_executor));
            assert_eq!(pending.underlay_reuse, Some(expected_reuse));
        }
    }
}
