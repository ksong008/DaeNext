use super::*;
use tokio::io::AsyncWriteExt;
pub(in crate::udp) struct AnyTlsPacketStreamSession {
    binding: ResidentProxyBinding,
    owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    logical: Option<AnyTlsLogicalStreamLease>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
    tls_underlay: Option<&'static str>,
    response_plaintext: Vec<u8>,
    fixed_target: UdpSessionFixedTarget,
}

impl AnyTlsPacketStreamSession {
    pub(super) fn new(
        binding: ResidentProxyBinding,
        owner_registry: Option<AnyTlsOwnerRegistryHandle>,
    ) -> Self {
        Self {
            binding,
            owner_registry,
            logical: None,
            owner_deadline: None,
            tls_underlay: None,
            response_plaintext: Vec::new(),
            fixed_target: UdpSessionFixedTarget::default(),
        }
    }

    pub(super) fn set_owner_deadline(&mut self, deadline: dae_runtime_control::AbsoluteDeadline) {
        self.owner_deadline = Some(deadline);
    }

    pub(super) async fn exchange(
        &mut self,
        _proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.fixed_target
            .bind(original_dst, "AnyTLS UDP packet stream")?;
        let opening_logical_stream = self.logical.is_none();
        if opening_logical_stream {
            let initial_payload =
                anytls_link::packet_first_write(&original_dst.to_string(), payload)
                    .map_err(|err| format!("build AnyTLS UDP first packet write: {err}"))?;
            let stream_target = anytls_link::udp_stream_target(&original_dst.to_string())
                .map_err(|err| format!("build AnyTLS UDP stream target: {err}"))?;
            let owner_registry = self.owner_registry.as_ref().ok_or_else(|| {
                "AnyTLS generation transport owner is unavailable for UDP execution".to_owned()
            })?;
            let deadline = self.owner_deadline.unwrap_or_else(|| {
                dae_runtime_control::AbsoluteDeadline::from_now(
                    Instant::now(),
                    RESIDENT_UDP_RESPONSE_TIMEOUT,
                )
            });
            let logical = owner_registry
                .acquire_with_initial_payload(
                    self.binding.clone(),
                    stream_target,
                    initial_payload,
                    deadline,
                )
                .await?;
            self.tls_underlay = Some(logical.tls_underlay());
            self.logical = Some(logical);
        }
        if !opening_logical_stream {
            let packet = anytls_link::packet_next_write(payload);
            let logical = self
                .logical
                .as_mut()
                .ok_or_else(|| "AnyTLS logical packet stream is not initialized".to_owned())?;
            time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, logical.write_all(&packet))
                .await
                .map_err(|_| "write AnyTLS UDP logical packet timeout".to_owned())?
                .map_err(|error| format!("write AnyTLS UDP logical packet: {error}"))?;
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
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        if self.logical.is_none() && mode.waits_for_readiness() {
            return std::future::pending().await;
        }
        let mut buf = [0_u8; 2048];
        let Some(logical) = self.logical.as_mut() else {
            return Ok(None);
        };
        match read_udp_stream_once(
            logical,
            &mut buf,
            mode,
            "read AnyTLS UDP packet stream plaintext",
        )
        .await?
        {
            None => Ok(None),
            Some(read) => {
                self.response_plaintext.extend_from_slice(&buf[..read]);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
        }
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.response_plaintext.len() < 2 {
            return Ok(None);
        }
        let payload_len =
            u16::from_be_bytes([self.response_plaintext[0], self.response_plaintext[1]]) as usize;
        let packet_len = 2_usize.saturating_add(payload_len);
        if self.response_plaintext.len() < packet_len {
            return Ok(None);
        }
        let payload = self.response_plaintext[2..packet_len].to_vec();
        self.response_plaintext.drain(..packet_len);
        Ok(Some(payload))
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        let result = UdpExchangeResult::new(payload, "frame-tls-udp-packet-stream")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-frame-stream-reused");
        match self.fixed_target.source() {
            Some(target) => result.with_session_bound_response_identity(target, None),
            None => {
                result.with_rejected_response_identity(UdpResponseDropReason::MissingWireSource)
            }
        }
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("frame-tls-udp-packet-stream")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-frame-stream-reused")
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(logical) = self.logical.as_mut() {
            let _ = logical.shutdown().await;
        }
        self.logical.take();
        self.response_plaintext.clear();
        self.fixed_target.clear();
    }
}

#[cfg(test)]
pub(crate) struct AnyTlsUdpTestExchange {
    pub(crate) payload: Vec<u8>,
    pub(crate) sid: u32,
    pub(crate) physical_instance_id: u64,
    pub(crate) reused: bool,
}

#[cfg(test)]
pub(crate) async fn exercise_anytls_udp_stream_session(
    binding: ResidentProxyBinding,
    owner_registry: AnyTlsOwnerRegistryHandle,
    original_dst: SocketAddr,
    payload: &[u8],
    deadline: dae_runtime_control::AbsoluteDeadline,
) -> Result<AnyTlsUdpTestExchange, String> {
    let proxy = Arc::clone(binding.shared_plan());
    let mut session = AnyTlsPacketStreamSession::new(binding, Some(owner_registry));
    session.set_owner_deadline(deadline);
    let mut response = session.exchange(&proxy, original_dst, payload).await?;
    if !response.reply_forwarded {
        response = session
            .wait_response()
            .await?
            .ok_or_else(|| "AnyTLS UDP test session returned no response".to_owned())?;
    }
    let expectation = response.fixed_target_expectation(original_dst);
    let payload = response
        .take_fixed_target_payload(expectation)
        .into_payload()
        .map_err(|reason| format!("AnyTLS UDP test fixed-target rejection: {}", reason.label()))?;
    let logical = session
        .logical
        .as_ref()
        .ok_or_else(|| "AnyTLS UDP test logical lease is unavailable".to_owned())?;
    let report = AnyTlsUdpTestExchange {
        payload,
        sid: logical.sid(),
        physical_instance_id: logical.physical_instance_id(),
        reused: logical.reused(),
    };
    session.shutdown().await;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_anytls_binding() -> ResidentProxyBinding {
        let mut proxy = test_anytls_proxy();
        proxy.materialize_execution();
        ResidentProxyBinding::configuration(Arc::new(proxy))
            .expect("materialized AnyTLS UDP test binding")
    }

    #[test]
    fn anytls_udp_stream_pending_result_does_not_forward_empty_reply() {
        let session = AnyTlsPacketStreamSession::new(test_anytls_binding(), None);
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload_for_test().is_empty());
        assert_eq!(pending.execution_label, "frame-tls-udp-packet-stream");
        assert_eq!(pending.session_executor, Some("tokio-stream-session"));
        assert_eq!(pending.underlay_reuse, Some("tls-frame-stream-reused"));
    }

    #[test]
    fn anytls_udp_stream_pops_concatenated_packet_payloads() {
        let first = anytls_link::packet_next_write(b"one");
        let second = anytls_link::packet_next_write(b"two");
        let mut session = AnyTlsPacketStreamSession::new(test_anytls_binding(), None);
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
    fn anytls_udp_stream_response_is_bound_to_its_fixed_target() {
        let expected: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let mut session = AnyTlsPacketStreamSession::new(test_anytls_binding(), None);
        session
            .fixed_target
            .bind(expected, "AnyTLS UDP packet stream")
            .unwrap();
        assert!(
            session
                .fixed_target
                .bind(other, "AnyTLS UDP packet stream")
                .is_err()
        );

        let mut response = session.response_result(b"response".to_vec());
        let expectation = response.fixed_target_expectation(expected);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Validated
        );
    }

    fn test_anytls_proxy() -> ResidentProxyPlan {
        super::super::super::tests::tests::test_udp_proxy(ResidentProxyProtocolPlan::AnyTlsTcpTls {
            auth: "auth".to_owned(),
        })
    }
}
