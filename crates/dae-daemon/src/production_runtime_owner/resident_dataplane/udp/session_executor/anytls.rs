use super::*;
pub(in crate::production_runtime_owner::resident_dataplane::udp) struct AnyTlsPacketStreamSession {
    auth: String,
    client: Option<AsyncResidentTlsClient>,
    opened: bool,
    tls_underlay: Option<&'static str>,
    response_plaintext: Vec<u8>,
    fixed_target: UdpSessionFixedTarget,
}

impl AnyTlsPacketStreamSession {
    pub(super) fn new(auth: String) -> Self {
        Self {
            auth,
            client: None,
            opened: false,
            tls_underlay: None,
            response_plaintext: Vec::new(),
            fixed_target: UdpSessionFixedTarget::default(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.fixed_target
            .bind(original_dst, "AnyTLS UDP packet stream")?;
        if self.client.is_none() {
            let mut client = open_async_resident_tls_client(proxy).await?;
            self.tls_underlay = Some(async_resident_tls_underlay_name(&client));
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::handshake_auth_bytes(&self.auth),
                "write AnyTLS auth handshake",
            )
            .await?;
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::frame(
                    anytls_contract::CMD_SETTINGS,
                    1,
                    &anytls_link::settings_bytes(),
                ),
                "write AnyTLS settings",
            )
            .await?;
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::frame(anytls_contract::CMD_SYN, 1, &[]),
                "write AnyTLS SYN",
            )
            .await?;
            let stream_target = anytls_link::udp_stream_target(&original_dst.to_string())
                .map_err(|err| format!("build AnyTLS UDP stream target: {err}"))?;
            let stream_target_addr = anytls_link::socks_addr(&stream_target)
                .map_err(|err| format!("build AnyTLS UDP stream address: {err}"))?;
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::frame(anytls_contract::CMD_PSH, 1, &stream_target_addr),
                "write AnyTLS UDP stream target",
            )
            .await?;
            self.client = Some(client);
        }
        let packet = if self.opened {
            anytls_link::packet_next_write(payload)
        } else {
            anytls_link::packet_first_write(&original_dst.to_string(), payload)
                .map_err(|err| format!("build AnyTLS UDP first packet write: {err}"))?
        };
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "AnyTLS packet stream client is not initialized".to_owned())?;
        write_async_tls_plain_all(
            client,
            &anytls_link::frame(anytls_contract::CMD_PSH, 1, &packet),
            "write AnyTLS UDP packet",
        )
        .await?;
        if !self.opened {
            wait_anytls_udp_synack_async(client).await?;
            self.opened = true;
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
        if self.client.is_none() && mode.waits_for_readiness() {
            return std::future::pending().await;
        }
        let mut buf = [0_u8; 2048];
        let Some(client) = self.client.as_mut() else {
            return Ok(None);
        };
        match read_udp_stream_once(
            client,
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
        loop {
            if self.response_plaintext.len() < anytls_contract::HEADER_OVERHEAD_SIZE {
                return Ok(None);
            }
            let header = &self.response_plaintext[..anytls_contract::HEADER_OVERHEAD_SIZE];
            let cmd = header[0];
            let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let len = u16::from_be_bytes([header[5], header[6]]) as usize;
            let frame_len = anytls_contract::HEADER_OVERHEAD_SIZE + len;
            if self.response_plaintext.len() < frame_len {
                return Ok(None);
            }
            let data =
                self.response_plaintext[anytls_contract::HEADER_OVERHEAD_SIZE..frame_len].to_vec();
            self.response_plaintext.drain(..frame_len);
            if cmd == anytls_contract::CMD_PSH && sid == 1 {
                let packet = dae_outbound::anytls::decode_packet_next_write(&data)
                    .map_err(|err| format!("decode AnyTLS UDP response packet: {err}"))?;
                return Ok(Some(packet.payload));
            }
            if cmd == anytls_contract::CMD_ALERT {
                return Err(format!("AnyTLS UDP alert frame: {len} bytes"));
            }
            if matches!(
                cmd,
                anytls_contract::CMD_WASTE
                    | anytls_contract::CMD_SERVER_SETTINGS
                    | anytls_contract::CMD_UPDATE_PADDING
                    | anytls_contract::CMD_HEART_RESPONSE
            ) {
                continue;
            }
            return Err(format!(
                "unexpected AnyTLS UDP response frame: cmd={cmd} sid={sid} len={len}"
            ));
        }
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
        if let Some(client) = self.client.as_mut() {
            let _ = write_async_tls_plain_all(
                client,
                &anytls_link::frame(anytls_contract::CMD_FIN, 1, &[]),
                "write AnyTLS UDP FIN",
            )
            .await;
            client.shutdown().await;
        }
        self.client.take();
        self.response_plaintext.clear();
        self.fixed_target.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anytls_udp_stream_pending_result_does_not_forward_empty_reply() {
        let session = AnyTlsPacketStreamSession::new("auth".to_owned());
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload_for_test().is_empty());
        assert_eq!(pending.execution_label, "frame-tls-udp-packet-stream");
        assert_eq!(pending.session_executor, Some("tokio-stream-session"));
        assert_eq!(pending.underlay_reuse, Some("tls-frame-stream-reused"));
    }

    #[test]
    fn anytls_udp_stream_pops_concatenated_response_frames() {
        let first = anytls_link::frame(
            anytls_contract::CMD_PSH,
            1,
            &anytls_link::packet_next_write(b"one"),
        );
        let second = anytls_link::frame(
            anytls_contract::CMD_PSH,
            1,
            &anytls_link::packet_next_write(b"two"),
        );
        let mut session = AnyTlsPacketStreamSession::new("auth".to_owned());
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
        let mut session = AnyTlsPacketStreamSession::new("auth".to_owned());
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
}
