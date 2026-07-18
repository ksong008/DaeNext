use super::*;

const SHADOWSOCKS_2022_CLIENT_SESSION_IDENTITY_DOMAIN: &[u8] = b"shadowsocks-2022-client-session";

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct ShadowsocksAeadDatagramSession
{
    cipher: String,
    password: String,
    salt_len: usize,
    relay: DatagramRelay,
}

impl ShadowsocksAeadDatagramSession {
    pub(super) fn new(cipher: String, password: String, salt_len: usize) -> Self {
        Self {
            cipher,
            password,
            salt_len,
            relay: DatagramRelay::default(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        let mut salt = vec![0_u8; self.salt_len];
        fastrand::fill(&mut salt);
        let request = encode_udp_packet(
            &self.cipher,
            &self.password,
            &salt,
            &original_dst.to_string(),
            payload,
        )
        .map_err(|err| format!("encode Shadowsocks UDP packet: {err}"))?;
        self.relay.send(proxy, &request, "Shadowsocks").await?;
        if let Some(response) = self.poll_response()? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let Some(response) = self.relay.poll_response("Shadowsocks")? else {
            return Ok(None);
        };
        self.decode_response(&response).map(Some)
    }

    pub(super) async fn wait_response(&mut self) -> Result<UdpExchangeResult, String> {
        let response = self.relay.wait_response("Shadowsocks").await?;
        self.decode_response(&response)
    }

    fn decode_response(&self, response: &[u8]) -> Result<UdpExchangeResult, String> {
        let decoded = decode_shadowsocks_udp_packet(&self.cipher, &self.password, response)
            .map_err(|err| format!("decode Shadowsocks UDP packet: {err}"))?;
        let result = UdpExchangeResult::new(decoded.payload, "udp-datagram-aead")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-reused");
        Ok(response_with_source_identity(result, &decoded.target))
    }

    pub(super) fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("udp-datagram-aead")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-reused")
    }
}

pub(in crate::production_runtime_owner::resident_dataplane::udp) struct Shadowsocks2022DatagramSession
{
    cipher: String,
    password: String,
    packet_nonce_len: usize,
    codec: Option<Ss2022UdpCodec>,
    relay: DatagramRelay,
}

impl Shadowsocks2022DatagramSession {
    pub(super) fn new(cipher: String, password: String, packet_nonce_len: usize) -> Self {
        Self {
            cipher,
            password,
            packet_nonce_len,
            codec: None,
            relay: DatagramRelay::default(),
        }
    }

    pub(super) async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if self.codec.is_none() {
            let mut session_id = [0_u8; 8];
            fastrand::fill(&mut session_id);
            self.codec = Some(
                Ss2022UdpCodec::new(&self.cipher, &self.password, session_id)
                    .map_err(|err| format!("create Shadowsocks 2022 UDP codec: {err}"))?,
            );
        }
        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| "Shadowsocks 2022 UDP codec is not initialized".to_owned())?;
        let mut packet_nonce = vec![0_u8; self.packet_nonce_len];
        if self.packet_nonce_len > 0 {
            fastrand::fill(&mut packet_nonce);
        }
        let request = codec
            .encode_client_packet(
                &original_dst.to_string(),
                payload,
                ss2022_udp_unix_timestamp_now(),
                if self.packet_nonce_len > 0 {
                    Some(packet_nonce.as_slice())
                } else {
                    None
                },
            )
            .map_err(|err| format!("encode Shadowsocks 2022 UDP packet: {err}"))?;
        self.relay
            .send(proxy, &request.wire, "Shadowsocks 2022")
            .await?;
        if let Some(response) = self.poll_response()? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    pub(super) fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let Some(response) = self.relay.poll_response("Shadowsocks 2022")? else {
            return Ok(None);
        };
        self.decode_response(&response).map(Some)
    }

    pub(super) async fn wait_response(&mut self) -> Result<UdpExchangeResult, String> {
        let response = self.relay.wait_response("Shadowsocks 2022").await?;
        self.decode_response(&response)
    }

    fn decode_response(&mut self, response: &[u8]) -> Result<UdpExchangeResult, String> {
        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| "Shadowsocks 2022 UDP codec is not initialized".to_owned())?;
        let decoded = codec
            .decode_server_packet(response, ss2022_udp_unix_timestamp_now())
            .map_err(|err| format!("decode Shadowsocks 2022 UDP packet: {err}"))?;
        let observed_identity = decoded.client_session_id.and_then(|session_id| {
            UdpResponseIdentityToken::from_protocol_identity(
                SHADOWSOCKS_2022_CLIENT_SESSION_IDENTITY_DOMAIN,
                &session_id,
            )
        });
        let result = UdpExchangeResult::new(decoded.payload, "udp-datagram-aead-2022")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-and-codec-session-reused");
        Ok(response_with_source_and_protocol_identity(
            result,
            &decoded.target,
            observed_identity,
        ))
    }

    pub(super) fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("udp-datagram-aead-2022")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-and-codec-session-reused")
    }
}

fn response_with_source_identity(result: UdpExchangeResult, target: &str) -> UdpExchangeResult {
    response_with_source_and_protocol_identity(result, target, None)
}

fn response_with_source_and_protocol_identity(
    result: UdpExchangeResult,
    target: &str,
    observed_identity: Option<UdpResponseIdentityToken>,
) -> UdpExchangeResult {
    match target.parse::<SocketAddr>() {
        Ok(source) => match observed_identity {
            Some(identity) => result.with_session_bound_response_identity(source, Some(identity)),
            None => result.with_decoded_response_identity(Some(source), None),
        },
        Err(_) => result.with_rejected_response_identity(UdpResponseDropReason::MalformedIdentity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS2022_CIPHER: &str = "2022-blake3-aes-128-gcm";
    const SS2022_PASSWORD: &str = "AQIDBAUGBwgJCgsMDQ4PEA==:ERITFBUWFxgZGhscHR4fIA==";

    #[test]
    fn aead_response_source_is_verified_at_the_consumer_boundary() {
        let cipher = "aes-128-gcm";
        let password = "fixed-target-password";
        let salt = [0x31_u8; 16];
        let expected: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let packet =
            encode_udp_packet(cipher, password, &salt, &other.to_string(), b"response").unwrap();
        let session =
            ShadowsocksAeadDatagramSession::new(cipher.to_owned(), password.to_owned(), salt.len());
        let mut response = session.decode_response(&packet).unwrap();
        let expectation = response.fixed_target_expectation(expected);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Dropped(UdpResponseDropReason::UnexpectedWireSource)
        );
    }

    #[test]
    fn ss2022_response_source_and_client_session_are_verified() {
        let client_session = *b"client90";
        let server_session = *b"server90";
        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let now = ss2022_udp_unix_timestamp_now();
        let codec = Ss2022UdpCodec::new(SS2022_CIPHER, SS2022_PASSWORD, client_session).unwrap();
        let packet = dae_outbound::shadowsocks::encode_ss2022_udp_server_packet(
            SS2022_CIPHER,
            SS2022_PASSWORD,
            server_session,
            0,
            client_session,
            &target.to_string(),
            b"response",
            now,
            None,
        )
        .unwrap();
        let mut session = Shadowsocks2022DatagramSession::new(
            SS2022_CIPHER.to_owned(),
            SS2022_PASSWORD.to_owned(),
            0,
        );
        session.codec = Some(codec);
        let mut response = session.decode_response(&packet.wire).unwrap();
        let expectation = response.fixed_target_expectation(target);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Validated
        );
    }
}
