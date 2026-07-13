use super::*;

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
        Ok(UdpExchangeResult::new(decoded.payload, "udp-datagram-aead")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-reused"))
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
        Ok(
            UdpExchangeResult::new(decoded.payload, "udp-datagram-aead-2022")
                .with_session_executor("tokio-datagram-relay")
                .with_underlay_reuse("udp-socket-and-codec-session-reused"),
        )
    }

    pub(super) fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("udp-datagram-aead-2022")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-and-codec-session-reused")
    }
}
