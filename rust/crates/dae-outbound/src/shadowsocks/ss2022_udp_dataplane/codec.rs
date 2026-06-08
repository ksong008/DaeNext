use super::*;
impl Ss2022UdpCodec {
    pub fn new(cipher: &str, password: &str, session_id: [u8; 8]) -> Result<Self, OutboundError> {
        let conf = require_cipher_conf(cipher)?;
        let psk_list = parse_psk_list(password, conf.key_len)?;
        let upsk = psk_list
            .last()
            .ok_or_else(|| OutboundError::BadShadowsocks("SS2022 PSK list is empty".to_owned()))?
            .clone();
        Ok(Self {
            conf,
            cipher: cipher.to_owned(),
            psk_list,
            upsk,
            session_id,
            next_packet_id: 0,
            server_windows: HashMap::new(),
        })
    }

    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    pub fn psk_count(&self) -> usize {
        self.psk_list.len()
    }

    pub fn upsk_index(&self) -> usize {
        self.psk_list.len().saturating_sub(1)
    }

    pub fn encode_client_packet(
        &mut self,
        target: &str,
        payload: &[u8],
        timestamp: u64,
        packet_nonce: Option<&[u8]>,
    ) -> Result<Ss2022UdpEncodedPacket, OutboundError> {
        let packet_id = self.next_packet_id;
        self.next_packet_id += 1;
        if self.conf.packet_cipher {
            encode_merged_header_packet(
                &self.conf,
                &self.cipher,
                &self.upsk,
                packet_nonce,
                HEADER_TYPE_CLIENT_PACKET,
                self.session_id,
                packet_id,
                None,
                target,
                payload,
                timestamp,
            )
        } else {
            encode_separate_header_client_packet(
                &self.conf,
                &self.cipher,
                &self.psk_list,
                self.session_id,
                packet_id,
                target,
                payload,
                timestamp,
            )
        }
    }

    pub fn decode_server_packet(
        &mut self,
        input: &[u8],
        now: u64,
    ) -> Result<Ss2022UdpDecodedPacket, OutboundError> {
        let decoded = if self.conf.packet_cipher {
            decode_merged_header_packet(&self.conf, &self.cipher, &self.upsk, input, now)?
        } else {
            decode_separate_header_server_packet(&self.conf, &self.cipher, &self.upsk, input, now)?
        };
        if decoded.packet_type != HEADER_TYPE_SERVER_PACKET {
            return Err(OutboundError::BadShadowsocks(format!(
                "SS2022 UDP expected server packet type {}, got {}",
                HEADER_TYPE_SERVER_PACKET, decoded.packet_type
            )));
        }
        if decoded.client_session_id != Some(self.session_id) {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP server packet client session mismatch".to_owned(),
            ));
        }
        let window = self
            .server_windows
            .entry(decoded.session_id)
            .or_insert_with(|| SlidingWindowFilter::new(UDP_REPLAY_WINDOW_SIZE));
        if !window.check_and_update(decoded.packet_id) {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP replay attack detected".to_owned(),
            ));
        }
        Ok(decoded)
    }
}

impl Ss2022UdpReplayTracker {
    pub fn check(&mut self, session_id: [u8; 8], packet_id: u64) -> Result<(), OutboundError> {
        let window = self
            .windows
            .entry(session_id)
            .or_insert_with(|| SlidingWindowFilter::new(UDP_REPLAY_WINDOW_SIZE));
        if !window.check_and_update(packet_id) {
            return Err(OutboundError::BadShadowsocks(
                "SS2022 UDP replay attack detected".to_owned(),
            ));
        }
        Ok(())
    }
}
