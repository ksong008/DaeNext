use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VisionTlsDecision {
    Unknown,
    Direct,
    PlainOverlay,
}

#[derive(Clone, Debug)]
pub(crate) struct VisionInnerTlsState {
    pub(crate) client_pending: Vec<u8>,
    pub(crate) server_pending: Vec<u8>,
    pub(crate) decision: VisionTlsDecision,
    pub(crate) client_tls_observed: bool,
    pub(crate) client_tls13_advertised: Option<bool>,
}

impl VisionInnerTlsState {
    pub(crate) fn new() -> Self {
        Self {
            client_pending: Vec::new(),
            server_pending: Vec::new(),
            decision: VisionTlsDecision::Unknown,
            client_tls_observed: false,
            client_tls13_advertised: None,
        }
    }

    pub(crate) fn observe_client_payload(&mut self, payload: &[u8]) -> Result<(), String> {
        let mut advertised = self.client_tls13_advertised;
        let mut observed = self.client_tls_observed;
        observe_tls_records(&mut self.client_pending, payload, |record| {
            if record.hdr.record_type != TlsRecordType::Handshake {
                return;
            }
            for message in &record.msg {
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) =
                    message
                {
                    observed = true;
                    advertised = client_hello_advertises_tls13(client_hello.ext);
                }
            }
        })
        .map(|()| {
            self.client_tls_observed = observed;
            self.client_tls13_advertised = advertised;
        })
    }

    pub(crate) fn observe_server_payload(&mut self, payload: &[u8]) -> Result<(), String> {
        if self.decision != VisionTlsDecision::Unknown {
            return Ok(());
        }
        let mut decision = self.decision;
        observe_tls_records(&mut self.server_pending, payload, |record| {
            if record.hdr.record_type != TlsRecordType::Handshake {
                return;
            }
            for message in &record.msg {
                if decision != VisionTlsDecision::Unknown {
                    return;
                }
                let TlsMessage::Handshake(handshake) = message else {
                    continue;
                };
                decision = match handshake {
                    TlsMessageHandshake::ServerHello(server_hello) => {
                        let selected_tls13 = server_hello_selects_tls13(server_hello.ext);
                        let cipher_suite = u16::from(server_hello.cipher);
                        server_hello_decision(selected_tls13, cipher_suite)
                    }
                    TlsMessageHandshake::ServerHelloV13Draft18(server_hello) => {
                        let selected_tls13 = server_hello_selects_tls13(server_hello.ext)
                            || server_hello.version == TlsVersion::Tls13Draft18;
                        let cipher_suite = u16::from(server_hello.cipher);
                        server_hello_decision(selected_tls13, cipher_suite)
                    }
                    _ => VisionTlsDecision::Unknown,
                };
            }
        })?;
        self.decision = decision;
        Ok(())
    }

    pub(crate) fn application_data_command(&self) -> Option<u8> {
        match self.decision {
            VisionTlsDecision::Unknown => None,
            VisionTlsDecision::Direct => Some(VISION_COMMAND_DIRECT),
            VisionTlsDecision::PlainOverlay => Some(VISION_COMMAND_END),
        }
    }

    pub(crate) fn client_tls_filter_active(&self) -> bool {
        self.client_tls_observed
            || self
                .client_pending
                .first()
                .is_some_and(|record_type| *record_type == TLS_CONTENT_TYPE_HANDSHAKE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VisionUplinkState {
    Padding,
    PlainOverlay,
    DirectPass,
}

#[cfg(test)]
pub(crate) fn tls_application_data_records_complete(mut input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    while !input.is_empty() {
        if input.len() < TLS_RECORD_HEADER_LEN {
            return false;
        }
        if input[0] != 23 || input[1] != 3 || input[2] != 3 {
            return false;
        }
        let len = u16::from_be_bytes([input[3], input[4]]) as usize;
        let record_len = TLS_RECORD_HEADER_LEN + len;
        if input.len() < record_len {
            return false;
        }
        input = &input[record_len..];
    }
    true
}
