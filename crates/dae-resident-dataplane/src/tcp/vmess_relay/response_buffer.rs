use super::*;

const RESIDENT_VMESS_RESPONSE_BUFFER_LIMIT: usize = 128 * 1024;

pub(in crate::tcp) struct VmessAeadResponseBuffer {
    request: dae_outbound::vmess::VMessAeadTcpRequest,
    reader: Option<dae_outbound::vmess::VMessAeadTcpResponseReader>,
    bytes: Vec<u8>,
    offset: usize,
}

impl VmessAeadResponseBuffer {
    pub(in crate::tcp) fn new(request: dae_outbound::vmess::VMessAeadTcpRequest) -> Self {
        Self {
            request,
            reader: None,
            bytes: Vec::new(),
            offset: 0,
        }
    }

    pub(in crate::tcp) fn response_header_received(&self) -> bool {
        self.reader.is_some()
    }

    pub(in crate::tcp) fn extend_from_slice(&mut self, input: &[u8]) -> Result<(), String> {
        self.compact_if_worthwhile();
        let buffered = self
            .bytes
            .len()
            .saturating_sub(self.offset)
            .saturating_add(input.len());
        if buffered > RESIDENT_VMESS_RESPONSE_BUFFER_LIMIT {
            return Err(format!(
                "VMess response buffer exceeded {} bytes",
                RESIDENT_VMESS_RESPONSE_BUFFER_LIMIT
            ));
        }
        self.bytes.extend_from_slice(input);
        if self.reader.is_none() {
            debug_assert_eq!(self.offset, 0);
            self.reader = aead_tcp_response_reader_from_buffer(&mut self.bytes, &self.request)
                .map_err(|err| format!("decode VMess AEAD response header: {err}"))?;
        }
        Ok(())
    }

    pub(in crate::tcp) fn next_chunk(&mut self) -> Result<Option<&[u8]>, String> {
        let Some(reader) = self.reader.as_mut() else {
            return Ok(None);
        };
        reader
            .try_read_chunk_in_place_from_buffer(&mut self.bytes, &mut self.offset)
            .map_err(|err| format!("decode VMess AEAD response chunk: {err}"))
    }

    fn compact_if_worthwhile(&mut self) {
        if self.offset == 0 {
            return;
        }
        if self.offset >= self.bytes.len() {
            self.bytes.clear();
            self.offset = 0;
            return;
        }
        if self.offset >= 8 * 1024 && self.offset * 2 >= self.bytes.len() {
            let remaining = self.bytes.len() - self.offset;
            self.bytes.copy_within(self.offset.., 0);
            self.bytes.truncate(remaining);
            self.offset = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UUID: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn incremental_response_decode_preserves_header_and_chunk_state() {
        let session = aead_tcp_client_session_start(TEST_UUID, "example.com:443", &[]).unwrap();
        let payloads = [
            b"incremental-response-one".as_slice(),
            b"incremental-response-two".as_slice(),
            b"incremental-response-three".as_slice(),
        ];
        let response =
            dae_outbound::vmess::aead_tcp_response_packet_chunks(&session.request, &payloads)
                .unwrap();
        let mut decoder = VmessAeadResponseBuffer::new(session.request);
        let mut decoded = Vec::new();

        for byte in response {
            decoder.extend_from_slice(&[byte]).unwrap();
            while let Some(chunk) = decoder.next_chunk().unwrap() {
                decoded.push(chunk.to_vec());
            }
        }

        assert!(decoder.response_header_received());
        assert_eq!(
            decoded,
            payloads
                .iter()
                .map(|payload| payload.to_vec())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn buffered_response_decodes_multiple_chunks_without_returning_owned_chunk_vectors() {
        let session = aead_tcp_client_session_start(TEST_UUID, "example.com:443", &[]).unwrap();
        let payloads = [vec![0x11; 16 * 1024], vec![0x22; 4097], b"tail".to_vec()];
        let response = dae_outbound::vmess::aead_tcp_response_packet_chunks(
            &session.request,
            &payloads.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )
        .unwrap();
        let mut decoder = VmessAeadResponseBuffer::new(session.request);
        decoder.extend_from_slice(&response).unwrap();

        for expected in &payloads {
            assert_eq!(decoder.next_chunk().unwrap().unwrap(), expected);
        }
        assert!(decoder.next_chunk().unwrap().is_none());
    }
}
