use super::*;

const RESIDENT_VMESS_RESPONSE_BUFFER_LIMIT: usize = 128 * 1024;

pub(in crate::production_runtime_owner::resident_dataplane::tcp) struct VmessAeadResponseBuffer {
    request: dae_outbound::vmess::VMessAeadTcpRequest,
    reader: Option<dae_outbound::vmess::VMessAeadTcpResponseReader>,
    bytes: Vec<u8>,
}

impl VmessAeadResponseBuffer {
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) fn new(
        request: dae_outbound::vmess::VMessAeadTcpRequest,
    ) -> Self {
        Self {
            request,
            reader: None,
            bytes: Vec::new(),
        }
    }

    pub(in crate::production_runtime_owner::resident_dataplane::tcp) fn response_header_received(
        &self,
    ) -> bool {
        self.reader.is_some()
    }

    pub(in crate::production_runtime_owner::resident_dataplane::tcp) fn push(
        &mut self,
        input: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        let buffered = self.bytes.len().saturating_add(input.len());
        if buffered > RESIDENT_VMESS_RESPONSE_BUFFER_LIMIT {
            return Err(format!(
                "VMess response buffer exceeded {} bytes",
                RESIDENT_VMESS_RESPONSE_BUFFER_LIMIT
            ));
        }
        self.bytes.extend_from_slice(input);
        if self.reader.is_none() {
            self.reader = aead_tcp_response_reader_from_buffer(&mut self.bytes, &self.request)
                .map_err(|err| format!("decode VMess AEAD response header: {err}"))?;
        }
        let Some(reader) = self.reader.as_mut() else {
            return Ok(Vec::new());
        };
        let mut chunks = Vec::new();
        while let Some(chunk) = reader
            .try_read_chunk_from_buffer(&mut self.bytes)
            .map_err(|err| format!("decode VMess AEAD response chunk: {err}"))?
        {
            chunks.push(chunk);
        }
        Ok(chunks)
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
            decoded.extend(decoder.push(&[byte]).unwrap());
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
}
