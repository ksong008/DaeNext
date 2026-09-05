use super::*;

pub fn observe_tls_records<F>(
    pending: &mut Vec<u8>,
    payload: &[u8],
    mut observe: F,
) -> Result<(), String>
where
    F: FnMut(&TlsPlaintext<'_>),
{
    pending.extend_from_slice(payload);
    let mut consumed_total = 0_usize;
    loop {
        let input = &pending[consumed_total..];
        let (_, header) = match tls_parser::parse_tls_record_header(input) {
            Ok(value) => value,
            Err(tls_parser::nom::Err::Incomplete(_)) => break,
            Err(_) => {
                pending.clear();
                return Ok(());
            }
        };
        if !matches!(
            header.record_type,
            TlsRecordType::ChangeCipherSpec
                | TlsRecordType::Alert
                | TlsRecordType::Handshake
                | TlsRecordType::ApplicationData
                | TlsRecordType::Heartbeat
        ) || usize::from(header.len) > TLS_RECORD_MAX_PAYLOAD_LEN
        {
            pending.clear();
            return Ok(());
        }
        let record_len = TLS_RECORD_HEADER_LEN + usize::from(header.len);
        if input.len() < record_len {
            break;
        }

        // Consume the complete record envelope even when the handshake message
        // inside it is fragmented across records. Vision only needs the Hello
        // metadata; retaining a whole fragmented certificate/handshake would
        // make the observation budget depend on the peer's certificate size.
        if let Ok((_, record)) = parse_tls_plaintext(&input[..record_len]) {
            observe(&record);
        }
        consumed_total = consumed_total.saturating_add(record_len);
    }

    if consumed_total > 0 {
        pending.drain(..consumed_total);
    }
    if pending.len() > VISION_TLS_OBSERVE_LIMIT {
        pending.clear();
        return Err(format!(
            "Vision TLS observation exceeds {VISION_TLS_OBSERVE_LIMIT} bytes"
        ));
    }
    Ok(())
}
