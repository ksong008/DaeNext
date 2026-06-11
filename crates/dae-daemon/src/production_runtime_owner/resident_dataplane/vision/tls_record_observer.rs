use super::*;
pub(crate) fn observe_tls_records<F>(
    pending: &mut Vec<u8>,
    payload: &[u8],
    mut observe: F,
) -> Result<(), String>
where
    F: FnMut(&TlsPlaintext<'_>),
{
    pending.extend_from_slice(payload);
    if pending.len() > VISION_TLS_OBSERVE_LIMIT {
        pending.clear();
        return Ok(());
    }
    loop {
        let consumed = {
            match parse_tls_plaintext(pending.as_slice()) {
                Ok((remaining, record)) => {
                    let consumed = pending.len() - remaining.len();
                    observe(&record);
                    consumed
                }
                Err(tls_parser::nom::Err::Incomplete(_)) => return Ok(()),
                Err(_) => {
                    pending.clear();
                    return Ok(());
                }
            }
        };
        if consumed == 0 {
            return Ok(());
        }
        pending.drain(..consumed);
    }
}
