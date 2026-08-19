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
    if pending.len() > VISION_TLS_OBSERVE_LIMIT {
        pending.clear();
        return Ok(());
    }
    let mut consumed_total = 0_usize;
    loop {
        let consumed = {
            match parse_tls_plaintext(&pending[consumed_total..]) {
                Ok((remaining, record)) => {
                    let consumed = pending[consumed_total..].len() - remaining.len();
                    observe(&record);
                    consumed
                }
                Err(tls_parser::nom::Err::Incomplete(_)) => {
                    if consumed_total > 0 {
                        pending.drain(..consumed_total);
                    }
                    return Ok(());
                }
                Err(_) => {
                    pending.clear();
                    return Ok(());
                }
            }
        };
        if consumed == 0 {
            if consumed_total > 0 {
                pending.drain(..consumed_total);
            }
            return Ok(());
        }
        consumed_total = consumed_total.saturating_add(consumed);
    }
}
