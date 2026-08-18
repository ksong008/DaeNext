use super::*;
pub fn looks_like_tls_record_start(pending: &[u8]) -> bool {
    could_be_tls_record_prefix(pending)
}

pub fn should_continue_vision_tls_filtering(
    pending: &[u8],
    tls_state: &VisionInnerTlsState,
) -> bool {
    tls_state.client_tls_filter_active() && looks_like_tls_record_start(pending)
}

pub fn could_be_tls_record_prefix(pending: &[u8]) -> bool {
    if pending.is_empty() {
        return true;
    }
    if !matches!(pending[0], 20..=23) {
        return false;
    }
    if pending.len() == 1 {
        return true;
    }
    if pending[1] != 3 {
        return false;
    }
    if pending.len() == 2 {
        return true;
    }
    if !(1..=4).contains(&pending[2]) {
        return false;
    }
    if pending.len() < TLS_RECORD_HEADER_LEN {
        return true;
    }
    let payload_len = u16::from_be_bytes([pending[3], pending[4]]) as usize;
    payload_len <= TLS_RECORD_MAX_PAYLOAD_LEN
}

#[cfg(test)]
pub fn pop_complete_tls_record(pending: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>, String> {
    let Some((record_type, record_len)) = peek_complete_tls_record(pending)? else {
        return Ok(None);
    };
    let record = take_vec_prefix(pending, record_len);
    Ok(Some((record_type, record)))
}

pub fn take_vec_prefix(pending: &mut Vec<u8>, len: usize) -> Vec<u8> {
    debug_assert!(len <= pending.len());
    let tail = pending.split_off(len);
    std::mem::replace(pending, tail)
}

pub fn peek_complete_tls_record(pending: &[u8]) -> Result<Option<(u8, usize)>, String> {
    if pending.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }
    let record_type = pending[0];
    if !matches!(record_type, 20..=23) {
        return Err(format!(
            "unexpected TLS record type before VLESS Vision uplink overlay switch: {record_type}"
        ));
    }
    if pending[1] != 3 || !(1..=4).contains(&pending[2]) {
        return Err(format!(
            "unexpected TLS record version before VLESS Vision uplink overlay switch: {}.{}",
            pending[1], pending[2]
        ));
    }
    let payload_len = u16::from_be_bytes([pending[3], pending[4]]) as usize;
    if payload_len > TLS_RECORD_MAX_PAYLOAD_LEN {
        return Err(format!(
            "TLS record too large before VLESS Vision uplink overlay switch: {payload_len} bytes"
        ));
    }
    let record_len = TLS_RECORD_HEADER_LEN + payload_len;
    if pending.len() < record_len {
        return Ok(None);
    }
    Ok(Some((record_type, record_len)))
}
