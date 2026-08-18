pub fn vision_padding_block(
    payload: &[u8],
    command: u8,
    user_uuid: [u8; 16],
    uuid_sent: &mut bool,
    long_padding: bool,
) -> Vec<u8> {
    let padding_len = vision_padding_len(payload.len(), long_padding);
    let mut out = Vec::with_capacity(
        if *uuid_sent { 0 } else { user_uuid.len() } + 5 + payload.len() + padding_len,
    );
    if !*uuid_sent {
        out.extend_from_slice(&user_uuid);
        *uuid_sent = true;
    }
    let content_len = payload.len().min(u16::MAX as usize) as u16;
    out.push(command);
    out.extend_from_slice(&content_len.to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(&payload[..content_len as usize]);
    out.resize(out.len() + padding_len, 0);
    out
}

pub fn vision_padding_len(content_len: usize, long_padding: bool) -> usize {
    if content_len < 900 && long_padding {
        900 - content_len + fastrand::usize(..500)
    } else {
        fastrand::usize(..256)
    }
}
