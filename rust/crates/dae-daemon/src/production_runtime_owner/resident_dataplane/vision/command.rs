use super::*;
pub(crate) fn vision_command_name(command: u8) -> &'static str {
    match command {
        VISION_COMMAND_CONTINUE => "continue",
        VISION_COMMAND_END => "end",
        VISION_COMMAND_DIRECT => "direct",
        _ => "unknown",
    }
}

pub(crate) fn vision_uplink_command(
    record_type: u8,
    tls_state: &VisionInnerTlsState,
) -> Option<u8> {
    if record_type != TLS_CONTENT_TYPE_APPLICATION_DATA {
        return Some(VISION_COMMAND_CONTINUE);
    }
    tls_state.application_data_command()
}

pub(crate) fn server_hello_decision(selected_tls13: bool, cipher_suite: u16) -> VisionTlsDecision {
    if selected_tls13 && tls13_cipher_allows_direct(cipher_suite) {
        VisionTlsDecision::Direct
    } else {
        VisionTlsDecision::PlainOverlay
    }
}

pub(crate) fn tls13_cipher_allows_direct(cipher: u16) -> bool {
    (0x1301..=0x1305).contains(&cipher) && cipher != TLS13_AES_128_CCM_8_SHA256
}
