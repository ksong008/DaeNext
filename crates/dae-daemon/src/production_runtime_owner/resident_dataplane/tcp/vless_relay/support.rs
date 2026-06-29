use super::*;
#[derive(Clone, Debug, Default)]
pub(crate) struct RelayStats {
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) client_to_proxy: usize,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) proxy_to_client: usize,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) response_header_stripped: bool,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) vision_unpadding_blocks: usize,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) vision_direct_command_seen:
        bool,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) vision_raw_direct_recovered:
        bool,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) vision_downlink_direct_active:
        bool,
}

#[derive(Debug)]
pub(crate) struct RelayError {
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) message: String,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) stats: RelayStats,
}

impl RelayError {
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) fn new(
        message: impl Into<String>,
        stats: &RelayStats,
    ) -> Self {
        Self {
            message: message.into(),
            stats: stats.clone(),
        }
    }
}

pub(crate) fn is_graceful_vless_response_tls_plain_close_error(
    err: &std::io::Error,
    stats: &RelayStats,
) -> bool {
    if !vless_response_started(stats) {
        return false;
    }
    if is_graceful_tls_plain_close_error(err) {
        return true;
    }
    is_boringssl_tls_plain_close_after_response_message(&err.to_string())
}

fn vless_response_started(stats: &RelayStats) -> bool {
    stats.response_header_stripped || stats.proxy_to_client > 0
}

fn is_boringssl_tls_plain_close_after_response_message(message: &str) -> bool {
    message.contains("[BAD_DECRYPT]") && message.contains("[DECRYPTION_FAILED_OR_BAD_RECORD_MAC]")
}

#[derive(Default)]
pub(crate) struct VlessResponseStripper {
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) header: Vec<u8>,
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) done: bool,
}

impl VlessResponseStripper {
    pub(in crate::production_runtime_owner::resident_dataplane::tcp) fn consume(
        &mut self,
        input: &[u8],
    ) -> Result<Vec<u8>, String> {
        if self.done {
            return Ok(input.to_vec());
        }
        self.header.extend_from_slice(input);
        if self.header.len() < 2 {
            return Ok(Vec::new());
        }
        if self.header[0] != VLESS_RESPONSE_VERSION {
            return Err(format!(
                "unexpected VLESS response version: {}",
                self.header[0]
            ));
        }
        let header_len = 2 + self.header[1] as usize;
        if self.header.len() < header_len {
            return Ok(Vec::new());
        }
        self.done = true;
        Ok(self.header.split_off(header_len))
    }
}
