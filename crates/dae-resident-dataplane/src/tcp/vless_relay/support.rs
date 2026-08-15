use super::*;
#[derive(Clone, Debug, Default)]
pub(crate) struct RelayStats {
    pub(in crate::tcp) client_to_proxy: usize,
    pub(in crate::tcp) proxy_to_client: usize,
    pub(in crate::tcp) response_header_stripped: bool,
    pub(in crate::tcp) vision_unpadding_blocks: usize,
    pub(in crate::tcp) vision_direct_command_seen: bool,
    pub(in crate::tcp) vision_raw_direct_recovered: bool,
    pub(in crate::tcp) vision_downlink_direct_active: bool,
}

#[derive(Debug)]
pub(crate) struct RelayError {
    pub(in crate::tcp) message: String,
    pub(in crate::tcp) stats: RelayStats,
}

impl RelayError {
    pub(in crate::tcp) fn new(message: impl Into<String>, stats: &RelayStats) -> Self {
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
    pub(in crate::tcp) header: Vec<u8>,
    header_len: Option<usize>,
    pub(in crate::tcp) done: bool,
}

impl VlessResponseStripper {
    pub(in crate::tcp) fn consume<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<std::borrow::Cow<'a, [u8]>, String> {
        if self.done {
            return Ok(std::borrow::Cow::Borrowed(input));
        }

        // The response header is at most 257 bytes.  Keep only the incomplete
        // prefix in the owned buffer and borrow the application payload from
        // the current transport read once the boundary is known.  The old
        // implementation appended the complete read and then `split_off`'d
        // the payload, allocating and copying on every first response read.
        if self.header_len.is_none() {
            if self.header.is_empty() && input.len() >= 2 {
                if input[0] != VLESS_RESPONSE_VERSION {
                    return Err(format!("unexpected VLESS response version: {}", input[0]));
                }
                let header_len = 2 + input[1] as usize;
                self.header_len = Some(header_len);
                if input.len() >= header_len {
                    self.done = true;
                    return Ok(std::borrow::Cow::Borrowed(&input[header_len..]));
                }
                self.header.extend_from_slice(input);
                return Ok(std::borrow::Cow::Borrowed(&[]));
            }

            let version_bytes = 2usize.saturating_sub(self.header.len());
            let take = version_bytes.min(input.len());
            self.header.extend_from_slice(&input[..take]);
            if self.header.len() < 2 {
                return Ok(std::borrow::Cow::Borrowed(&[]));
            }
            if self.header[0] != VLESS_RESPONSE_VERSION {
                return Err(format!(
                    "unexpected VLESS response version: {}",
                    self.header[0]
                ));
            }
            self.header_len = Some(2 + self.header[1] as usize);
            let input = &input[take..];
            let header_len = self.header_len.expect("set above");
            let needed = header_len.saturating_sub(self.header.len());
            let header_take = needed.min(input.len());
            self.header.extend_from_slice(&input[..header_take]);
            if self.header.len() < header_len {
                return Ok(std::borrow::Cow::Borrowed(&[]));
            }
            self.done = true;
            return Ok(std::borrow::Cow::Borrowed(&input[header_take..]));
        }

        let header_len = self.header_len.expect("checked above");
        let needed = header_len.saturating_sub(self.header.len());
        let take = needed.min(input.len());
        self.header.extend_from_slice(&input[..take]);
        if self.header.len() < header_len {
            return Ok(std::borrow::Cow::Borrowed(&[]));
        }
        if self.header[0] != VLESS_RESPONSE_VERSION {
            return Err(format!(
                "unexpected VLESS response version: {}",
                self.header[0]
            ));
        }
        self.done = true;
        Ok(std::borrow::Cow::Borrowed(&input[take..]))
    }
}
