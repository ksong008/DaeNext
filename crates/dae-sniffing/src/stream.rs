use crate::{SniffingError, sniff_tcp};

/// F-25: 嗅探缓冲的内部字节上限（与生产 direct_sniffing 的 64 KiB
/// 预算一致），防止 bench/test 误用导致无界内存增长。
pub const TCP_SNIFF_BUFFER_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpSniffBuffer {
    data: Vec<u8>,
    sniffed: Option<String>,
    max_bytes: usize,
}

impl TcpSniffBuffer {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data
                .iter()
                .copied()
                .take(TCP_SNIFF_BUFFER_MAX_BYTES)
                .collect(),
            sniffed: None,
            max_bytes: TCP_SNIFF_BUFFER_MAX_BYTES,
        }
    }

    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            data: Vec::new(),
            sniffed: None,
            max_bytes,
        }
    }

    pub fn append_data(&mut self, data: &[u8]) -> Result<(), SniffingError> {
        if self.data.len().saturating_add(data.len()) > self.max_bytes {
            return Err(SniffingError::Message(format!(
                "TCP sniff buffer exceeds {} bytes",
                self.max_bytes
            )));
        }
        self.data.extend_from_slice(data);
        self.sniffed = None;
        Ok(())
    }

    pub fn sniff_tcp(&mut self) -> Result<&str, SniffingError> {
        if self.sniffed.is_none() {
            self.sniffed = Some(sniff_tcp(&self.data)?);
        }
        Ok(self.sniffed.as_deref().expect("sniffed domain is set"))
    }

    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn data_view(&self) -> &[u8] {
        &self.data
    }
}
