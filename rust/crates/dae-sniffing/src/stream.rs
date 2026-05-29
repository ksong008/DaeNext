use crate::{SniffingError, sniff_tcp};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpSniffBuffer {
    data: Vec<u8>,
    sniffed: Option<String>,
}

impl TcpSniffBuffer {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            sniffed: None,
        }
    }

    pub fn append_data(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
        self.sniffed = None;
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
