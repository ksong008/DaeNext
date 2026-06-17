use crate::SniffingError;
use crate::quic::sniff_quic_initial_sni;

pub const PACKET_SNIFFER_MAX_BUFFERED_BYTES: usize = 64 * 1024;
pub const PACKET_SNIFFER_MAX_CHUNKS: usize = 64;

#[derive(Clone, Debug)]
pub struct PacketSniffer {
    data: Vec<Vec<u8>>,
    buffered: usize,
    need_more: bool,
    data_error: Option<SniffingError>,
}

impl PacketSniffer {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: vec![data.to_vec()],
            buffered: data.len(),
            need_more: false,
            data_error: None,
        }
    }

    pub fn append_data(&mut self, data: &[u8]) {
        self.need_more = false;
        if self.buffered + data.len() > PACKET_SNIFFER_MAX_BUFFERED_BYTES
            || self.data.len() >= PACKET_SNIFFER_MAX_CHUNKS
        {
            self.data_error = Some(SniffingError::DataTooLarge);
            return;
        }
        self.buffered += data.len();
        self.data.push(data.to_vec());
    }

    pub fn data(&self) -> Vec<Vec<u8>> {
        self.data.clone()
    }

    pub fn data_view(&self) -> Vec<&[u8]> {
        self.data.iter().map(Vec::as_slice).collect()
    }

    pub const fn need_more(&self) -> bool {
        self.need_more
    }

    pub fn sniff_udp(&mut self) -> Result<String, SniffingError> {
        self.need_more = false;
        if let Some(err) = &self.data_error {
            return Err(err.clone());
        }
        let view = self.data_view();
        match sniff_quic_initial_sni(&view) {
            Err(SniffingError::NeedMore) => {
                self.need_more = true;
                Err(SniffingError::NeedMore)
            }
            result => result,
        }
    }
}
