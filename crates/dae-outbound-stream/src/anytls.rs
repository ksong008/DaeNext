pub mod padding;

pub use dae_outbound_core::anytls::AnyTLSLink;
pub use dae_outbound_core::anytls::{contract, link};
pub use padding::AnyTlsPaddingScheme;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnyTlsFrame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

impl AnyTlsFrame {
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}
