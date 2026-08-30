pub mod contract;
pub mod metadata;
pub mod uuid;

pub const VMESS_AEAD_SECURITY_AES_128_GCM: u8 = 3;
pub const VMESS_AEAD_SECURITY_CHACHA20_POLY1305: u8 = 4;
pub const VMESS_AEAD_SECURITY_NONE: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VMessBodySecurity {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

impl VMessBodySecurity {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Aes128Gcm => VMESS_AEAD_SECURITY_AES_128_GCM,
            Self::Chacha20Poly1305 => VMESS_AEAD_SECURITY_CHACHA20_POLY1305,
            Self::None | Self::Zero => VMESS_AEAD_SECURITY_NONE,
        }
    }

    pub const fn uses_raw_body(self) -> bool {
        matches!(self, Self::Zero)
    }
}

pub use metadata::{VMessMetadata, VMessMetadataType, VMessNetwork};
