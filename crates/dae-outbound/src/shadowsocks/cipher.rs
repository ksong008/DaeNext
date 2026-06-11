use crate::error::OutboundError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherFamily {
    Aead,
    Aead2022,
    Stream,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherInfo {
    pub cipher: String,
    pub family: CipherFamily,
    pub protocol_dialer: &'static str,
    pub rust_capability_label: &'static str,
    pub export_userinfo_plain: bool,
}

pub fn classify_cipher(cipher: &str) -> Result<CipherInfo, OutboundError> {
    let cipher = cipher.to_ascii_lowercase();
    let family = match cipher.as_str() {
        "aes-256-gcm" | "aes-128-gcm" | "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
            CipherFamily::Aead
        }
        "2022-blake3-aes-256-gcm" | "2022-blake3-aes-128-gcm" | "2022-blake3-chacha20-poly1305" => {
            CipherFamily::Aead2022
        }
        "aes-128-cfb" | "aes-192-cfb" | "aes-256-cfb" | "aes-128-ctr" | "aes-192-ctr"
        | "aes-256-ctr" | "aes-128-ofb" | "aes-192-ofb" | "aes-256-ofb" | "des-cfb" | "bf-cfb"
        | "cast5-cfb" | "rc4-md5" | "rc4-md5-6" | "chacha20" | "chacha20-ietf" | "salsa20"
        | "camellia-128-cfb" | "camellia-192-cfb" | "camellia-256-cfb" | "idea-cfb" | "rc2-cfb"
        | "seed-cfb" | "rc4" | "none" | "plain" => CipherFamily::Stream,
        _ => {
            return Err(OutboundError::BadShadowsocks(format!(
                "unsupported shadowsocks encryption method: {cipher}"
            )));
        }
    };
    Ok(CipherInfo {
        cipher,
        family,
        protocol_dialer: match family {
            CipherFamily::Aead => "shadowsocks",
            CipherFamily::Aead2022 => "shadowsocks_2022",
            CipherFamily::Stream => "shadowsocks_stream",
        },
        rust_capability_label: match family {
            CipherFamily::Aead2022 => "shadowsocks-2022",
            CipherFamily::Aead | CipherFamily::Stream => "shadowsocks",
        },
        export_userinfo_plain: family == CipherFamily::Aead2022,
    })
}
