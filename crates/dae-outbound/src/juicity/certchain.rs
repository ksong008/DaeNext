use sha2::{Digest, Sha256};

use crate::error::OutboundError;

use super::link::decode_pinned_certchain;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JuicityCertChainPinCheck {
    pub pin_format: String,
    pub decoded_pin: Vec<u8>,
    pub chain_hash: Vec<u8>,
    pub matched: bool,
    pub cert_count: usize,
    pub forces_insecure_verify: bool,
    pub verifies_full_chain_hash: bool,
    pub not_hysteria2_pin_sha256: bool,
}

pub fn generate_cert_chain_hash(raw_certs: &[&[u8]]) -> Vec<u8> {
    let mut chain_hash: Option<[u8; 32]> = None;
    for cert in raw_certs {
        let cert_hash = Sha256::digest(cert);
        chain_hash = Some(match chain_hash {
            Some(current) => {
                let mut hasher = Sha256::new();
                hasher.update(current);
                hasher.update(cert_hash);
                hasher.finalize().into()
            }
            None => cert_hash.into(),
        });
    }
    chain_hash.map(|hash| hash.to_vec()).unwrap_or_default()
}

pub fn check_pinned_certchain(
    raw_certs: &[&[u8]],
    encoded_pin: &str,
) -> Result<JuicityCertChainPinCheck, OutboundError> {
    let decoded = decode_pinned_certchain(encoded_pin)?;
    let chain_hash = generate_cert_chain_hash(raw_certs);
    let matched = chain_hash == decoded.decoded;
    Ok(JuicityCertChainPinCheck {
        pin_format: decoded.format,
        decoded_pin: decoded.decoded,
        chain_hash,
        matched,
        cert_count: raw_certs.len(),
        forces_insecure_verify: !encoded_pin.is_empty(),
        verifies_full_chain_hash: true,
        not_hysteria2_pin_sha256: true,
    })
}

pub fn verify_pinned_certchain(
    raw_certs: &[&[u8]],
    encoded_pin: &str,
) -> Result<JuicityCertChainPinCheck, OutboundError> {
    let check = check_pinned_certchain(raw_certs, encoded_pin)?;
    if !check.matched {
        return Err(OutboundError::BadJuicity(
            "pinned hash of cert chain does not match".to_owned(),
        ));
    }
    Ok(check)
}
