use super::*;
use boring::hash::hmac_sha512;
use boring::ssl::{SslAlert, SslRef, SslVerifyError};

const ED25519_SPKI_DER_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const ED25519_BIT_STRING_HEADER_DER: &[u8] = &[0x03, 0x21, 0x00];
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const REALITY_CERT_HMAC_LEN: usize = 64;
const REALITY_CERT_KEY_SCAN_WINDOW: usize = 16;

pub(super) fn verify_reality_boring_server_cert(ssl: &mut SslRef) -> Result<(), SslVerifyError> {
    let auth_key =
        reality_boring_auth_key(ssl).ok_or(SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE))?;
    let cert = ssl
        .peer_certificate()
        .ok_or(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
    let der = cert
        .to_der()
        .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
    if reality_cert_matches_auth_key(&der, &auth_key) {
        Ok(())
    } else {
        Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
    }
}

fn reality_cert_matches_auth_key(cert_der: &[u8], auth_key: &[u8; 32]) -> bool {
    let Some(pubkey) = extract_reality_ed25519_public_key(cert_der) else {
        return false;
    };
    let Ok(expected) = hmac_sha512(auth_key, &pubkey) else {
        return false;
    };
    let Some(tail) = cert_der.get(cert_der.len().saturating_sub(REALITY_CERT_HMAC_LEN)..) else {
        return false;
    };
    constant_time_eq(&expected, tail)
}

fn extract_reality_ed25519_public_key(cert_der: &[u8]) -> Option<[u8; ED25519_PUBLIC_KEY_LEN]> {
    let minimum_len =
        ED25519_OID_DER.len() + ED25519_BIT_STRING_HEADER_DER.len() + ED25519_PUBLIC_KEY_LEN;
    if cert_der.len() < minimum_len {
        return None;
    }

    for oid_offset in 0..=cert_der.len().saturating_sub(ED25519_OID_DER.len()) {
        if cert_der.get(oid_offset..oid_offset + ED25519_OID_DER.len()) != Some(ED25519_OID_DER) {
            continue;
        }
        let header_start = oid_offset + ED25519_OID_DER.len();
        let header_end = (header_start + REALITY_CERT_KEY_SCAN_WINDOW).min(
            cert_der
                .len()
                .saturating_sub(ED25519_BIT_STRING_HEADER_DER.len() + ED25519_PUBLIC_KEY_LEN),
        );
        for bit_string_offset in header_start..=header_end {
            if cert_der
                .get(bit_string_offset..bit_string_offset + ED25519_BIT_STRING_HEADER_DER.len())
                != Some(ED25519_BIT_STRING_HEADER_DER)
            {
                continue;
            }
            let key_start = bit_string_offset + ED25519_BIT_STRING_HEADER_DER.len();
            let key = cert_der.get(key_start..key_start + ED25519_PUBLIC_KEY_LEN)?;
            let mut out = [0_u8; ED25519_PUBLIC_KEY_LEN];
            out.copy_from_slice(key);
            return Some(out);
        }
    }
    None
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

#[allow(dead_code)]
fn ed25519_spki_der_from_public_key(public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut der = Vec::with_capacity(ED25519_SPKI_DER_PREFIX.len() + public_key.len());
    der.extend_from_slice(ED25519_SPKI_DER_PREFIX);
    der.extend_from_slice(public_key);
    der
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_cert_match_requires_auth_key_hmac_tail() {
        let auth_key = [7_u8; 32];
        let pubkey = [9_u8; ED25519_PUBLIC_KEY_LEN];
        let mut cert = b"prefix".to_vec();
        cert.extend_from_slice(&ed25519_spki_der_from_public_key(&pubkey));
        let hmac = hmac_sha512(&auth_key, &pubkey).unwrap();
        cert.extend_from_slice(&hmac);

        assert!(reality_cert_matches_auth_key(&cert, &auth_key));

        let mut wrong_key = auth_key;
        wrong_key[0] ^= 1;
        assert!(!reality_cert_matches_auth_key(&cert, &wrong_key));
    }

    #[test]
    fn reality_cert_match_rejects_missing_ed25519_key() {
        let auth_key = [7_u8; 32];
        let mut cert = b"prefix".to_vec();
        cert.extend_from_slice(&[0_u8; REALITY_CERT_HMAC_LEN]);

        assert!(!reality_cert_matches_auth_key(&cert, &auth_key));
    }
}
