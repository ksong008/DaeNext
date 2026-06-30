use super::*;
use boring::hash::hmac_sha512;
use boring::pkey::Id;
use boring::ssl::{SslAlert, SslRef, SslVerifyError};

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const REALITY_CERT_SIGNATURE_LEN: usize = 64;

pub(super) fn verify_reality_boring_server_cert(ssl: &mut SslRef) -> Result<(), SslVerifyError> {
    let auth_key =
        reality_boring_auth_key(ssl).ok_or(SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE))?;
    let cert = ssl
        .peer_certificate()
        .ok_or(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
    let public_key = reality_cert_ed25519_public_key(&cert)
        .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
    if reality_cert_signature_matches_auth_key(&public_key, cert.signature().as_slice(), &auth_key)
    {
        Ok(())
    } else {
        Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
    }
}

fn reality_cert_ed25519_public_key(
    cert: &boring::x509::X509Ref,
) -> Result<[u8; ED25519_PUBLIC_KEY_LEN], boring::error::ErrorStack> {
    let public_key = cert.public_key()?;
    if public_key.id() != Id::ED25519 {
        return Err(boring::error::ErrorStack::get());
    }
    let mut out = [0_u8; ED25519_PUBLIC_KEY_LEN];
    let len = public_key.raw_public_key(&mut out)?.len();
    if len == ED25519_PUBLIC_KEY_LEN {
        Ok(out)
    } else {
        Err(boring::error::ErrorStack::get())
    }
}

fn reality_cert_signature_matches_auth_key(
    public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    signature: &[u8],
    auth_key: &[u8; 32],
) -> bool {
    if signature.len() != REALITY_CERT_SIGNATURE_LEN {
        return false;
    }
    let Ok(expected) = hmac_sha512(auth_key, public_key) else {
        return false;
    };
    constant_time_eq(&expected, signature)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_cert_match_requires_auth_key_hmac_signature() {
        let auth_key = [7_u8; 32];
        let pubkey = [9_u8; ED25519_PUBLIC_KEY_LEN];
        let signature = hmac_sha512(&auth_key, &pubkey).unwrap();

        assert!(reality_cert_signature_matches_auth_key(
            &pubkey, &signature, &auth_key
        ));

        let mut wrong_key = auth_key;
        wrong_key[0] ^= 1;
        assert!(!reality_cert_signature_matches_auth_key(
            &pubkey, &signature, &wrong_key
        ));
    }

    #[test]
    fn reality_cert_match_rejects_invalid_signature_length() {
        let auth_key = [7_u8; 32];
        let pubkey = [9_u8; ED25519_PUBLIC_KEY_LEN];
        let signature = [0_u8; REALITY_CERT_SIGNATURE_LEN - 1];

        assert!(!reality_cert_signature_matches_auth_key(
            &pubkey, &signature, &auth_key
        ));
    }
}
