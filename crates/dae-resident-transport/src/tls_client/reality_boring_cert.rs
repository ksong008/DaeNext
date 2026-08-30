use super::*;
use boring::hash::hmac_sha512;
use boring::pkey::Id;
use boring::ssl::{SslAlert, SslRef, SslVerifyError};
use foreign_types::ForeignTypeRef;

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const REALITY_CERT_SIGNATURE_LEN: usize = 64;

pub(super) fn verify_reality_boring_server_cert(
    ssl: &mut SslRef,
    mldsa65_verify: Option<&Mldsa65VerifyKey>,
) -> Result<(), SslVerifyError> {
    let auth_key =
        reality_boring_auth_key(ssl).ok_or(SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE))?;
    let cert = ssl
        .peer_certificate()
        .ok_or(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
    let public_key = reality_cert_ed25519_public_key(&cert)
        .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
    if !reality_cert_signature_matches_auth_key(&public_key, cert.signature().as_slice(), &auth_key)
    {
        return Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN));
    }
    let Some(mldsa65_verify) = mldsa65_verify else {
        return Ok(());
    };
    let transcript = reality_boring_transcript(ssl)
        .ok_or(SslVerifyError::Invalid(SslAlert::HANDSHAKE_FAILURE))?;
    let signature = reality_cert_first_extension_value(&cert)
        .ok_or(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;
    if reality_mldsa65_signature_matches(
        mldsa65_verify,
        &public_key,
        &auth_key,
        &transcript,
        &signature,
    ) {
        Ok(())
    } else {
        Err(SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN))
    }
}

fn reality_cert_first_extension_value(cert: &boring::x509::X509Ref) -> Option<Vec<u8>> {
    let extension = unsafe {
        if boring_sys::X509_get_ext_count(cert.as_ptr()) < 1 {
            return None;
        }
        boring_sys::X509_get_ext(cert.as_ptr(), 0)
    };
    if extension.is_null() {
        return None;
    }
    let value = unsafe { boring_sys::X509_EXTENSION_get_data(extension) };
    if value.is_null() {
        return None;
    }
    let value = value.cast::<boring_sys::ASN1_STRING>();
    let len = unsafe { boring_sys::ASN1_STRING_length(value) };
    let data = unsafe { boring_sys::ASN1_STRING_get0_data(value) };
    if len < 0 || data.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(data, len as usize).to_vec() })
}

fn reality_mldsa65_signature_matches(
    mldsa65_verify: &Mldsa65VerifyKey,
    public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    auth_key: &[u8; 32],
    transcript: &RealityBoringTranscript,
    signature: &[u8],
) -> bool {
    let mut authenticated = Vec::with_capacity(
        public_key.len() + transcript.client_hello.len() + transcript.server_hello.len(),
    );
    authenticated.extend_from_slice(public_key);
    authenticated.extend_from_slice(&transcript.client_hello);
    authenticated.extend_from_slice(&transcript.server_hello);
    let Ok(message) = hmac_sha512(auth_key, &authenticated) else {
        return false;
    };
    mldsa65_verify.verify(&message, signature)
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
    use std::mem::MaybeUninit;

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

    #[test]
    fn reality_pqv_verifies_exact_official_transcript_message() {
        let mut encoded_public_key =
            vec![0_u8; dae_outbound_stream::shared_transport::MLDSA65_PUBLIC_KEY_BYTES];
        let mut seed = [0_u8; 32];
        let mut private_key = MaybeUninit::<boring_sys::MLDSA65_private_key>::uninit();
        let generated = unsafe {
            boring_sys::MLDSA65_generate_key(
                encoded_public_key.as_mut_ptr(),
                seed.as_mut_ptr(),
                private_key.as_mut_ptr(),
            )
        };
        assert_eq!(generated, 1);
        let private_key = unsafe { private_key.assume_init() };
        let verify_key = Mldsa65VerifyKey::from_bytes(encoded_public_key).unwrap();
        let public_key = [9_u8; ED25519_PUBLIC_KEY_LEN];
        let auth_key = [7_u8; 32];
        let transcript = RealityBoringTranscript {
            client_hello: vec![1, 0, 0, 3, 1, 2, 3],
            server_hello: vec![2, 0, 0, 2, 4, 5],
        };
        let mut authenticated = Vec::new();
        authenticated.extend_from_slice(&public_key);
        authenticated.extend_from_slice(&transcript.client_hello);
        authenticated.extend_from_slice(&transcript.server_hello);
        let message = hmac_sha512(&auth_key, &authenticated).unwrap();
        let mut signature =
            vec![0_u8; dae_outbound_stream::shared_transport::MLDSA65_SIGNATURE_BYTES];
        let signed = unsafe {
            boring_sys::MLDSA65_sign(
                signature.as_mut_ptr(),
                &private_key,
                message.as_ptr(),
                message.len(),
                std::ptr::null(),
                0,
            )
        };
        assert_eq!(signed, 1);
        assert!(reality_mldsa65_signature_matches(
            &verify_key,
            &public_key,
            &auth_key,
            &transcript,
            &signature,
        ));

        let mut wrong_transcript = transcript;
        wrong_transcript.server_hello[4] ^= 1;
        assert!(!reality_mldsa65_signature_matches(
            &verify_key,
            &public_key,
            &auth_key,
            &wrong_transcript,
            &signature,
        ));
    }
}
