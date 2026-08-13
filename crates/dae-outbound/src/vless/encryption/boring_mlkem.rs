//! Small, audited Rust boundary for the vendor BoringSSL ML-KEM-768 API.
//!
//! The opaque BoringSSL key layouts intentionally never cross this module.
//! Only the protocol's fixed-size encoded public key, ciphertext, and shared
//! secret are exposed to VLESS Encryption. Secret-bearing buffers are cleared
//! through BoringSSL's constant-time memory wipe before being dropped.

use boring_sys::{
    MLKEM768_decap, MLKEM768_encap, MLKEM768_generate_key, MLKEM768_parse_public_key,
    MLKEM768_private_key, MLKEM768_public_key,
};
use std::io::{Error, ErrorKind, Result};
use std::mem::MaybeUninit;

pub(crate) const PUBLIC_KEY_BYTES: usize = 1184;
pub(crate) const CIPHERTEXT_BYTES: usize = 1088;
pub(crate) const SHARED_SECRET_BYTES: usize = 32;

struct SecretKey(MLKEM768_private_key);

impl Drop for SecretKey {
    fn drop(&mut self) {
        unsafe {
            boring_sys::OPENSSL_cleanse(
                (&mut self.0 as *mut MLKEM768_private_key).cast(),
                std::mem::size_of::<MLKEM768_private_key>(),
            );
        }
    }
}

struct PublicKey(MLKEM768_public_key);

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            boring_sys::OPENSSL_cleanse(
                (&mut self.0 as *mut MLKEM768_public_key).cast(),
                std::mem::size_of::<MLKEM768_public_key>(),
            );
        }
    }
}

pub(crate) struct EncapsulationKey {
    key: PublicKey,
}

pub(crate) struct SharedSecret([u8; SHARED_SECRET_BYTES]);

impl SharedSecret {
    pub(crate) fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        unsafe {
            boring_sys::OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.len());
        }
    }
}

impl EncapsulationKey {
    pub(crate) fn from_encoded(encoded: &[u8]) -> Result<Self> {
        if encoded.len() != PUBLIC_KEY_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "VLESS ML-KEM-768 public key length mismatch",
            ));
        }
        let mut key = MaybeUninit::<MLKEM768_public_key>::zeroed();
        let mut cbs = boring_sys::CBS {
            data: encoded.as_ptr(),
            len: encoded.len(),
        };
        let ok = unsafe { MLKEM768_parse_public_key(key.as_mut_ptr(), &mut cbs) };
        if ok != 1 || cbs.len != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid VLESS ML-KEM-768 public key",
            ));
        }
        Ok(Self {
            key: PublicKey(unsafe { key.assume_init() }),
        })
    }

    pub(crate) fn encapsulate(&self) -> ([u8; CIPHERTEXT_BYTES], SharedSecret) {
        let mut ciphertext = [0_u8; CIPHERTEXT_BYTES];
        let mut secret = [0_u8; SHARED_SECRET_BYTES];
        unsafe { MLKEM768_encap(ciphertext.as_mut_ptr(), secret.as_mut_ptr(), &self.key.0) };
        (ciphertext, SharedSecret(secret))
    }
}

pub(crate) struct DecapsulationKey {
    key: SecretKey,
}

impl DecapsulationKey {
    pub(crate) fn generate() -> ([u8; PUBLIC_KEY_BYTES], Self) {
        let mut public = [0_u8; PUBLIC_KEY_BYTES];
        let mut private = MaybeUninit::<MLKEM768_private_key>::zeroed();
        unsafe {
            MLKEM768_generate_key(
                public.as_mut_ptr(),
                std::ptr::null_mut(),
                private.as_mut_ptr(),
            )
        };
        (
            public,
            Self {
                key: SecretKey(unsafe { private.assume_init() }),
            },
        )
    }

    pub(crate) fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret> {
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "VLESS ML-KEM-768 ciphertext length mismatch",
            ));
        }
        let mut secret = [0_u8; SHARED_SECRET_BYTES];
        let ok = unsafe {
            MLKEM768_decap(
                secret.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                &self.key.0,
            )
        };
        if ok != 1 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "VLESS ML-KEM-768 decapsulation failed",
            ));
        }
        Ok(SharedSecret(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::kem::{
        Ciphertext as AwsCiphertext, DecapsulationKey as AwsDecapsulationKey,
        EncapsulationKey as AwsEncapsulationKey, ML_KEM_768,
    };

    #[test]
    fn boring_mlkem_round_trip_has_fixed_wire_lengths() {
        let (public, private) = DecapsulationKey::generate();
        let encapsulation = EncapsulationKey::from_encoded(&public).unwrap();
        let (ciphertext, sender_secret) = encapsulation.encapsulate();
        let receiver_secret = private.decapsulate(&ciphertext).unwrap();
        assert_eq!(ciphertext.len(), CIPHERTEXT_BYTES);
        assert_eq!(sender_secret.as_bytes(), receiver_secret.as_bytes());
    }

    #[test]
    fn boring_mlkem_rejects_trailing_or_short_public_key() {
        assert!(EncapsulationKey::from_encoded(&[0_u8; PUBLIC_KEY_BYTES - 1]).is_err());
        let (mut public, _) = DecapsulationKey::generate();
        public[0] ^= 0xff;
        let mut trailing = public.to_vec();
        trailing.push(0);
        assert!(EncapsulationKey::from_encoded(&trailing).is_err());
    }

    #[test]
    fn boring_mlkem_rejects_wrong_ciphertext_length() {
        let (_, private) = DecapsulationKey::generate();
        assert!(private.decapsulate(&[0_u8; CIPHERTEXT_BYTES - 1]).is_err());
    }

    #[test]
    fn boring_encapsulation_interoperates_with_aws_lc_decapsulation() {
        let aws_private = AwsDecapsulationKey::generate(&ML_KEM_768).unwrap();
        let public = aws_private
            .encapsulation_key()
            .unwrap()
            .key_bytes()
            .unwrap();
        let boring_public = EncapsulationKey::from_encoded(public.as_ref()).unwrap();
        let (ciphertext, boring_secret) = boring_public.encapsulate();
        let aws_secret = aws_private
            .decapsulate(AwsCiphertext::from(ciphertext.as_slice()))
            .unwrap();
        assert_eq!(boring_secret.as_bytes(), aws_secret.as_ref());
    }

    #[test]
    fn aws_lc_encapsulation_interoperates_with_boring_decapsulation() {
        let (public, boring_private) = DecapsulationKey::generate();
        let aws_public = AwsEncapsulationKey::new(&ML_KEM_768, &public).unwrap();
        let (ciphertext, aws_secret) = aws_public.encapsulate().unwrap();
        let boring_secret = boring_private.decapsulate(ciphertext.as_ref()).unwrap();
        assert_eq!(boring_secret.as_bytes(), aws_secret.as_ref());
    }
}
