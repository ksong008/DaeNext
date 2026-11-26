#![allow(
    clippy::missing_safety_doc,
    clippy::redundant_static_lifetimes,
    clippy::too_many_arguments,
    clippy::unreadable_literal,
    clippy::upper_case_acronyms,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports
)]

use std::convert::TryInto;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_uint, c_ulong};

#[allow(
    clippy::useless_transmute,
    clippy::derive_partial_eq_without_eq,
    clippy::ptr_offset_with_cast,
    dead_code,
    unnecessary_transmutes
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// explicitly require presence of some symbols to check if the bindings worked
pub use generated::{ssl_compliance_policy_t, ERR_add_error_data, SSL_set1_groups}; // if these are missing, your include path is incorrect or has a wrong version of boringssl
pub use generated::{BIO_new, OPENSSL_free, SSL_ERROR_NONE}; // if these are missing, your include path is incorrect
#[cfg(feature = "fips")]
pub use generated::{FIPS_mode, SSL_CTX_set_compliance_policy}; // your include path is incorrect or has a version of boringssl without FIPS support
#[cfg(feature = "mlkem")]
pub use generated::{MLKEM768_encap, MLKEM768_private_key_from_seed}; // your include path is incorrect or has a version of boringssl without mlkem support
#[cfg(feature = "rpk")]
pub use generated::{SSL_CREDENTIAL_new_raw_public_key_empty, SSL_CREDENTIAL_set1_spki}; // your include path is incorrect or has a version of boringssl without rpk support

pub use generated::*;

#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = u64;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = u32;

#[must_use]
pub const fn ERR_PACK(l: c_int, f: c_int, r: c_int) -> c_ulong {
    ((l as c_ulong & 0x0FF) << 24) | ((f as c_ulong & 0xFFF) << 12) | (r as c_ulong & 0xFFF)
}

#[must_use]
pub const fn ERR_GET_LIB(l: c_uint) -> c_int {
    ((l >> 24) & 0x0FF) as c_int
}

#[must_use]
pub const fn ERR_GET_FUNC(l: c_uint) -> c_int {
    ((l >> 12) & 0xFFF) as c_int
}

#[must_use]
pub const fn ERR_GET_REASON(l: c_uint) -> c_int {
    (l & 0xFFF) as c_int
}

pub fn init() {
    unsafe {
        CRYPTO_library_init();
    }
}

// CBS_init is inline in BoringSSL, so bindgen can't generate bindings for it.
#[inline]
#[must_use]
pub fn cbs_init(data: &[u8]) -> CBS {
    CBS {
        data: data.as_ptr(),
        len: data.len(),
    }
}

pub mod internal {
    use super::EVP_MD;
    use std::os::raw::c_int;

    extern "C" {
        /// Calculates `out_len` bytes of the TLS 1.2 PRF using `digest` and writes
        /// them to `out`.
        ///
        /// This symbol is exported by BoringSSL, but it is declared in an internal
        /// header (`crypto/fipsmodule/tls/internal.h`) and is therefore not present
        /// in generated bindgen output.
        pub fn CRYPTO_tls1_prf(
            digest: *const EVP_MD,
            out: *mut u8,
            out_len: usize,
            secret: *const u8,
            secret_len: usize,
            label: *const u8,
            label_len: usize,
            seed1: *const u8,
            seed1_len: usize,
            seed2: *const u8,
            seed2_len: usize,
        ) -> c_int;
    }
}

// BoringSSL 0.20261105.0 implements the one-shot SHA functions inline.
// Mirror those helpers for Rust callers, including cleansing the stack state.
macro_rules! one_shot_sha {
    ($name:ident, $context:ty, $init:ident, $update:ident, $final:ident) => {
        pub unsafe extern "C" fn $name(data: *const u8, len: usize, out: *mut u8) -> *mut u8 {
            let mut context = std::mem::MaybeUninit::<$context>::uninit();
            unsafe {
                $init(context.as_mut_ptr());
                $update(context.as_mut_ptr(), data.cast(), len);
                $final(out, context.as_mut_ptr());
                OPENSSL_cleanse(context.as_mut_ptr().cast(), std::mem::size_of::<$context>());
            }
            out
        }
    };
}

one_shot_sha!(SHA1, SHA_CTX, SHA1_Init, SHA1_Update, SHA1_Final);
one_shot_sha!(SHA224, SHA256_CTX, SHA224_Init, SHA224_Update, SHA224_Final);
one_shot_sha!(SHA256, SHA256_CTX, SHA256_Init, SHA256_Update, SHA256_Final);
one_shot_sha!(SHA384, SHA512_CTX, SHA384_Init, SHA384_Update, SHA384_Final);
one_shot_sha!(SHA512, SHA512_CTX, SHA512_Init, SHA512_Update, SHA512_Final);
one_shot_sha!(
    SHA512_256,
    SHA512_CTX,
    SHA512_256_Init,
    SHA512_256_Update,
    SHA512_256_Final
);

#[cfg(test)]
mod sha_compat_tests {
    use super::*;

    #[test]
    fn one_shot_sha_matches_known_vectors() {
        type Hash = unsafe extern "C" fn(*const u8, usize, *mut u8) -> *mut u8;
        let algorithms: [(Hash, usize, &str, &str); 6] = [
            (SHA1, 20, "a9993e364706816aba3e25717850c26c9cd0d89d", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (SHA224, 28, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
            (SHA256, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (SHA384, 48, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
            (SHA512, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (SHA512_256, 32, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
        ];
        for (hash, size, abc, empty) in algorithms {
            for (input, expected) in [(b"abc".as_slice(), abc), (b"".as_slice(), empty)] {
                let mut output = [0; 64];
                let result = unsafe { hash(input.as_ptr(), input.len(), output.as_mut_ptr()) };
                assert_eq!(result, output.as_mut_ptr());
                let actual: String = output[..size]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(actual, expected);
            }
        }
    }
}
