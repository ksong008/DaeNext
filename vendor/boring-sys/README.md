# Low-level bindings to BoringSSL

[BoringSSL](https://boringssl.googlesource.com/boringssl) is Google's fork of OpenSSL for Chrome/Chromium and Android.

This crate builds the BoringSSL library (or optionally links a pre-built version) and generates FFI bindings for it.
It supports [FIPS-compatible builds of BoringSSL](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md),
as well as [Post-Quantum crypto](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
and [Raw Public Key](https://docs.rs/boring/latest/boring/ssl/struct.SslRef.html#method.peer_pubkey) extensions.

To use BoringSSL from Rust, prefer the [higher-level safe API](https://docs.rs/boring).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## DaeNext source revision

The Rust bindings are based on Cloudflare boring-sys 5.6.0. The embedded
BoringSSL source is Google release 0.20261105.0, commit
3dc4b63808921e914a3fb1fa61869abc3938781b.

DaeNext retains typed ClientHello templates, REALITY authentication, explicit
signature GREASE, trust-anchor range selection and checkpoint-only
Davidben-08 MTC verification. Server padding uses the upstream implementation.
The PQ compatibility patch is rebased onto this revision and retains the
legacy Kyber groups used by existing templates.
