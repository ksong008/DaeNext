use std::ffi::CString;
use std::io::Read;
use std::os::raw::c_int;
use std::sync::Arc;

use foreign_types::ForeignType;

use super::h3_transport::xhttp_h3_transport_config;
use super::*;

pub(super) fn build_chrome_boring_xhttp_h3_client_config(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<quinn::ClientConfig, String> {
    let crypto = build_chrome_boring_xhttp_h3_crypto(endpoint)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(xhttp_h3_transport_config()?));
    Ok(config)
}

fn build_chrome_boring_xhttp_h3_crypto(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<quinn_boring::ClientConfig, String> {
    let mut crypto = quinn_boring::ClientConfig::new()
        .map_err(|err| format!("create xHTTP H3 BoringSSL QUIC config: {err}"))?;
    crypto.verify_peer(!endpoint.allow_insecure);
    crypto
        .set_alpn(&[b"h3".to_vec()])
        .map_err(|err| format!("set xHTTP H3 BoringSSL QUIC ALPN: {err}"))?;
    configure_chrome_boring_quic_context(crypto.ctx_mut())?;
    Ok(crypto)
}

fn configure_chrome_boring_quic_context(
    context: &mut boring::ssl::SslContext,
) -> Result<(), String> {
    let curves = CString::new("X25519:P-256:P-384").expect("static curve list has no NUL");
    let configured = unsafe {
        boring_sys::SSL_CTX_set_grease_enabled(context.as_ptr(), 1);
        boring_sys::SSL_CTX_set_permute_extensions(context.as_ptr(), 1);
        boring_sys::SSL_CTX_enable_ocsp_stapling(context.as_ptr());
        boring_sys::SSL_CTX_enable_signed_cert_timestamps(context.as_ptr());
        boring_sys::SSL_CTX_set1_curves_list(context.as_ptr(), curves.as_ptr())
    };
    if configured != 1 {
        return Err(format!(
            "configure xHTTP H3 Chrome BoringSSL groups: {}",
            boring::error::ErrorStack::get()
        ));
    }
    let compression_configured = unsafe {
        boring_sys::SSL_CTX_add_cert_compression_alg(
            context.as_ptr(),
            boring_sys::TLSEXT_cert_compression_brotli as u16,
            None,
            Some(decompress_brotli_certificate),
        )
    };
    if compression_configured != 1 {
        return Err(format!(
            "configure xHTTP H3 Chrome BoringSSL certificate compression: {}",
            boring::error::ErrorStack::get()
        ));
    }
    Ok(())
}

unsafe extern "C" fn decompress_brotli_certificate(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut boring_sys::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> c_int {
    let compressed = unsafe { std::slice::from_raw_parts(input, input_len) };
    let mut decompressed = Vec::with_capacity(uncompressed_len);
    let mut decoder = brotli::Decompressor::new(compressed, 4096);
    if decoder.read_to_end(&mut decompressed).is_err() || decompressed.len() != uncompressed_len {
        return 0;
    }
    let buffer = unsafe {
        boring_sys::CRYPTO_BUFFER_new(
            decompressed.as_ptr(),
            decompressed.len(),
            std::ptr::null_mut(),
        )
    };
    if buffer.is_null() {
        return 0;
    }
    unsafe {
        *out = buffer;
    }
    1
}

#[cfg(test)]
#[path = "h3_boring_tls_tests.rs"]
pub(super) mod tests;
