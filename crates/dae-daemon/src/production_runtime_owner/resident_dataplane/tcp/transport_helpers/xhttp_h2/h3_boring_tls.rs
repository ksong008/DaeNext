use std::ffi::CString;
use std::io::Read;
use std::os::raw::c_int;
use std::sync::Arc;

use foreign_types::ForeignType;

use super::h3_transport::xhttp_h3_transport_config;
use super::*;

pub(super) fn build_chrome_boring_xhttp_h3_client_config(
    endpoint: &ResidentXhttpEndpointPlan,
    session_cache: Option<dae_outbound::shared_transport::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, String> {
    let policy = chrome_boring_xhttp_h3_policy(endpoint)?;
    let system_ca = if endpoint.allow_insecure {
        None
    } else {
        Some(
            dae_outbound::shared_transport::system_ca_snapshot()
                .map_err(|err| format!("load xHTTP H3 system CA bundle: {err}"))?,
        )
    };
    if cfg!(feature = "test-boringssl-quic") {
        return dae_outbound::shared_transport::boring_quic::build_boring_quic_client_config_with_session_cache(
            &policy,
            Arc::new(xhttp_h3_transport_config()?),
            session_cache,
        )
        .map_err(|err| format!("build xHTTP H3 Chrome BoringSSL QUIC config: {err}"));
    }
    build_chrome_boring_xhttp_h3_client_config_with_system_ca(endpoint, system_ca.as_deref())
}

pub(super) fn build_chrome_boring_xhttp_h3_client_config_with_system_ca(
    endpoint: &ResidentXhttpEndpointPlan,
    system_ca: Option<&dae_outbound::shared_transport::SystemCaSnapshot>,
) -> Result<quinn::ClientConfig, String> {
    let crypto = build_chrome_boring_xhttp_h3_crypto(endpoint, system_ca)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(xhttp_h3_transport_config()?));
    Ok(config)
}

fn build_chrome_boring_xhttp_h3_crypto(
    endpoint: &ResidentXhttpEndpointPlan,
    system_ca: Option<&dae_outbound::shared_transport::SystemCaSnapshot>,
) -> Result<quinn_boring::ClientConfig, String> {
    let mut crypto = quinn_boring::ClientConfig::new()
        .map_err(|err| format!("create xHTTP H3 BoringSSL QUIC config: {err}"))?;
    if !endpoint.allow_insecure {
        system_ca
            .ok_or_else(|| "xHTTP H3 BoringSSL config is missing system CA snapshot".to_owned())?
            .install_boring_context(crypto.ctx_mut())
            .map_err(|err| format!("install xHTTP H3 system CA bundle: {err}"))?;
    }
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

fn chrome_boring_xhttp_h3_policy(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<dae_outbound::shared_transport::boring_quic::BoringQuicClientPolicy, String> {
    dae_outbound::shared_transport::boring_quic::BoringQuicClientPolicy::new([b"h3".as_slice()])
        .map(|policy| {
            policy
                .allow_insecure(endpoint.allow_insecure)
                .zero_rtt(false)
                .client_hello_profile(
                    dae_outbound::shared_transport::boring_quic::BoringQuicClientHelloProfile::Chrome,
                )
        })
        .map_err(|err| format!("build xHTTP H3 Chrome BoringSSL QUIC policy: {err}"))
}

#[cfg(test)]
#[path = "h3_boring_tls_tests.rs"]
pub(super) mod tests;
