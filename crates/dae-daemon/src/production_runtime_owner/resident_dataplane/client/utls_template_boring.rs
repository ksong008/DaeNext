use super::*;
use foreign_types::ForeignTypeRef;

unsafe extern "C" {
    fn DAE_SSL_set1_utls_template(
        ssl: *mut boring_sys::SSL,
        cipher_suites: *const u16,
        num_cipher_suites: usize,
        extension_order: *const u16,
        num_extension_order: usize,
        supported_versions: *const u16,
        num_supported_versions: usize,
        supported_groups: *const u16,
        num_supported_groups: usize,
        key_share_groups: *const u16,
        num_key_share_groups: usize,
        signature_schemes: *const u16,
        num_signature_schemes: usize,
        delegated_credential_signature_schemes: *const u16,
        num_delegated_credential_signature_schemes: usize,
        record_size_limit: u16,
        empty_extensions: *const u16,
        num_empty_extensions: usize,
        grease_placeholder: u16,
        session_id_len: usize,
        padding_target_handshake_len: usize,
        grease_enabled: libc::c_int,
    ) -> libc::c_int;

    fn SSL_add_application_settings(
        ssl: *mut boring_sys::SSL,
        proto: *const u8,
        proto_len: usize,
        settings: *const u8,
        settings_len: usize,
    ) -> libc::c_int;

    fn SSL_set_alps_use_new_codepoint(ssl: *mut boring_sys::SSL, use_new: libc::c_int);
}

pub(super) fn configure_utls_template_boring_context(
    builder: &mut boring::ssl::SslConnectorBuilder,
    fingerprint: &ResidentUtlsFingerprintPlan,
) -> Result<(), String> {
    let Some(template) = utls_template_for_plan(fingerprint) else {
        return Ok(());
    };
    if template.capabilities.ocsp_stapling {
        builder.enable_ocsp_stapling();
    }
    if template.capabilities.signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }
    if template.capabilities.cert_compression_brotli {
        builder
            .add_certificate_compression_algorithm(ResidentBrotliCertCompressor)
            .map_err(|err| format!("enable VLESS BoringSSL brotli cert compression: {err}"))?;
    }
    Ok(())
}

pub(super) fn configure_utls_template_boring_ssl(
    ssl: &mut SslRef,
    proxy: &ResidentProxyPlan,
) -> Result<(), String> {
    let Some(fingerprint) = proxy.utls_fingerprint.as_ref() else {
        return Ok(());
    };
    let Some(template) = utls_template_for_plan(fingerprint) else {
        return Ok(());
    };
    if template.key_share_groups.is_empty()
        && (proxy.reality.is_some() || is_xtls_rprx_vision_flow(&proxy.flow))
    {
        return Err(format!(
            "uTLS template {} cannot be used with TLS 1.3-only VLESS flow",
            template.name
        ));
    }
    if template.key_share_groups.is_empty() {
        ssl.set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|err| format!("set VLESS BoringSSL template max TLS version: {err}"))?;
    }

    let ok = unsafe {
        DAE_SSL_set1_utls_template(
            ssl.as_ptr(),
            template.cipher_suites.as_ptr(),
            template.cipher_suites.len(),
            template.extension_order.as_ptr(),
            template.extension_order.len(),
            template.supported_versions.as_ptr(),
            template.supported_versions.len(),
            template.supported_groups.as_ptr(),
            template.supported_groups.len(),
            template.key_share_groups.as_ptr(),
            template.key_share_groups.len(),
            template.signature_schemes.as_ptr(),
            template.signature_schemes.len(),
            template.delegated_credential_signature_schemes.as_ptr(),
            template.delegated_credential_signature_schemes.len(),
            template.record_size_limit.unwrap_or(0),
            template.empty_extensions.as_ptr(),
            template.empty_extensions.len(),
            dae_outbound::shared_transport::UTLS_TEMPLATE_GREASE,
            template.session_id_len,
            template.padding_target_handshake_len.unwrap_or(0),
            if template.capabilities.grease { 1 } else { 0 },
        )
    };
    if ok != 1 {
        return Err(format!(
            "configure VLESS BoringSSL uTLS template {}: {}",
            template.name,
            boring::error::ErrorStack::get()
        ));
    }

    if template.capabilities.alps_old_h2 {
        configure_old_alps_h2(ssl)?;
    }

    Ok(())
}

fn utls_template_for_plan(
    fingerprint: &ResidentUtlsFingerprintPlan,
) -> Option<&'static dae_outbound::shared_transport::UtlsRuntimeTemplate> {
    dae_outbound::shared_transport::resolve_utls_client_hello_id(&fingerprint.name)
        .ok()
        .and_then(|fingerprint| {
            dae_outbound::shared_transport::resolve_utls_runtime_template(&fingerprint)
        })
}

fn configure_old_alps_h2(ssl: &mut SslRef) -> Result<(), String> {
    const H2: &[u8] = b"h2";
    unsafe {
        SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 0);
        let ok =
            SSL_add_application_settings(ssl.as_ptr(), H2.as_ptr(), H2.len(), std::ptr::null(), 0);
        if ok == 1 {
            Ok(())
        } else {
            Err("configure VLESS BoringSSL old ALPS h2 settings".to_owned())
        }
    }
}

struct ResidentBrotliCertCompressor;

impl CertificateCompressor for ResidentBrotliCertCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)?;
        Ok(())
    }
}

#[cfg(test)]
mod capture_tests;
