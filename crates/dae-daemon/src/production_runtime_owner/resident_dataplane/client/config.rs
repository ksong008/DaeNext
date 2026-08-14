use super::*;
use dae_outbound::shared_transport::reality::reality_client_version;

pub(super) fn boring_vless_connector(
    proxy: &ResidentProxyPlan,
    policy: &ResidentTlsPolicy,
) -> Result<Arc<ResidentBoringTlsContextEntry>, String> {
    require_tcp_tls_session_policy(policy)?;
    let system_ca = proxy_system_ca_snapshot(proxy)?;
    let key = ResidentTlsClientConfigKey::from_proxy(proxy, system_ca.as_deref());
    let alpn = boring_alpn_wire(proxy, policy)?;
    boring_connector_cached(
        key,
        "VLESS",
        system_ca.as_deref(),
        policy.verification.allow_insecure(),
        boring_read_ahead_enabled(proxy),
        proxy.utls_fingerprint.is_none()
            && (policy.verification.reality_material().is_some()
                || proxy.execution_plan().protocol == ResidentProtocolShape::VlessVision),
        proxy.utls_fingerprint.as_ref(),
        &alpn,
    )
}

fn boring_connector_cached(
    key: ResidentTlsClientConfigKey,
    context: &'static str,
    system_ca: Option<&SystemCaSnapshot>,
    allow_insecure: bool,
    read_ahead: bool,
    tls13_only: bool,
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
    alpn: &[u8],
) -> Result<Arc<ResidentBoringTlsContextEntry>, String> {
    let cache =
        BORING_CONNECTOR_CACHE.get_or_init(|| Mutex::new(ResidentTlsConfigCache::default()));
    {
        let mut cache = cache
            .lock()
            .map_err(|_| format!("{context} BoringSSL connector cache lock poisoned"))?;
        if let Some(connector) = cache.get(&key) {
            return Ok(connector);
        }
    }
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|err| format!("create {context} BoringSSL connector: {err}"))?;
    if let Some(system_ca) = system_ca {
        system_ca.install_boring_builder(&mut builder);
    }
    configure_boring_certificate_verification(&mut builder, allow_insecure);
    builder.set_read_ahead(read_ahead);
    if tls13_only {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set {context} BoringSSL min TLS version: {err}"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set {context} BoringSSL max TLS version: {err}"))?;
    }
    if let Some(fingerprint) = fingerprint {
        configure_boring_fingerprint(&mut builder, fingerprint)?;
        configure_utls_template_boring_context(&mut builder, fingerprint)?;
    }
    if !alpn.is_empty() {
        builder
            .set_alpn_protos(alpn)
            .map_err(|err| format!("set {context} BoringSSL ALPN: {err}"))?;
    }
    let connector = Arc::new(ResidentBoringTlsContextEntry::build(builder, context)?);
    let mut cache = cache
        .lock()
        .map_err(|_| format!("{context} BoringSSL connector cache lock poisoned"))?;
    Ok(cache.insert_or_get(key, connector))
}

pub(super) fn boring_xhttp_endpoint_connector(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<Arc<ResidentBoringTlsContextEntry>, String> {
    let system_ca = xhttp_endpoint_system_ca_snapshot(endpoint)?;
    let key = ResidentTlsClientConfigKey::from_xhttp_endpoint(endpoint, system_ca.as_deref());
    let cache =
        BORING_CONNECTOR_CACHE.get_or_init(|| Mutex::new(ResidentTlsConfigCache::default()));
    {
        let mut cache = cache
            .lock()
            .map_err(|_| "xHTTP BoringSSL connector cache lock poisoned".to_owned())?;
        if let Some(connector) = cache.get(&key) {
            return Ok(connector);
        }
    }
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|err| format!("create xHTTP BoringSSL connector: {err}"))?;
    if let Some(system_ca) = system_ca {
        system_ca.install_boring_builder(&mut builder);
    }
    configure_boring_certificate_verification(&mut builder, endpoint.allow_insecure);
    if endpoint.ech.is_some() || endpoint.reality.is_some() {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set xHTTP BoringSSL min TLS version: {err}"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set xHTTP BoringSSL max TLS version: {err}"))?;
    }
    if let Some(fingerprint) = &endpoint.utls_fingerprint {
        configure_boring_fingerprint(&mut builder, fingerprint)?;
        configure_utls_template_boring_context(&mut builder, fingerprint)?;
    }
    let alpn = encode_boring_alpn_wire(&endpoint.alpn, "xHTTP")?;
    if !alpn.is_empty() {
        builder
            .set_alpn_protos(&alpn)
            .map_err(|err| format!("set xHTTP BoringSSL ALPN: {err}"))?;
    }
    let connector = Arc::new(ResidentBoringTlsContextEntry::build(builder, "xHTTP")?);
    let mut cache = cache
        .lock()
        .map_err(|_| "xHTTP BoringSSL connector cache lock poisoned".to_owned())?;
    Ok(cache.insert_or_get(key, connector))
}

pub(super) fn configure_boring_certificate_verification(
    builder: &mut SslConnectorBuilder,
    allow_insecure: bool,
) {
    if allow_insecure {
        builder.set_verify(SslVerifyMode::NONE);
        return;
    }
    builder.set_verify_callback(SslVerifyMode::PEER, |preverify_ok, context| {
        if preverify_ok {
            return true;
        }
        if context.error_depth() != 0
            || context.verify_result() != Err(X509VerifyError::HOSTNAME_MISMATCH)
        {
            return false;
        }
        let Ok(ssl_index) = X509StoreContext::ssl_idx() else {
            return false;
        };
        let Some(ssl) = context.ex_data(ssl_index) else {
            return false;
        };
        let Some(public_name) = ssl.get_ech_name_override() else {
            return false;
        };
        let Ok(public_name) = std::str::from_utf8(public_name) else {
            return false;
        };
        context
            .current_cert()
            .and_then(|certificate| certificate.check_host(public_name).ok())
            .unwrap_or(false)
    });
}

impl ResidentTlsClientConfigKey {
    pub(super) fn from_proxy(
        proxy: &ResidentProxyPlan,
        system_ca: Option<&SystemCaSnapshot>,
    ) -> Self {
        Self {
            protocol_namespace: proxy.protocol.to_owned(),
            server_name: proxy.server_name.clone(),
            flow: proxy.flow.clone(),
            alpn: proxy.alpn.clone(),
            allow_insecure: proxy.allow_insecure,
            system_ca: system_ca.map(|snapshot| snapshot.identity().clone()),
            utls_fingerprint: proxy
                .utls_fingerprint
                .as_ref()
                .map(ResidentTlsFingerprintConfigKey::from_plan),
            ech: proxy.ech.as_ref().map(|ech| *ech.config_list_sha256()),
            reality: proxy
                .reality
                .as_ref()
                .map(ResidentRealityConfigKey::from_plan),
        }
    }

    pub(super) fn from_xhttp_endpoint(
        endpoint: &ResidentXhttpEndpointPlan,
        system_ca: Option<&SystemCaSnapshot>,
    ) -> Self {
        Self {
            protocol_namespace: "xhttp-endpoint".to_owned(),
            server_name: endpoint.server_name.clone(),
            flow: String::new(),
            alpn: endpoint.alpn.clone(),
            allow_insecure: endpoint.allow_insecure,
            system_ca: system_ca.map(|snapshot| snapshot.identity().clone()),
            utls_fingerprint: endpoint
                .utls_fingerprint
                .as_ref()
                .map(ResidentTlsFingerprintConfigKey::from_plan),
            ech: endpoint.ech.as_ref().map(|ech| *ech.config_list_sha256()),
            reality: endpoint
                .reality
                .as_ref()
                .map(ResidentRealityConfigKey::from_plan),
        }
    }
}

impl ResidentTlsFingerprintConfigKey {
    pub(super) fn from_plan(plan: &ResidentUtlsFingerprintPlan) -> Self {
        Self {
            source: plan.source,
            requested: plan.requested.clone(),
            name: plan.name.clone(),
            canonical: plan.canonical.clone(),
            family: plan.family.clone(),
            client: plan.client.clone(),
            randomized: plan.randomized,
            alpn_policy: plan.alpn_policy.clone(),
            default_alpn: plan.default_alpn.clone(),
        }
    }
}

impl ResidentRealityConfigKey {
    pub(super) fn from_plan(plan: &ResidentRealityUnderlayPlan) -> Self {
        Self {
            public_key: plan.public_key,
            short_id: plan.short_id.clone(),
            mldsa65_verify: plan.mldsa65_verify.as_ref().map(|key| *key.sha256()),
        }
    }
}

pub(super) fn rustls_vless_client_config(
    proxy: &ResidentProxyPlan,
    policy: &ResidentTlsPolicy,
) -> Result<Arc<ClientConfig>, String> {
    require_tcp_tls_session_policy(policy)?;
    if proxy.ech.is_some() {
        return Err("VLESS ECH must use the authenticated-retry BoringSSL factory".to_owned());
    }
    if proxy.reality.is_some() {
        if proxy
            .reality
            .as_ref()
            .is_some_and(|reality| reality.mldsa65_verify.is_some())
        {
            return Err("VLESS Reality PQV requires the BoringSSL Reality engine".to_owned());
        }
        return build_rustls_vless_client_config(proxy, policy);
    }
    let system_ca = proxy_system_ca_snapshot(proxy)?;
    let key = ResidentTlsClientConfigKey::from_proxy(proxy, system_ca.as_deref());
    let cache =
        RUSTLS_CLIENT_CONFIG_CACHE.get_or_init(|| Mutex::new(ResidentTlsConfigCache::default()));
    {
        let mut cache = cache
            .lock()
            .map_err(|_| "VLESS rustls client config cache lock poisoned".to_owned())?;
        if let Some(config) = cache.get(&key) {
            return Ok(config);
        }
    }
    let config =
        build_rustls_vless_client_config_with_system_ca(proxy, policy, system_ca.as_deref())?;
    let mut cache = cache
        .lock()
        .map_err(|_| "VLESS rustls client config cache lock poisoned".to_owned())?;
    Ok(cache.insert_or_get(key, config))
}

fn build_rustls_vless_client_config(
    proxy: &ResidentProxyPlan,
    policy: &ResidentTlsPolicy,
) -> Result<Arc<ClientConfig>, String> {
    build_rustls_vless_client_config_with_system_ca(proxy, policy, None)
}

fn build_rustls_vless_client_config_with_system_ca(
    proxy: &ResidentProxyPlan,
    policy: &ResidentTlsPolicy,
    system_ca: Option<&SystemCaSnapshot>,
) -> Result<Arc<ClientConfig>, String> {
    let builder = if policy.verification.reality_material().is_some() {
        if proxy.utls_fingerprint.is_some() {
            return Err("VLESS Reality with uTLS fingerprint requires a fingerprint-capable Reality TLS underlay; rustls cannot implement uTLS fingerprints".to_owned());
        }
        let provider = rustls_reality_crypto_provider();
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| format!("create VLESS Reality rustls provider: {err}"))?
    } else if proxy.execution_plan().protocol == ResidentProtocolShape::VlessVision {
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        ClientConfig::builder()
    };
    let mut config = if let Some((public_key, short_id)) = policy.verification.reality_material() {
        let reality_config = RealityConfig::new(*public_key, short_id.to_vec())
            .map_err(|err| format!("create VLESS Reality config: {err}"))?
            .with_client_version(reality_client_version());
        builder
            .dangerous()
            .with_custom_certificate_verifier(ResidentRealityFallbackRejectVerifier::new())
            .with_reality(reality_config)
            .with_no_client_auth()
    } else if policy.verification.allow_insecure() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(ResidentInsecureCertVerifier::new())
            .with_no_client_auth()
    } else {
        let roots = system_ca
            .ok_or_else(|| "VLESS secure TLS config is missing system CA snapshot".to_owned())?
            .rustls_roots();
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = policy
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

pub(super) fn rustls_xhttp_endpoint_client_config(
    endpoint: &ResidentXhttpEndpointPlan,
    policy: &ResidentTlsPolicy,
) -> Result<Arc<ClientConfig>, String> {
    require_tcp_tls_session_policy(policy)?;
    if endpoint.ech.is_some() {
        return Err("xHTTP ECH must use the authenticated-retry BoringSSL factory".to_owned());
    }
    if endpoint.reality.is_some() {
        if endpoint
            .reality
            .as_ref()
            .is_some_and(|reality| reality.mldsa65_verify.is_some())
        {
            return Err("xHTTP Reality PQV requires the BoringSSL Reality engine".to_owned());
        }
        return build_rustls_xhttp_endpoint_client_config(policy);
    }
    let system_ca = xhttp_endpoint_system_ca_snapshot(endpoint)?;
    let key = ResidentTlsClientConfigKey::from_xhttp_endpoint(endpoint, system_ca.as_deref());
    let cache =
        RUSTLS_CLIENT_CONFIG_CACHE.get_or_init(|| Mutex::new(ResidentTlsConfigCache::default()));
    {
        let mut cache = cache
            .lock()
            .map_err(|_| "xHTTP rustls client config cache lock poisoned".to_owned())?;
        if let Some(config) = cache.get(&key) {
            return Ok(config);
        }
    }
    let config =
        build_rustls_xhttp_endpoint_client_config_with_system_ca(policy, system_ca.as_deref())?;
    let mut cache = cache
        .lock()
        .map_err(|_| "xHTTP rustls client config cache lock poisoned".to_owned())?;
    Ok(cache.insert_or_get(key, config))
}

fn build_rustls_xhttp_endpoint_client_config(
    policy: &ResidentTlsPolicy,
) -> Result<Arc<ClientConfig>, String> {
    build_rustls_xhttp_endpoint_client_config_with_system_ca(policy, None)
}

fn build_rustls_xhttp_endpoint_client_config_with_system_ca(
    policy: &ResidentTlsPolicy,
    system_ca: Option<&SystemCaSnapshot>,
) -> Result<Arc<ClientConfig>, String> {
    let builder = if policy.verification.reality_material().is_some() {
        let provider = rustls_reality_crypto_provider();
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| format!("create xHTTP Reality rustls provider: {err}"))?
    } else {
        ClientConfig::builder()
    };
    let mut config = if let Some((public_key, short_id)) = policy.verification.reality_material() {
        let reality_config = RealityConfig::new(*public_key, short_id.to_vec())
            .map_err(|err| format!("create xHTTP Reality config: {err}"))?
            .with_client_version(reality_client_version());
        builder
            .dangerous()
            .with_custom_certificate_verifier(ResidentRealityFallbackRejectVerifier::new())
            .with_reality(reality_config)
            .with_no_client_auth()
    } else if policy.verification.allow_insecure() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(ResidentInsecureCertVerifier::new())
            .with_no_client_auth()
    } else {
        let roots = system_ca
            .ok_or_else(|| "xHTTP secure TLS config is missing system CA snapshot".to_owned())?
            .rustls_roots();
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = policy
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

fn proxy_system_ca_snapshot(
    proxy: &ResidentProxyPlan,
) -> Result<Option<Arc<SystemCaSnapshot>>, String> {
    if proxy.allow_insecure || proxy.reality.is_some() {
        return Ok(None);
    }
    system_ca_snapshot()
        .map(Some)
        .map_err(|err| format!("load VLESS system CA bundle: {err}"))
}

fn xhttp_endpoint_system_ca_snapshot(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<Option<Arc<SystemCaSnapshot>>, String> {
    if endpoint.allow_insecure || endpoint.reality.is_some() {
        return Ok(None);
    }
    system_ca_snapshot()
        .map(Some)
        .map_err(|err| format!("load xHTTP system CA bundle: {err}"))
}

pub(super) fn rustls_reality_crypto_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = rustls_reality_cipher_suites();
    provider.kx_groups = rustls_reality_kx_groups();
    provider
}

fn rustls_reality_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ]
}

fn rustls_reality_kx_groups() -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ]
}

#[derive(Debug)]
pub(super) struct ResidentInsecureCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ResidentInsecureCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }
}

impl ServerCertVerifier for ResidentInsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub(super) struct ResidentRealityFallbackRejectVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ResidentRealityFallbackRejectVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }
}

impl ServerCertVerifier for ResidentRealityFallbackRejectVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Err(RustlsError::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(super) fn configure_boring_fingerprint(
    builder: &mut boring::ssl::SslConnectorBuilder,
    fingerprint: &ResidentUtlsFingerprintPlan,
) -> Result<(), String> {
    match fingerprint.family.as_str() {
        UTLS_FAMILY_FIREFOX => {
            builder
                .set_curves_list("X25519:P-256:P-384:P-521")
                .map_err(|err| format!("set VLESS BoringSSL Firefox-style groups: {err}"))?;
        }
        UTLS_FAMILY_ANDROID => {
            builder
                .set_curves_list("X25519:P-256")
                .map_err(|err| format!("set VLESS BoringSSL Android-style groups: {err}"))?;
        }
        _ => {
            builder.set_grease_enabled(true);
            builder
                .set_curves_list("X25519:P-256:P-384")
                .map_err(|err| format!("set VLESS BoringSSL browser-style groups: {err}"))?;
        }
    }

    if matches!(
        fingerprint.family.as_str(),
        UTLS_FAMILY_CHROME
            | UTLS_FAMILY_EDGE
            | UTLS_FAMILY_RANDOM
            | UTLS_FAMILY_360
            | UTLS_FAMILY_QQ
    ) {
        builder.set_permute_extensions(true);
    }
    Ok(())
}

pub(super) fn boring_alpn_wire(
    proxy: &ResidentProxyPlan,
    policy: &ResidentTlsPolicy,
) -> Result<Vec<u8>, String> {
    if proxy
        .utls_fingerprint
        .as_ref()
        .is_some_and(|fingerprint| fingerprint.alpn_policy == UTLS_ALPN_POLICY_RANDOMIZED_NO_ALPN)
    {
        return Ok(Vec::new());
    }
    let mut protocols = policy.alpn.clone();
    if protocols.is_empty()
        && let Some(fingerprint) = proxy.utls_fingerprint.as_ref()
        && fingerprint.alpn_policy == UTLS_ALPN_POLICY_RANDOMIZED_ALPN
    {
        protocols.extend(fingerprint.default_alpn.iter().cloned());
    }
    encode_boring_alpn_wire(&protocols, "VLESS")
}

fn encode_boring_alpn_wire(protocols: &[String], label: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for protocol in protocols {
        let bytes = protocol.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > u8::MAX as usize {
            return Err(format!("{label} ALPN item too long: {protocol}"));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

pub(super) fn boring_read_ahead_enabled(proxy: &ResidentProxyPlan) -> bool {
    proxy.execution_plan().protocol != ResidentProtocolShape::VlessVision
}

fn require_tcp_tls_session_policy(policy: &ResidentTlsPolicy) -> Result<(), String> {
    if policy.session == ResidentTlsSessionPolicy::ProviderManagedNoEarlyData {
        Ok(())
    } else {
        Err(format!(
            "resident TCP TLS factory rejects session policy {} (zero-rtt={})",
            policy.session.resumption_label(),
            policy.session.zero_rtt_admitted()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::plan::{
        ResidentEchPlan, ResidentProxyProtocolPlan, ResidentXhttpMode, ResidentXhttpSettingsPlan,
    };

    const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
    const ECH_CONFIG_LIST: &str =
        "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";

    #[test]
    fn boring_read_ahead_stays_disabled_for_vless_vision() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.flow = XTLS_RPRX_VISION.to_owned();
        proxy.materialize_execution();

        assert!(!boring_read_ahead_enabled(&proxy));
    }

    #[test]
    fn boring_read_ahead_is_enabled_for_trojan_plain_tls() {
        let proxy = test_proxy_plan(ResidentProxyProtocolPlan::TrojanTcpTls {
            password: "secret".to_owned(),
        });

        assert!(boring_read_ahead_enabled(&proxy));
    }

    #[test]
    fn reality_client_version_uses_shared_protocol_version() {
        assert_eq!(
            reality_client_version(),
            dae_outbound::shared_transport::reality::REALITY_VERSION
        );
    }

    #[test]
    fn reality_provider_keeps_generic_tls13_shape_without_fingerprint() {
        let provider = rustls_reality_crypto_provider();

        let groups = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect::<Vec<_>>();
        assert_eq!(groups[0], rustls::NamedGroup::X25519);
        assert_eq!(groups[1], rustls::NamedGroup::secp256r1);
        assert_eq!(groups[2], rustls::NamedGroup::secp384r1);
        assert_eq!(
            provider.cipher_suites[0],
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        );
        assert_eq!(
            provider.cipher_suites[1],
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
        );
        assert_eq!(
            provider.cipher_suites[2],
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        );
    }

    #[test]
    fn reality_client_config_keeps_auth_slot_per_connection() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.tls = "reality".to_owned();
        proxy.reality = Some(ResidentRealityUnderlayPlan {
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        });
        proxy.materialize_execution();

        let policy = ResidentTlsPolicy::from_proxy(&proxy);
        let first = rustls_vless_client_config(&proxy, &policy).unwrap();
        let second = rustls_vless_client_config(&proxy, &policy).unwrap();

        assert!(!Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn reality_client_config_keeps_rustls_fingerprint_fail_closed_if_called_directly() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.tls = "reality".to_owned();
        proxy.reality = Some(ResidentRealityUnderlayPlan {
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        });
        proxy.utls_fingerprint = Some(test_fingerprint_plan(
            dae_outbound::shared_transport::UTLS_FAMILY_IOS,
        ));
        proxy.materialize_execution();

        let policy = ResidentTlsPolicy::from_proxy(&proxy);
        let err = rustls_vless_client_config(&proxy, &policy).unwrap_err();
        assert!(err.contains("rustls cannot implement uTLS fingerprints"));
    }

    #[test]
    fn reality_fingerprint_uses_boring_provider() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.tls = "reality".to_owned();
        proxy.reality = Some(ResidentRealityUnderlayPlan {
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: None,
        });
        proxy.utls_fingerprint = Some(test_fingerprint_plan(
            dae_outbound::shared_transport::UTLS_FAMILY_CHROME,
        ));
        proxy.materialize_execution();

        assert_eq!(
            ResidentTlsProvider::from_proxy(&proxy).unwrap(),
            ResidentTlsProvider::RealityFingerprintBoring
        );
    }

    #[test]
    fn reality_pqv_without_fingerprint_uses_boring_provider() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.tls = "reality".to_owned();
        proxy.reality = Some(ResidentRealityUnderlayPlan {
            public_key: [7; 32],
            short_id: vec![1, 2, 3, 4],
            spider_x: "/".to_owned(),
            mldsa65_verify: Some(Mldsa65VerifyKey::from_bytes(vec![9; 1952]).unwrap()),
        });
        proxy.materialize_execution();

        assert_eq!(
            ResidentTlsProvider::from_proxy(&proxy).unwrap(),
            ResidentTlsProvider::RealityFingerprintBoring
        );
        let policy = ResidentTlsPolicy::from_proxy(&proxy);
        assert!(
            rustls_vless_client_config(&proxy, &policy)
                .unwrap_err()
                .contains("PQV requires the BoringSSL Reality engine")
        );
    }

    #[test]
    fn xhttp_endpoint_provider_and_config_key_follow_endpoint_fingerprint() {
        let proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        let mut endpoint = ResidentXhttpEndpointPlan::from_proxy(&proxy);
        let rustls_key = ResidentTlsClientConfigKey::from_xhttp_endpoint(&endpoint, None);
        assert_eq!(
            ResidentTlsProvider::from_xhttp_endpoint(&endpoint).unwrap(),
            ResidentTlsProvider::StandardRustls
        );

        endpoint.utls_fingerprint = Some(test_fingerprint_plan(
            dae_outbound::shared_transport::UTLS_FAMILY_CHROME,
        ));
        let boring_key = ResidentTlsClientConfigKey::from_xhttp_endpoint(&endpoint, None);
        assert_eq!(
            ResidentTlsProvider::from_xhttp_endpoint(&endpoint).unwrap(),
            ResidentTlsProvider::FingerprintAwareBoring
        );
        assert_ne!(rustls_key, boring_key);
        assert!(boring_key.utls_fingerprint.is_some());
    }

    #[test]
    fn standard_rustls_client_config_still_uses_cache() {
        let proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });

        let policy = ResidentTlsPolicy::from_proxy(&proxy);
        let first = rustls_vless_client_config(&proxy, &policy).unwrap();
        let second = rustls_vless_client_config(&proxy, &policy).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn ech_selects_boring_and_keeps_rustls_fail_closed() {
        let mut proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        proxy.ech = Some(test_ech_plan());

        assert_eq!(
            ResidentTlsProvider::from_proxy(&proxy).unwrap(),
            ResidentTlsProvider::FingerprintAwareBoring
        );
        let policy = ResidentTlsPolicy::from_proxy(&proxy);
        assert!(
            rustls_vless_client_config(&proxy, &policy)
                .unwrap_err()
                .contains("authenticated-retry BoringSSL factory")
        );
    }

    #[test]
    fn ech_config_identity_partitions_tls_config_keys() {
        let mut first_proxy = test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        });
        first_proxy.ech = Some(test_ech_plan());
        let mut second_proxy = first_proxy.clone();
        let mut second_bytes = second_proxy
            .ech
            .as_ref()
            .unwrap()
            .config_list_bytes()
            .to_vec();
        let public_name = second_bytes
            .windows(b"ech.com".len())
            .position(|window| window == b"ech.com")
            .unwrap();
        second_bytes[public_name..public_name + b"alt.com".len()].copy_from_slice(b"alt.com");
        second_proxy.ech = Some(ResidentEchPlan::new(
            dae_outbound::shared_transport::EchConfigList::from_bytes(second_bytes).unwrap(),
        ));

        let first_key = ResidentTlsClientConfigKey::from_proxy(&first_proxy, None);
        let second_key = ResidentTlsClientConfigKey::from_proxy(&second_proxy, None);

        assert_ne!(first_key.ech, second_key.ech);
        assert_ne!(first_key, second_key);
    }

    #[test]
    fn reality_fallback_verifier_rejects_non_reality_certificates() {
        let verifier = ResidentRealityFallbackRejectVerifier::new();
        let cert = CertificateDer::from(vec![0_u8]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let err = verifier
            .verify_server_cert(
                &cert,
                &[],
                &server_name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(0)),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        ));
    }

    fn test_fingerprint_plan(family: &str) -> ResidentUtlsFingerprintPlan {
        ResidentUtlsFingerprintPlan {
            source: "test fp",
            requested: family.to_owned(),
            name: family.to_owned(),
            canonical: family.to_owned(),
            family: family.to_owned(),
            client: family.to_owned(),
            randomized: family == UTLS_FAMILY_RANDOM,
            alpn_policy: dae_outbound::shared_transport::UTLS_ALPN_POLICY_AUTO.to_owned(),
            default_alpn: dae_outbound::shared_transport::UTLS_BROWSER_DEFAULT_ALPN
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect(),
        }
    }

    fn test_ech_plan() -> ResidentEchPlan {
        ResidentEchPlan::new(
            dae_outbound::shared_transport::EchConfigList::parse_base64(ECH_CONFIG_LIST).unwrap(),
        )
    }

    fn test_proxy_plan(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        let mut proxy = ResidentProxyPlan {
            graph_id: "resident-graph:test".to_owned(),
            graph_link_hash: "sha256:test".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "trojan",
            group_name: "proxy".to_owned(),
            group_policy: "fixed".to_owned(),
            node_tag: "test".to_owned(),
            server_host: "127.0.0.1".to_owned(),
            server_port: 443,
            server_name: "example.com".to_owned(),
            alpn: Vec::new(),
            flow: String::new(),
            net: "tcp".to_owned(),
            stream_host: String::new(),
            stream_path: String::new(),
            grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: "tls".to_owned(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            ech: None,
            reality: None,
            handler,
            execution: None,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        };
        proxy.materialize_execution();
        proxy
    }
}
