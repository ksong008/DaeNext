use super::*;

const REALITY_CLIENT_VERSION: [u8; 3] = REALITY_VERSION;
pub(super) fn boring_vless_connector(
    proxy: &ResidentProxyPlan,
) -> Result<Arc<SslConnector>, String> {
    let key = ResidentTlsClientConfigKey::from_proxy(proxy);
    let cache =
        BORING_CONNECTOR_CACHE.get_or_init(|| Mutex::new(ResidentTlsConfigCache::default()));
    {
        let mut cache = cache
            .lock()
            .map_err(|_| "VLESS BoringSSL connector cache lock poisoned".to_owned())?;
        if let Some(connector) = cache.get(&key) {
            return Ok(connector);
        }
    }
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|err| format!("create VLESS BoringSSL connector: {err}"))?;
    builder.set_verify(if proxy.allow_insecure {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });
    builder.set_read_ahead(boring_read_ahead_enabled(proxy));
    if is_xtls_rprx_vision_flow(&proxy.flow) {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set VLESS BoringSSL min TLS version: {err}"))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| format!("set VLESS BoringSSL max TLS version: {err}"))?;
    }
    if let Some(fingerprint) = &proxy.utls_fingerprint {
        configure_boring_fingerprint(&mut builder, fingerprint)?;
    }
    let alpn = boring_alpn_wire(proxy)?;
    if !alpn.is_empty() {
        builder
            .set_alpn_protos(&alpn)
            .map_err(|err| format!("set VLESS BoringSSL ALPN: {err}"))?;
    }
    let connector = Arc::new(builder.build());
    let mut cache = cache
        .lock()
        .map_err(|_| "VLESS BoringSSL connector cache lock poisoned".to_owned())?;
    Ok(cache.insert_or_get(key, connector))
}

impl ResidentTlsClientConfigKey {
    pub(super) fn from_proxy(proxy: &ResidentProxyPlan) -> Self {
        Self {
            flow: proxy.flow.clone(),
            alpn: proxy.alpn.clone(),
            allow_insecure: proxy.allow_insecure,
            utls_fingerprint: proxy
                .utls_fingerprint
                .as_ref()
                .map(ResidentTlsFingerprintConfigKey::from_plan),
            reality: proxy
                .reality
                .as_ref()
                .map(ResidentRealityConfigKey::from_plan),
        }
    }

    pub(super) fn from_xhttp_endpoint(endpoint: &ResidentXhttpEndpointPlan) -> Self {
        Self {
            flow: String::new(),
            alpn: endpoint.alpn.clone(),
            allow_insecure: endpoint.allow_insecure,
            utls_fingerprint: None,
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
        }
    }
}

impl ResidentRealityConfigKey {
    pub(super) fn from_plan(plan: &ResidentRealityUnderlayPlan) -> Self {
        Self {
            public_key: plan.public_key,
            short_id: plan.short_id.clone(),
        }
    }
}

pub(super) fn rustls_vless_client_config(
    proxy: &ResidentProxyPlan,
) -> Result<Arc<ClientConfig>, String> {
    let key = ResidentTlsClientConfigKey::from_proxy(proxy);
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
    let builder = if proxy.reality.is_some() {
        let provider = rustls_reality_crypto_provider(proxy.utls_fingerprint.as_ref());
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| format!("create VLESS Reality rustls provider: {err}"))?
    } else if is_xtls_rprx_vision_flow(&proxy.flow) {
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        ClientConfig::builder()
    };
    let mut config = if let Some(reality) = &proxy.reality {
        let reality_config = RealityConfig::new(reality.public_key, reality.short_id.clone())
            .map_err(|err| format!("create VLESS Reality config: {err}"))?
            .with_client_version(REALITY_CLIENT_VERSION);
        if proxy.allow_insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(ResidentInsecureCertVerifier::new())
                .with_reality(reality_config)
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder
                .with_root_certificates(roots)
                .with_reality(reality_config)
                .with_no_client_auth()
        }
    } else if proxy.allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(ResidentInsecureCertVerifier::new())
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = proxy
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    let config = Arc::new(config);
    let mut cache = cache
        .lock()
        .map_err(|_| "VLESS rustls client config cache lock poisoned".to_owned())?;
    Ok(cache.insert_or_get(key, config))
}

pub(super) fn rustls_xhttp_endpoint_client_config(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<Arc<ClientConfig>, String> {
    let key = ResidentTlsClientConfigKey::from_xhttp_endpoint(endpoint);
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
    let builder = if endpoint.reality.is_some() {
        let provider = rustls_reality_crypto_provider(None);
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| format!("create xHTTP Reality rustls provider: {err}"))?
    } else {
        ClientConfig::builder()
    };
    let mut config = if let Some(reality) = &endpoint.reality {
        let reality_config = RealityConfig::new(reality.public_key, reality.short_id.clone())
            .map_err(|err| format!("create xHTTP Reality config: {err}"))?
            .with_client_version(REALITY_CLIENT_VERSION);
        if endpoint.allow_insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(ResidentInsecureCertVerifier::new())
                .with_reality(reality_config)
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder
                .with_root_certificates(roots)
                .with_reality(reality_config)
                .with_no_client_auth()
        }
    } else if endpoint.allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(ResidentInsecureCertVerifier::new())
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = endpoint
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    let config = Arc::new(config);
    let mut cache = cache
        .lock()
        .map_err(|_| "xHTTP rustls client config cache lock poisoned".to_owned())?;
    Ok(cache.insert_or_get(key, config))
}

pub(super) fn rustls_reality_crypto_provider(
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
) -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = rustls_reality_cipher_suites(fingerprint);
    provider.kx_groups = rustls_reality_kx_groups(fingerprint);
    provider
}

fn rustls_reality_cipher_suites(
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
) -> Vec<SupportedCipherSuite> {
    if fingerprint.is_some_and(|fingerprint| fingerprint.family == UTLS_FAMILY_FIREFOX) {
        return vec![
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ];
    }
    vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ]
}

fn rustls_reality_kx_groups(
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
) -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    if fingerprint.is_some_and(|fingerprint| fingerprint.family == UTLS_FAMILY_ANDROID) {
        return vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        ];
    }
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

pub(super) fn boring_alpn_wire(proxy: &ResidentProxyPlan) -> Result<Vec<u8>, String> {
    if proxy
        .utls_fingerprint
        .as_ref()
        .is_some_and(|fingerprint| fingerprint.alpn_policy == "force-no-alpn")
    {
        return Ok(Vec::new());
    }
    let mut protocols = proxy.alpn.clone();
    if protocols.is_empty()
        && proxy
            .utls_fingerprint
            .as_ref()
            .is_some_and(|fingerprint| fingerprint.alpn_policy == "force-alpn")
    {
        protocols.extend(["h2".to_owned(), "http/1.1".to_owned()]);
    }
    let mut out = Vec::new();
    for protocol in protocols {
        let bytes = protocol.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > u8::MAX as usize {
            return Err(format!("VLESS ALPN item too long: {protocol}"));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

pub(super) fn boring_read_ahead_enabled(proxy: &ResidentProxyPlan) -> bool {
    !is_xtls_rprx_vision_flow(&proxy.flow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_runtime_owner::resident_dataplane::plan::{
        ResidentProxyProtocolPlan, ResidentXhttpMode, ResidentXhttpSettingsPlan,
    };

    const XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

    #[test]
    fn boring_read_ahead_stays_disabled_for_vless_vision() {
        let mut proxy =
            test_proxy_plan(ResidentProxyProtocolPlan::VlessVisionTcpTls { key: [0; 16] });
        proxy.flow = XTLS_RPRX_VISION.to_owned();

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
            REALITY_CLIENT_VERSION,
            dae_outbound::shared_transport::reality::REALITY_VERSION
        );
    }

    #[test]
    fn reality_provider_keeps_browser_style_groups_without_single_group_downgrade() {
        let provider =
            rustls_reality_crypto_provider(Some(&test_fingerprint_plan(UTLS_FAMILY_IOS)));

        let groups = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect::<Vec<_>>();
        assert_eq!(groups[0], rustls::NamedGroup::X25519);
        assert_eq!(groups[1], rustls::NamedGroup::secp256r1);
        assert_eq!(groups[2], rustls::NamedGroup::secp384r1);
    }

    #[test]
    fn reality_provider_uses_android_narrow_group_profile() {
        let provider =
            rustls_reality_crypto_provider(Some(&test_fingerprint_plan(UTLS_FAMILY_ANDROID)));

        let groups = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect::<Vec<_>>();
        assert_eq!(
            groups,
            vec![rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1]
        );
    }

    #[test]
    fn reality_provider_keeps_firefox_cipher_preference() {
        let provider =
            rustls_reality_crypto_provider(Some(&test_fingerprint_plan(UTLS_FAMILY_FIREFOX)));

        assert_eq!(
            provider.cipher_suites[0],
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        );
        assert_eq!(
            provider.cipher_suites[1],
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(
            provider.cipher_suites[2],
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
        );
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
            alpn_policy: "auto".to_owned(),
        }
    }

    fn test_proxy_plan(handler: ResidentProxyProtocolPlan) -> ResidentProxyPlan {
        ResidentProxyPlan {
            graph_id: "resident-graph:test".to_owned(),
            graph_link_hash: "sha256:test".to_owned(),
            redacted_link_source: "source:<redacted>".to_owned(),
            protocol: "trojan".to_owned(),
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
            xhttp_download: None,
            xhttp_mode: ResidentXhttpMode::PacketUp,
            xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
            xhttp_xmux: None,
            tls: "tls".to_owned(),
            allow_insecure: false,
            tls_fragment: None,
            utls_fingerprint: None,
            reality: None,
            handler,
            chain_parent: None,
            mark: 0,
            mptcp: false,
        }
    }
}
