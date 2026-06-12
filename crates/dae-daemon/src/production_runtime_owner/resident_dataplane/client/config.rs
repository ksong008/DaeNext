use super::*;

const REALITY_COMPAT_CLIENT_VERSION: [u8; 3] = [26, 6, 1];
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
    builder.set_read_ahead(false);
    if proxy.flow == XTLS_RPRX_VISION {
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
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| format!("create VLESS Reality rustls provider: {err}"))?
    } else if proxy.flow == XTLS_RPRX_VISION {
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        ClientConfig::builder()
    };
    let mut config = if let Some(reality) = &proxy.reality {
        let reality_config = RealityConfig::new(reality.public_key, reality.short_id.clone())
            .map_err(|err| format!("create VLESS Reality config: {err}"))?
            .with_client_version(REALITY_COMPAT_CLIENT_VERSION);
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
        "firefox" => {
            builder
                .set_curves_list("X25519:P-256:P-384:P-521")
                .map_err(|err| format!("set VLESS BoringSSL Firefox-style groups: {err}"))?;
        }
        "android" => {
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
        "chrome" | "edge" | "random" | "360" | "qq"
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
