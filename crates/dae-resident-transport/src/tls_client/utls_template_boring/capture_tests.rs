use super::*;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslAcceptor, SslOptions};
use dae_outbound::shared_transport::test_support::{
    TestCertificateValidity, signed_tls_certificate_chain,
    signed_tls_certificate_chain_with_leaf_key,
};
use dae_outbound::shared_transport::{
    SUPPORTED_UTLS_FINGERPRINTS, UtlsClientHelloProfile, UtlsFingerprint, UtlsRuntimeTemplate,
    parse_utls_client_hello_record, parse_utls_client_hello_record_hex,
    resolve_utls_client_hello_id, resolve_utls_runtime_template,
    utls_fingerprint_default_alpn_protocols,
};
use dae_resident_model::{
    ResidentProxyProtocolPlan, ResidentRealityUnderlayPlan, ResidentXhttpMode,
    ResidentXhttpSettingsPlan,
};
use foreign_types::ForeignType;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

const FIXTURE_SERVER_NAME: &str = "utls-profiles.invalid";
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);
const FIXTURE_REALITY_PUBLIC_KEY: [u8; 32] = [
    0x4c, 0x23, 0xa2, 0x05, 0x07, 0xab, 0x96, 0xb6, 0x73, 0xd3, 0xcc, 0xf5, 0x96, 0xb6, 0x60, 0x87,
    0x47, 0x2b, 0xe6, 0x98, 0xbb, 0xe6, 0x97, 0xfa, 0x67, 0x0b, 0x63, 0x81, 0xfb, 0xa4, 0xd6, 0x50,
];

#[tokio::test(flavor = "current_thread")]
async fn boring_template_clienthello_matches_runtime_templates() {
    for fingerprint in exact_runtime_fingerprints() {
        let template = resolve_utls_runtime_template(&fingerprint).unwrap();
        let captured = capture_boring_client_hello(test_tls_proxy(&fingerprint))
            .await
            .unwrap_or_else(|err| panic!("capture {} ordinary TLS: {err}", fingerprint.name));
        let fixture = fixture_profile(fingerprint.name);
        assert_profile_matches_template(fingerprint.name, &captured, template);
        assert_profile_matches_fixture(fingerprint.name, &captured, &fixture);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reality_boring_template_clienthello_matches_runtime_templates_before_session_mutation() {
    for fingerprint in exact_runtime_fingerprints()
        .into_iter()
        .filter(|fingerprint| {
            resolve_utls_runtime_template(fingerprint)
                .is_some_and(|template| !template.key_share_groups.is_empty())
        })
    {
        let template = resolve_utls_runtime_template(&fingerprint).unwrap();
        let captured = capture_boring_client_hello(test_reality_proxy(&fingerprint))
            .await
            .unwrap_or_else(|err| panic!("capture {} Reality TLS: {err}", fingerprint.name));
        let fixture = fixture_profile(fingerprint.name);
        assert_profile_matches_template(fingerprint.name, &captured, template);
        assert_profile_matches_fixture_except_session_id(fingerprint.name, &captured, &fixture);
        assert_eq!(
            captured.session_id_len, 32,
            "{} Reality session id",
            fingerprint.name
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reality_default_clienthello_advertises_hybrid_before_authentication_share() {
    for name in ["chrome", "chrome_auto"] {
        let fingerprint = resolve_utls_client_hello_id(name).unwrap();
        let captured = capture_boring_client_hello(test_reality_proxy(&fingerprint))
            .await
            .unwrap();
        // Xray's current admission rule is independent of minClientVer and
        // requires MLKEM before the X25519 share used for REALITY auth.
        let shares = normalized_optional_u16_values(&captured.key_share_groups)
            .into_iter()
            .filter(|&group| group != 0x0a0a)
            .collect::<Vec<_>>();
        assert_eq!(shares, [0x11ec, 0x001d]);
        let supported = normalized_optional_u16_values(&captured.supported_groups);
        assert!(supported.contains(&0x11ec));
        assert!(supported.contains(&0x001d));
        assert_eq!(captured.session_id_len, 32);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_132_clienthello_matches_wreq_tls_parameters() {
    let fingerprint = resolve_utls_client_hello_id(CHROME_132_FINGERPRINT).unwrap();
    let mut proxy = test_tls_proxy(&fingerprint);
    let record = capture_client_hello_record(proxy.clone()).await.unwrap();
    let captured = parse_utls_client_hello_record(&record).unwrap();
    assert_eq!(captured.session_id_len, 32);
    assert_eq!(
        normalized_optional_u16_values(&captured.supported_groups),
        [0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018]
    );
    assert_eq!(
        normalized_optional_u16_values(&captured.key_share_groups),
        [0x0a0a, 0x11ec, 0x001d]
    );
    assert_eq!(
        normalized_optional_u16_values(&captured.signature_schemes),
        [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
        ]
    );
    let suites = normalized_u16_values(&captured.cipher_suites);
    assert_eq!(suites[0], 0x0a0a);
    assert!(matches!(
        suites[1..4],
        [0x1301, 0x1302, 0x1303] | [0x1303, 0x1301, 0x1302]
    ));
    assert_eq!(
        &suites[4..],
        &[
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
            0x0035
        ]
    );
    assert_eq!(captured.alpn.as_deref().unwrap(), ["h2", "http/1.1"]);
    let extensions = normalized_u16_values(&captured.extension_types);
    for extension in [0x0005, 0x0012, 0x001b, 0x44cd, 0xfe0d] {
        assert!(extensions.contains(&extension), "missing {extension:04x}");
    }
    assert!(!extensions.contains(&0x4469));
    assert_eq!(extension_body(&record, 0x44cd), [0, 3, 2, b'h', b'2']);
    assert_eq!(extension_body(&record, 0x001b), [2, 0, 2]);
    let ech = extension_body(&record, 0xfe0d);
    assert_eq!(ech[0], 0, "outer ECH ClientHello");
    let encapsulated_key_len = u16::from_be_bytes([ech[6], ech[7]]) as usize;
    assert_eq!(encapsulated_key_len, 32);
    let payload = &ech[8 + encapsulated_key_len..];
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]) as usize,
        payload.len() - 2
    );
    assert!(payload.len() > 18);
    assert_eq!(extensions.first(), Some(&0x0a0a));
    assert_eq!(extensions.last(), Some(&0x0a0a));

    proxy.alpn = vec!["http/1.1".to_owned()];
    proxy.materialize_execution();
    let captured = capture_boring_client_hello(proxy).await.unwrap();
    assert_eq!(captured.alpn.as_deref().unwrap(), ["http/1.1"]);
    let extensions = normalized_u16_values(&captured.extension_types);
    assert!(!extensions.contains(&0x44cd));
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_152_advertises_new_extensions_and_only_trusted_anchor_ids() {
    let fingerprint = resolve_utls_client_hello_id(CHROME_152_FINGERPRINT).unwrap();
    let mut proxy = test_tls_proxy(&fingerprint);
    let ca_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/utls_clienthello/isrg-root-x2.pem");
    let ca = SystemCaSnapshot::load_from_path(ca_path).unwrap();
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    ca.install_boring_builder(&mut builder);
    configure_boring_fingerprint(&mut builder, proxy.utls_fingerprint.as_ref().unwrap()).unwrap();
    configure_utls_template_boring_context(
        &mut builder,
        proxy.utls_fingerprint.as_ref().unwrap(),
        Some(&ca),
    )
    .unwrap();
    let policy = ResidentTlsPolicy::from_proxy(&proxy);
    builder
        .set_alpn_protos(&boring_alpn_wire(&proxy, &policy).unwrap())
        .unwrap();
    let connector = Arc::new(ResidentBoringTlsContextEntry::build(builder, "Chrome 152").unwrap());
    let record = capture_client_hello_with_connector(proxy.clone(), Some(connector))
        .await
        .unwrap();
    let captured = parse_utls_client_hello_record(&record).unwrap();
    assert_eq!(
        normalized_optional_u16_values(&captured.signature_schemes),
        [
            0x0a0a, 0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
            0x0601,
        ]
    );
    assert_eq!(
        normalized_optional_u16_values(&captured.key_share_groups),
        [0x0a0a, 0x11ec, 0x001d]
    );
    assert_eq!(extension_body(&record, 0x12e0), [0, 0]);
    assert_eq!(
        extension_body(&record, 0xca34),
        [0, 6, 5, 0x82, 0xdf, 0x13, 0x02, 0x06] // ISRG Root X2
    );
    assert_eq!(extension_body(&record, 0x44cd), [0, 3, 2, b'h', b'2']);
    assert_eq!(extension_body(&record, 0x001b), [2, 0, 2]);
    assert_eq!(extension_body(&record, 0xfe0d)[0], 0);

    proxy.allow_insecure = true;
    proxy.materialize_execution();
    let insecure = capture_boring_client_hello(proxy).await.unwrap();
    assert!(!normalized_u16_values(&insecure.extension_types).contains(&0xca34));
    let reality = capture_boring_client_hello(test_reality_proxy(&fingerprint))
        .await
        .unwrap();
    assert!(!normalized_u16_values(&reality.extension_types).contains(&0xca34));
    assert!(normalized_optional_u16_values(&reality.signature_schemes).contains(&0x0807));
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_132_reality_keeps_hybrid_and_authentication_key_shares() {
    let fingerprint = resolve_utls_client_hello_id(CHROME_132_FINGERPRINT).unwrap();
    let captured = capture_boring_client_hello(test_reality_proxy(&fingerprint))
        .await
        .unwrap();
    assert_eq!(
        normalized_optional_u16_values(&captured.key_share_groups),
        [0x0a0a, 0x11ec, 0x001d]
    );
    assert_eq!(captured.session_id_len, 32);
    let extensions = normalized_u16_values(&captured.extension_types);
    assert!(extensions.contains(&0x44cd));
    assert!(extensions.contains(&0xfe0d));
}

#[tokio::test(flavor = "current_thread")]
async fn firefox_150_advertises_hybrid_key_shares_and_supported_compression() {
    let fingerprint = resolve_utls_client_hello_id(FIREFOX_150_FINGERPRINT).unwrap();
    let record = capture_client_hello_record(test_tls_proxy(&fingerprint))
        .await
        .unwrap();
    let profile = parse_utls_client_hello_record(&record).unwrap();
    assert_eq!(
        normalized_optional_u16_values(&profile.supported_groups),
        [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.key_share_groups),
        [0x11ec, 0x001d, 0x0017]
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.signature_schemes),
        [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ]
    );
    assert_eq!(extension_body(&record, 0x001b), [2, 0, 2]);
    assert_eq!(extension_body(&record, 0xfe0d)[0], 0);
    let ext = normalized_u16_values(&profile.extension_types);
    assert!(ext.contains(&0x0012));
    assert!(!ext.contains(&0x0a0a));
}

#[tokio::test(flavor = "current_thread")]
async fn firefox_150_reality_uses_the_authentication_key_share_and_signature() {
    let fingerprint = resolve_utls_client_hello_id(FIREFOX_150_FINGERPRINT).unwrap();
    let record = capture_client_hello_record(test_reality_proxy(&fingerprint))
        .await
        .unwrap();
    let profile = parse_utls_client_hello_record(&record).unwrap();
    assert_eq!(profile.session_id_len, 32);
    assert_eq!(
        normalized_optional_u16_values(&profile.supported_groups),
        [0x11ec, 0x001d, 0x0017, 0x0018]
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.key_share_groups),
        [0x11ec, 0x001d]
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.signature_schemes).first(),
        Some(&0x0807) // Ed25519
    );
    assert_eq!(extension_body(&record, 0x001b), [2, 0, 2]);
    assert_eq!(extension_body(&record, 0xfe0d)[0], 0);
}

#[tokio::test(flavor = "current_thread")]
async fn safari_27_2_clienthello_uses_observed_groups_and_zlib() {
    let fingerprint = resolve_utls_client_hello_id(SAFARI_27_2_FINGERPRINT).unwrap();
    let record = capture_client_hello_record(test_tls_proxy(&fingerprint))
        .await
        .unwrap();
    let profile = parse_utls_client_hello_record(&record).unwrap();
    assert_eq!(
        normalized_optional_u16_values(&profile.supported_groups),
        [0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.key_share_groups),
        [0x0a0a, 0x11ec, 0x001d]
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.signature_schemes),
        [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201
        ]
    );
    assert_eq!(
        &normalized_u16_values(&profile.cipher_suites)[4..],
        [
            0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d,
            0x009c, 0x0035, 0x002f
        ]
    );
    assert_eq!(profile.alpn.as_deref().unwrap(), ["h2", "http/1.1"]);
    assert_eq!(extension_body(&record, 0x001b), [2, 0, 1]);
    let extensions = normalized_u16_values(&profile.extension_types);
    assert!(extensions.contains(&0x0012));
    assert!(!extensions.contains(&0x44cd));
    assert!(!extensions.contains(&0xfe0d));
}

#[tokio::test(flavor = "current_thread")]
async fn safari_27_2_verifies_zlib_certificates_and_resumes_tls13() {
    verify_certificate_and_resumption(SAFARI_27_2_FINGERPRINT, None, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn safari_27_2_negotiates_tls12_and_a_tls13_retry_group() {
    verify_tls12_and_retry_group(SAFARI_27_2_FINGERPRINT).await;
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_132_verifies_certificate_and_resumes_tls13() {
    verify_certificate_and_resumption(CHROME_132_FINGERPRINT, None, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn firefox_150_verifies_certificate_and_resumes_tls13() {
    verify_certificate_and_resumption(FIREFOX_150_FINGERPRINT, None, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_152_verifies_mldsa_certificates_and_resumes_tls13() {
    let algorithms = unsafe {
        [
            (boring_sys::EVP_pkey_ml_dsa_44(), "mldsa44", 0x0904),
            (boring_sys::EVP_pkey_ml_dsa_65(), "mldsa65", 0x0905),
            (boring_sys::EVP_pkey_ml_dsa_87(), "mldsa87", 0x0906),
        ]
    };
    for (algorithm, name, scheme) in algorithms {
        let mut seed = [0; 32];
        boring::rand::rand_bytes(&mut seed).unwrap();
        let key =
            unsafe { boring_sys::EVP_PKEY_from_private_seed(algorithm, seed.as_ptr(), seed.len()) };
        assert!(!key.is_null(), "construct {name} key");
        let key = unsafe { PKey::from_ptr(key) };
        verify_certificate_and_resumption(CHROME_152_FINGERPRINT, Some((key, name, scheme)), false)
            .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn exact_template_resumption_recomputes_binders_after_client_hello_rewrite() {
    verify_certificate_and_resumption("chrome_102", None, true).await;
}

async fn verify_certificate_and_resumption(
    name: &str,
    algorithm: Option<(PKey<Private>, &str, u16)>,
    exact_template_psk: bool,
) {
    let (chain, signature) = if let Some((leaf_key, algorithm, scheme)) = algorithm {
        (
            signed_tls_certificate_chain_with_leaf_key(
                FIXTURE_SERVER_NAME,
                TestCertificateValidity::Current,
                leaf_key,
            ),
            Some((algorithm, scheme)),
        )
    } else {
        (
            signed_tls_certificate_chain(FIXTURE_SERVER_NAME, TestCertificateValidity::Current),
            None,
        )
    };
    let chain = chain.unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor
        .set_certificate(&chain.leaf_identity.certificate)
        .unwrap();
    acceptor
        .set_private_key(&chain.leaf_identity.private_key)
        .unwrap();
    if let Some((signatures, _)) = signature {
        acceptor.set_sigalgs_list(signatures).unwrap();
    }
    let zlib_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    if name == SAFARI_27_2_FINGERPRINT {
        acceptor
            .add_certificate_compression_algorithm(TestZlibCompressor(Arc::clone(&zlib_calls)))
            .unwrap();
    }
    acceptor.set_session_cache_mode(SslSessionCacheMode::SERVER);
    acceptor
        .set_session_id_context(b"browser-profile-test")
        .unwrap();
    acceptor.clear_options(SslOptions::NO_TICKET);
    acceptor.set_alpn_select_callback(|_, client| {
        boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", client)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let fingerprint = resolve_utls_client_hello_id(name).unwrap();
    timeout(CAPTURE_TIMEOUT, async {
        for (trusted, name, alpn, expected_error) in [
            (true, FIXTURE_SERVER_NAME, "h2", None),
            (true, FIXTURE_SERVER_NAME, "http/1.1", None),
            (
                false,
                FIXTURE_SERVER_NAME,
                "h2",
                Some(X509VerifyError::UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
            ),
            (
                true,
                "wrong.invalid",
                "h2",
                Some(X509VerifyError::HOSTNAME_MISMATCH),
            ),
        ] {
            let mut proxy = test_tls_proxy(&fingerprint);
            proxy.alpn = vec![alpn.to_owned()];
            let entry = browser_test_connector(&proxy, trusted.then_some(&chain.root_certificate));
            let handshakes = if expected_error.is_some() { 1 } else { 2 };
            for handshake in 0..handshakes {
                let (server_reused, ()) = tokio::join!(
                    async {
                        let (tcp, _) = listener.accept().await.unwrap();
                        if let Ok(mut tls) = tokio_boring::accept(&acceptor, tcp).await {
                            tls.write_all(b"hello").await.unwrap();
                            let mut ack = [0];
                            tls.read_exact(&mut ack).await.unwrap();
                            assert_eq!(ack, [1]);
                            Some(tls.ssl().session_reused())
                        } else {
                            None
                        }
                    },
                    async {
                        let tcp = TcpStream::connect(addr).await.unwrap();
                        let mut config = entry.configure().unwrap();
                        configure_utls_template_boring_ssl(&mut config, &proxy).unwrap();
                        if exact_template_psk && handshake == 1 {
                            let template = resolve_utls_runtime_template(&fingerprint).unwrap();
                            let mut extensions = template.extension_order.to_vec();
                            extensions.retain(|&extension| extension != 21);
                            extensions.push(41);
                            // PSK must remain last, and its binder must authenticate
                            // the rewritten cipher and extension lists.
                            assert_eq!(
                                unsafe {
                                    DAE_SSL_set1_utls_template(
                                        config.as_ptr(),
                                        template.cipher_suites.as_ptr(),
                                        template.cipher_suites.len(),
                                        extensions.as_ptr(),
                                        extensions.len(),
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
                                        dae_outbound_stream::shared_transport::UTLS_TEMPLATE_GREASE,
                                        template.session_id_len,
                                        0,
                                        i32::from(template.capabilities.grease),
                                    )
                                },
                                1
                            );
                        }
                        let result = entry
                            .connect(config, ResidentBoringTlsSessionKey::new(name), name, tcp)
                            .await;
                        if let Some(expected) = expected_error {
                            let Err(ResidentBoringTlsConnectError::Handshake(error)) = result
                            else {
                                panic!("expected a certificate verification failure");
                            };
                            assert_eq!(error.ssl().unwrap().verify_result(), Err(expected));
                        } else {
                            let mut tls =
                                result.unwrap_or_else(|error| panic!("TLS handshake: {error}"));
                            if let Some((_, scheme)) = signature
                                && handshake == 0
                            {
                                assert_eq!(
                                    unsafe {
                                        boring_sys::SSL_get_peer_signature_algorithm(
                                            tls.ssl().as_ptr(),
                                        )
                                    },
                                    scheme
                                );
                            }
                            assert_eq!(tls.ssl().session_reused(), handshake == 1);
                            assert_eq!(tls.ssl().selected_alpn_protocol(), Some(alpn.as_bytes()));
                            let mut reply = [0; 5];
                            tls.read_exact(&mut reply).await.unwrap();
                            assert_eq!(&reply, b"hello");
                            tls.write_all(&[1]).await.unwrap();
                        }
                    },
                );
                assert_eq!(
                    server_reused,
                    expected_error.is_none().then_some(handshake == 1)
                );
            }
        }
    })
    .await
    .unwrap();
    if name == SAFARI_27_2_FINGERPRINT {
        assert_eq!(zlib_calls.load(std::sync::atomic::Ordering::Relaxed), 4);
    }
}

fn browser_test_connector(
    proxy: &ResidentProxyPlan,
    root: Option<&boring::x509::X509Ref>,
) -> ResidentBoringTlsContextEntry {
    let fp = proxy.utls_fingerprint.as_ref().unwrap();
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    if let Some(root) = root {
        builder.cert_store_mut().add_cert(root).unwrap();
    }
    configure_boring_certificate_verification(&mut builder, false);
    configure_boring_fingerprint(&mut builder, fp).unwrap();
    configure_utls_template_boring_context(&mut builder, fp, None).unwrap();
    let policy = ResidentTlsPolicy::from_proxy(proxy);
    builder
        .set_alpn_protos(&boring_alpn_wire(proxy, &policy).unwrap())
        .unwrap();
    ResidentBoringTlsContextEntry::build(builder, "browser test").unwrap()
}

struct TestBrotliCompressor(Arc<std::sync::atomic::AtomicUsize>);

struct TestZlibCompressor(Arc<std::sync::atomic::AtomicUsize>);

impl CertificateCompressor for TestZlibCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = false;

    fn compress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        use std::io::Write;

        let mut encoder = flate2::write::ZlibEncoder::new(output, flate2::Compression::fast());
        encoder.write_all(input)?;
        encoder.finish()?;
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl CertificateCompressor for TestBrotliCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = false;

    fn compress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;

        brotli::BrotliCompress(
            &mut std::io::Cursor::new(input),
            output,
            &brotli::enc::BrotliEncoderParams::default(),
        )?;
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn browser_profiles_validate_a_brotli_compressed_certificate() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let chain = signed_tls_certificate_chain(FIXTURE_SERVER_NAME, TestCertificateValidity::Current)
        .unwrap();
    for name in [CHROME_132_FINGERPRINT, FIREFOX_150_FINGERPRINT] {
        let fingerprint = resolve_utls_client_hello_id(name).unwrap();
        let proxy = test_tls_proxy(&fingerprint);
        let entry = browser_test_connector(&proxy, Some(&chain.root_certificate));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        server
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        server
            .set_certificate(&chain.leaf_identity.certificate)
            .unwrap();
        server
            .set_private_key(&chain.leaf_identity.private_key)
            .unwrap();
        server
            .add_certificate_compression_algorithm(TestBrotliCompressor(Arc::clone(&calls)))
            .unwrap();
        let server = server.build();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut config = entry.configure().unwrap();
        configure_utls_template_boring_ssl(&mut config, &proxy).unwrap();
        let (server, client) = timeout(CAPTURE_TIMEOUT, async {
            tokio::join!(
                tokio_boring::accept(&server, server_io),
                entry.connect(
                    config,
                    ResidentBoringTlsSessionKey::new(FIXTURE_SERVER_NAME),
                    FIXTURE_SERVER_NAME,
                    client_io
                ),
            )
        })
        .await
        .unwrap();
        server.unwrap();
        let client = client.unwrap_or_else(|error| panic!("TLS handshake: {error}"));
        assert_eq!(client.ssl().verify_result(), Ok(()));
        assert_eq!(calls.load(Ordering::Relaxed), 1, "{name}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_132_negotiates_tls12_and_a_tls13_retry_group() {
    verify_tls12_and_retry_group(CHROME_132_FINGERPRINT).await;
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_152_negotiates_tls12_and_a_tls13_retry_group() {
    verify_tls12_and_retry_group(CHROME_152_FINGERPRINT).await;
}

async fn verify_tls12_and_retry_group(name: &str) {
    let chain = signed_tls_certificate_chain(FIXTURE_SERVER_NAME, TestCertificateValidity::Current)
        .unwrap();
    let fingerprint = resolve_utls_client_hello_id(name).unwrap();
    let proxy = test_tls_proxy(&fingerprint);
    let entry = browser_test_connector(&proxy, Some(&chain.root_certificate));
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        server.set_min_proto_version(Some(version)).unwrap();
        server.set_max_proto_version(Some(version)).unwrap();
        server.set_curves_list("P-256").unwrap();
        server
            .set_certificate(&chain.leaf_identity.certificate)
            .unwrap();
        server
            .set_private_key(&chain.leaf_identity.private_key)
            .unwrap();
        let server = server.build();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let mut config = entry.configure().unwrap();
        configure_utls_template_boring_ssl(&mut config, &proxy).unwrap();
        let (server, client) = timeout(CAPTURE_TIMEOUT, async {
            tokio::join!(
                tokio_boring::accept(&server, server_io),
                entry.connect(
                    config,
                    ResidentBoringTlsSessionKey::new(FIXTURE_SERVER_NAME),
                    FIXTURE_SERVER_NAME,
                    client_io,
                ),
            )
        })
        .await
        .unwrap();
        server.unwrap();
        let client = client.unwrap_or_else(|error| panic!("TLS handshake: {error}"));
        assert_eq!(client.ssl().version2(), Some(version));
        // The first ClientHello has just the hybrid and X25519 shares.
        assert_eq!(
            unsafe { boring_sys::SSL_get_group_id(client.ssl().as_ptr()) },
            0x0017
        );
    }
}

async fn capture_boring_client_hello(
    proxy: ResidentProxyPlan,
) -> Result<UtlsClientHelloProfile, String> {
    parse_utls_client_hello_record(&capture_client_hello_record(proxy).await?)
        .map_err(|err| format!("parse captured TLS ClientHello: {err}"))
}

fn extension_body(record: &[u8], extension: u16) -> &[u8] {
    let mut cursor = &record[43..];
    cursor = &cursor[1 + usize::from(cursor[0])..];
    cursor = &cursor[2 + usize::from(u16::from_be_bytes([cursor[0], cursor[1]]))..];
    cursor = &cursor[1 + usize::from(cursor[0])..];
    let mut extensions = &cursor[2..];
    while !extensions.is_empty() {
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        let size = usize::from(u16::from_be_bytes([extensions[2], extensions[3]]));
        let (body, remaining) = extensions[4..].split_at(size);
        if kind == extension {
            return body;
        }
        extensions = remaining;
    }
    panic!("missing extension {extension:04x}");
}

async fn capture_client_hello_record(proxy: ResidentProxyPlan) -> Result<Vec<u8>, String> {
    capture_client_hello_with_connector(proxy, None).await
}

async fn capture_client_hello_with_connector(
    mut proxy: ResidentProxyPlan,
    connector: Option<Arc<ResidentBoringTlsContextEntry>>,
) -> Result<Vec<u8>, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("bind local TLS capture listener: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("read local TLS capture address: {err}"))?;
    proxy.server_host = addr.ip().to_string();
    proxy.server_port = addr.port();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|err| format!("accept local TLS capture connection: {err}"))?;
        let mut header = [0_u8; 5];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|err| format!("read TLS record header: {err}"))?;
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = Vec::with_capacity(5 + record_len);
        record.extend_from_slice(&header);
        let mut body = vec![0_u8; record_len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| format!("read TLS record body: {err}"))?;
        record.extend_from_slice(&body);
        Ok::<_, String>(record)
    });

    let client_proxy = proxy.clone();
    let client = tokio::spawn(async move {
        let policy = ResidentTlsPolicy::from_proxy(&client_proxy);
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|err| format!("connect local TLS capture listener: {err}"))?;
        let connector = match connector {
            Some(connector) => connector,
            None => boring_vless_connector(&client_proxy, &policy)?,
        };
        let mut config = connector
            .configure()
            .map_err(|err| format!("configure BoringSSL client: {err}"))?;
        configure_utls_template_boring_ssl(&mut config, &client_proxy)?;
        if policy.verification.reality_material().is_some() {
            config.set_verify_hostname(false);
            let mldsa65_verify = client_proxy
                .reality
                .as_ref()
                .and_then(|reality| reality.mldsa65_verify.clone());
            config.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                verify_reality_boring_server_cert(ssl, mldsa65_verify.as_ref())
            });
            configure_reality_boring_ssl(&mut config, &policy.verification)?;
        }
        let session_key = ResidentBoringTlsSessionKey::new(&policy.server_name);
        connector
            .connect(config, session_key, &policy.server_name, tcp)
            .await
            .map(|_| ())
            .map_err(|err| format!("BoringSSL handshake stopped before capture completed: {err}"))
    });

    let server_result = timeout(CAPTURE_TIMEOUT, server)
        .await
        .map_err(|_| "capture TLS ClientHello timed out".to_owned())?
        .map_err(|err| format!("join TLS capture server: {err}"))?;
    let client_result = timeout(CAPTURE_TIMEOUT, client)
        .await
        .map_err(|_| "capture TLS client timed out".to_owned())?
        .map_err(|err| format!("join TLS capture client: {err}"))?;
    let record = match server_result {
        Ok(record) => record,
        Err(server_err) => {
            return Err(format!("{server_err}; client result: {client_result:?}"));
        }
    };

    Ok(record)
}

fn exact_runtime_fingerprints() -> Vec<UtlsFingerprint> {
    SUPPORTED_UTLS_FINGERPRINTS
        .iter()
        .copied()
        .filter(|fingerprint| resolve_utls_runtime_template(fingerprint).is_some())
        .collect()
}

fn fixture_profile(fingerprint_name: &str) -> UtlsClientHelloProfile {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/utls_clienthello/generated.json");
    let fixture = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", fixture_path.display()));
    let fixture: serde_json::Value = serde_json::from_str(&fixture)
        .unwrap_or_else(|err| panic!("parse {}: {err}", fixture_path.display()));
    let sample = fixture["samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["fingerprint"].as_str().unwrap() == fingerprint_name)
        .unwrap_or_else(|| panic!("missing fixture sample for {fingerprint_name}"));
    parse_utls_client_hello_record_hex(sample["record_hex"].as_str().unwrap())
        .unwrap_or_else(|err| panic!("parse fixture {fingerprint_name}: {err}"))
}

fn assert_profile_matches_template(
    fingerprint_name: &str,
    profile: &UtlsClientHelloProfile,
    template: &UtlsRuntimeTemplate,
) {
    assert_eq!(
        normalized_u16_values(&profile.cipher_suites),
        template.cipher_suites,
        "{fingerprint_name} cipher suites"
    );
    assert_eq!(
        normalized_u16_values(&profile.extension_types),
        template.extension_order,
        "{fingerprint_name} extension order"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.supported_versions),
        template.supported_versions,
        "{fingerprint_name} supported versions"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.supported_groups),
        template.supported_groups,
        "{fingerprint_name} supported groups"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.key_share_groups),
        template.key_share_groups,
        "{fingerprint_name} key share groups"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.signature_schemes),
        template.signature_schemes,
        "{fingerprint_name} signature schemes"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.delegated_credential_signature_schemes),
        template.delegated_credential_signature_schemes,
        "{fingerprint_name} delegated credential signature schemes"
    );
    assert_eq!(
        normalized_optional_u16_values(&profile.record_size_limit)
            .first()
            .copied(),
        template.record_size_limit,
        "{fingerprint_name} record size limit"
    );
}

fn assert_profile_matches_fixture(
    fingerprint_name: &str,
    captured: &UtlsClientHelloProfile,
    fixture: &UtlsClientHelloProfile,
) {
    assert_profile_matches_fixture_except_session_id(fingerprint_name, captured, fixture);
    assert_eq!(
        captured.session_id_len, fixture.session_id_len,
        "{fingerprint_name} session id length"
    );
}

fn assert_profile_matches_fixture_except_session_id(
    fingerprint_name: &str,
    captured: &UtlsClientHelloProfile,
    fixture: &UtlsClientHelloProfile,
) {
    assert_eq!(captured.sni, fixture.sni, "{fingerprint_name} SNI");
    assert_eq!(captured.alpn, fixture.alpn, "{fingerprint_name} ALPN");
    assert_eq!(
        captured.compression_methods, fixture.compression_methods,
        "{fingerprint_name} compression methods"
    );
    assert_eq!(
        captured.legacy_version, fixture.legacy_version,
        "{fingerprint_name} legacy version"
    );
}

fn normalized_optional_u16_values(values: &Option<Vec<String>>) -> Vec<u16> {
    values
        .as_deref()
        .map(normalized_u16_values)
        .unwrap_or_default()
}

fn normalized_u16_values(values: &[String]) -> Vec<u16> {
    values
        .iter()
        .map(|value| {
            if is_grease_u16_hex(value) {
                dae_outbound::shared_transport::UTLS_TEMPLATE_GREASE
            } else {
                u16::from_str_radix(value, 16).unwrap()
            }
        })
        .collect()
}

fn is_grease_u16_hex(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 4 {
        return false;
    }
    let Some(high) = hex_byte(&bytes[0..2]) else {
        return false;
    };
    let Some(low) = hex_byte(&bytes[2..4]) else {
        return false;
    };
    high == low && (high & 0x0f) == 0x0a
}

fn hex_byte(bytes: &[u8]) -> Option<u8> {
    Some((hex_nibble(bytes[0])? << 4) | hex_nibble(bytes[1])?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(in crate::tls_client) fn test_tls_proxy(fingerprint: &UtlsFingerprint) -> ResidentProxyPlan {
    let mut proxy = base_proxy(
        fingerprint,
        ResidentProxyProtocolPlan::TrojanTcpTls {
            password: "capture-secret".to_owned(),
        },
    );
    proxy.protocol = "trojan";
    proxy.tls = "tls".to_owned();
    proxy.materialize_execution();
    proxy
}

fn test_reality_proxy(fingerprint: &UtlsFingerprint) -> ResidentProxyPlan {
    let mut proxy = base_proxy(
        fingerprint,
        ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [0; 16],
            encryption: None,
        },
    );
    proxy.protocol = "vless";
    proxy.tls = "reality".to_owned();
    proxy.flow = "xtls-rprx-vision".to_owned();
    proxy.reality = Some(ResidentRealityUnderlayPlan {
        public_key: FIXTURE_REALITY_PUBLIC_KEY,
        short_id: vec![1, 2, 3, 4],
        spider_x: "/".to_owned(),
        mldsa65_verify: None,
    });
    proxy.materialize_execution();
    proxy
}

fn base_proxy(
    fingerprint: &UtlsFingerprint,
    handler: ResidentProxyProtocolPlan,
) -> ResidentProxyPlan {
    ResidentProxyPlan {
        graph_id: "resident-graph:utls-capture".to_owned(),
        graph_link_hash: "sha256:utls-capture".to_owned(),
        redacted_link_source: "capture:<redacted>".to_owned(),
        protocol: "test",
        group_name: "capture".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: format!("capture-{}", fingerprint.name),
        server_host: "127.0.0.1".to_owned(),
        server_port: 0,
        server_name: FIXTURE_SERVER_NAME.to_owned(),
        alpn: utls_fingerprint_default_alpn_protocols(fingerprint)
            .iter()
            .map(|protocol| (*protocol).to_owned())
            .collect(),
        flow: String::new(),
        net: "tcp".to_owned(),
        stream_host: String::new(),
        stream_path: String::new(),
        grpc_mode: dae_outbound::shared_transport::GrpcMode::Gun,
        xhttp_download: None,
        xhttp_mode: ResidentXhttpMode::PacketUp,
        xhttp_settings: ResidentXhttpSettingsPlan::official_default(),
        xhttp_xmux: None,
        vless_mux: None,
        vless_hysteria: None,
        tls: String::new(),
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: Some(ResidentUtlsFingerprintPlan {
            source: "capture fp",
            requested: fingerprint.name.to_owned(),
            name: fingerprint.name.to_owned(),
            canonical: fingerprint.canonical.to_owned(),
            family: fingerprint.family.to_owned(),
            client: fingerprint.client.to_owned(),
            randomized: fingerprint.randomized,
            alpn_policy: fingerprint.alpn_policy.to_owned(),
            default_alpn: utls_fingerprint_default_alpn_protocols(fingerprint)
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect(),
        }),
        ech: None,
        reality: None,
        handler,
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    }
}
