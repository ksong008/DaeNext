use super::*;
use boring::ssl::SslAcceptor;
use dae_outbound::shared_transport::test_support::{
    TestCertificateValidity, TestTlsIdentity, signed_tls_certificate_chain,
};
use foreign_types::ForeignTypeRef;
use tokio::net::TcpListener;

const TEST_NAME: &str = "test-anchor.invalid";
const ALTERNATE_ID: &[u8] = &[0x32];

fn install_alternate(
    acceptor: &boring::ssl::SslContextBuilder,
    leaf: &TestTlsIdentity,
    id: &[u8],
    group: Option<(u8, u64, u64)>,
) {
    let der = leaf.certificate.to_der().unwrap();
    unsafe {
        let certificate =
            boring_sys::CRYPTO_BUFFER_new(der.as_ptr(), der.len(), std::ptr::null_mut());
        let credential = boring_sys::SSL_CREDENTIAL_new_x509();
        assert!(!certificate.is_null() && !credential.is_null());
        assert_eq!(
            boring_sys::SSL_CREDENTIAL_set1_cert_chain(credential, &certificate, 1),
            1
        );
        assert_eq!(
            boring_sys::SSL_CREDENTIAL_set1_private_key(credential, leaf.private_key.as_ptr()),
            1
        );
        boring_sys::SSL_CREDENTIAL_set_must_match_issuer(credential, 1);
        assert_eq!(
            boring_sys::SSL_CREDENTIAL_set1_trust_anchor_id(credential, id.as_ptr(), id.len()),
            1
        );
        if let Some((base, min, max)) = group {
            assert_eq!(
                boring_sys::SSL_CREDENTIAL_add1_trust_anchor_group_inclusion(
                    credential, &base, 1, min, max
                ),
                1
            );
        }
        assert_eq!(
            boring_sys::SSL_CTX_add1_credential(acceptor.as_ptr(), credential),
            1
        );
        boring_sys::SSL_CREDENTIAL_free(credential);
        boring_sys::CRYPTO_BUFFER_free(certificate);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn trust_anchor_retry_redials_once_and_preserves_verification() {
    let fallback =
        signed_tls_certificate_chain(TEST_NAME, TestCertificateValidity::Current).unwrap();
    let alternate =
        signed_tls_certificate_chain(TEST_NAME, TestCertificateValidity::Current).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor
        .set_certificate(&fallback.leaf_identity.certificate)
        .unwrap();
    acceptor
        .set_private_key(&fallback.leaf_identity.private_key)
        .unwrap();
    install_alternate(&acceptor, &alternate.leaf_identity, ALTERNATE_ID, None);
    let acceptor = acceptor.build();
    for (trusted_id, server_name, attempts, success) in [
        (ALTERNATE_ID[0], TEST_NAME, 2, true),
        (ALTERNATE_ID[0], "wrong.invalid", 2, false),
        (0x42, TEST_NAME, 1, false),
    ] {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder
            .cert_store_mut()
            .add_cert(&alternate.root_certificate)
            .unwrap();
        configure_boring_certificate_verification(&mut builder, false);
        let initial = [1, 0x21];
        assert_eq!(
            unsafe {
                boring_sys::SSL_CTX_set1_requested_trust_anchors(
                    builder.as_ptr(),
                    initial.as_ptr(),
                    initial.len(),
                )
            },
            1
        );
        let mut entry = ResidentBoringTlsContextEntry::build(builder, "trust anchor test").unwrap();
        entry.trust_anchor_ids = Arc::from([1, trusted_id]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (result, ()) = time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let tcp = TokioTcpStream::connect(addr).await.unwrap();
                    connect_boring_with_anchor_retry(
                        &entry,
                        entry.configure().unwrap(),
                        server_name,
                        AsyncResidentTcpStream::new_boring(tcp, None),
                        Some((addr, 0, false)),
                        "test",
                        |_| Ok(()),
                        |tcp| AsyncResidentTcpStream::new_boring(tcp, None),
                    )
                    .await
                },
                async {
                    for attempt in 0..attempts {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let accepted = tokio_boring::accept(&acceptor, tcp).await;
                        assert_eq!(accepted.is_ok(), success && attempt == 1);
                    }
                    assert!(
                        time::timeout(std::time::Duration::from_millis(25), listener.accept())
                            .await
                            .is_err()
                    );
                }
            )
        })
        .await
        .unwrap();
        assert_eq!(
            result.is_ok(),
            success,
            "{server_name}, anchor {trusted_id:02x}: {:?}",
            result.as_ref().err()
        );
        if let Ok(tls) = result {
            assert_eq!(tls.ssl().verify_result(), Ok(()));
            assert!(!tls.ssl().session_reused());
        }
    }
}

fn test_ca_snapshot(roots: &[u8], manifest: &serde_json::Value) -> dae_tls::SystemCaSnapshot {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("dae-trust-test-{}-{serial}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let roots_path = dir.join("ca.pem");
    let manifest_path = dir.join("trust.json");
    std::fs::write(&roots_path, roots).unwrap();
    std::fs::write(&manifest_path, serde_json::to_vec(manifest).unwrap()).unwrap();
    let result =
        dae_tls::SystemCaSnapshot::load_from_path_with_trust_metadata(roots_path, manifest_path);
    std::fs::remove_dir_all(dir).unwrap();
    result.unwrap()
}

fn trusted_connector(ca: &dae_tls::SystemCaSnapshot) -> ResidentBoringTlsContextEntry {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    ca.install_boring_builder(&mut builder);
    ca.install_chrome_152_trust_in_builder(&mut builder)
        .unwrap();
    configure_boring_certificate_verification(&mut builder, false);
    let mut entry = ResidentBoringTlsContextEntry::build(builder, "trust extension test").unwrap();
    entry.trust_anchor_ids = Arc::from(ca.chrome_152_trust_anchor_ids());
    entry
}

#[tokio::test(flavor = "current_thread")]
async fn trust_anchor_group_selects_a_chain_and_recovers_with_individual_id() {
    use serde_json::json;

    let fallback =
        signed_tls_certificate_chain(TEST_NAME, TestCertificateValidity::Current).unwrap();
    let alternate =
        signed_tls_certificate_chain(TEST_NAME, TestCertificateValidity::Current).unwrap();
    let second_root =
        signed_tls_certificate_chain(TEST_NAME, TestCertificateValidity::Current).unwrap();
    let fallback_id = [0x31];
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor
        .set_certificate(&fallback.leaf_identity.certificate)
        .unwrap();
    acceptor
        .set_private_key(&fallback.leaf_identity.private_key)
        .unwrap();
    install_alternate(
        &acceptor,
        &fallback.leaf_identity,
        &fallback_id,
        Some((80, 2, 2)),
    );
    install_alternate(
        &acceptor,
        &alternate.leaf_identity,
        ALTERNATE_ID,
        Some((80, 1, 1)),
    );
    let acceptor = acceptor.build();
    let mut roots = alternate.root_certificate.to_pem().unwrap();
    roots.extend(second_root.root_certificate.to_pem().unwrap());
    let member = |id: &str, cert: &boring::x509::X509| {
        let digest = boring::sha::sha256(&cert.to_der().unwrap());
        let sha256 = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        json!({ "id": id, "sha256": sha256 })
    };
    for (version, attempts, name, succeed) in [
        (1, 1, TEST_NAME, true),
        (2, 2, TEST_NAME, true),
        (2, 2, "wrong.invalid", false),
    ] {
        let ca = test_ca_snapshot(
            &roots,
            &json!({
                "groups": [{
                    "id": format!("80.{version}"),
                    "members": [
                        member("50", &alternate.root_certificate),
                        member("51", &second_root.root_certificate)
                    ]
                }]
            }),
        );
        let connector = trusted_connector(&ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (result, ()) = time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let tcp = TokioTcpStream::connect(addr).await.unwrap();
                    connect_boring_with_anchor_retry(
                        &connector,
                        connector.configure().unwrap(),
                        name,
                        AsyncResidentTcpStream::new_boring(tcp, None),
                        Some((addr, 0, false)),
                        "test group",
                        |_| Ok(()),
                        |tcp| AsyncResidentTcpStream::new_boring(tcp, None),
                    )
                    .await
                },
                async {
                    for attempt in 0..attempts {
                        let (tcp, _) = listener.accept().await.unwrap();
                        assert_eq!(
                            tokio_boring::accept(&acceptor, tcp).await.is_ok(),
                            succeed && attempt == attempts - 1
                        );
                    }
                    assert!(
                        time::timeout(std::time::Duration::from_millis(25), listener.accept())
                            .await
                            .is_err()
                    );
                }
            )
        })
        .await
        .unwrap();
        assert_eq!(
            result.is_ok(),
            succeed,
            "{version}: {:?}",
            result.as_ref().err()
        );
        if let Ok(tls) = result {
            assert_eq!(tls.ssl().verify_result(), Ok(()));
            assert!(!tls.ssl().session_reused());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn trust_anchor_mtc_checks_proof_name_time_and_revocations() {
    use serde_json::{Value, json};

    let cert = boring::x509::X509::from_pem(include_bytes!(
        "../../../../../testdata/tls_trust/mtc-leaf.pem"
    ))
    .unwrap();
    let key = boring::pkey::PKey::private_key_from_pem(include_bytes!(
        "../../../../../testdata/tls_trust/mtc-test-key.pem"
    ))
    .unwrap();
    let roots = include_bytes!("../../../../../testdata/utls_clienthello/isrg-root-x2.pem");
    let valid: Value =
        serde_json::from_str(include_str!("../../../../../testdata/tls_trust/mtc.json")).unwrap();
    for (case, name, error) in [
        ("valid", "a.example", None),
        (
            "name",
            "wrong.example",
            Some(boring_sys::X509_V_ERR_HOSTNAME_MISMATCH),
        ),
        (
            "revoked",
            "a.example",
            Some(boring_sys::X509_V_ERR_CERT_REVOKED),
        ),
        (
            "expired",
            "a.example",
            Some(boring_sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
        ),
        (
            "future",
            "a.example",
            Some(boring_sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
        ),
        (
            "wrong log",
            "a.example",
            Some(boring_sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
        ),
        (
            "wrong root",
            "a.example",
            Some(boring_sys::X509_V_ERR_CERT_SIGNATURE_FAILURE),
        ),
        (
            "damaged proof",
            "a.example",
            Some(boring_sys::X509_V_ERR_CERT_SIGNATURE_FAILURE),
        ),
        (
            "unused bit",
            "a.example",
            Some(boring_sys::X509_V_ERR_CERT_SIGNATURE_FAILURE),
        ),
    ] {
        let mut manifest = valid.clone();
        let log = &mut manifest["mtc"]["logs"][0];
        match case {
            "revoked" => log["revoked_serials"] = json!([9]),
            "wrong log" => log["log_id"] = json!("32473.2"),
            "wrong root" => log["subtrees"][0]["sha256"] = json!("00".repeat(32)),
            "expired" => manifest["mtc"]["expires_unix"] = json!(1_577_836_801),
            "future" => manifest["mtc"]["valid_from_unix"] = json!(1_924_991_999),
            _ => {}
        }
        let leaf = match case {
            "damaged proof" | "unused bit" => {
                let mut der = cert.to_der().unwrap();
                // The last BIT STRING contains the proof, then a zero-length signature list.
                let index = if case == "damaged proof" {
                    der.len() - 3
                } else {
                    der.len() - 117
                };
                der[index] ^= 1;
                boring::x509::X509::from_der(&der).unwrap()
            }
            _ => cert.clone(),
        };
        let ca = test_ca_snapshot(roots, &manifest);
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor.set_certificate(&leaf).unwrap();
        acceptor.set_private_key(&key).unwrap();
        let acceptor = acceptor.build();
        let entry = trusted_connector(&ca);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        for _ in 0..if error.is_none() { 2 } else { 1 } {
            let (result, server) = time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    async {
                        let tcp = TokioTcpStream::connect(addr).await.unwrap();
                        entry
                            .connect(
                                entry.configure().unwrap(),
                                ResidentBoringTlsSessionKey::new(name),
                                name,
                                tcp,
                            )
                            .await
                    },
                    async {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let mut tls = tokio_boring::accept(&acceptor, tcp).await?;
                        tls.write_all(b"verified").await.unwrap();
                        Ok::<_, tokio_boring::HandshakeError<TokioTcpStream>>(())
                    }
                )
            })
            .await
            .unwrap();
            match (result, error) {
                (Ok(mut tls), None) => {
                    let mut response = [0; 8];
                    tls.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"verified");
                    assert!(!tls.ssl().session_reused());
                    assert_eq!(entry.session_stats().entries, 0);
                    assert!(server.is_ok());
                }
                (Err(ResidentBoringTlsConnectError::Handshake(err)), Some(expected)) => {
                    assert_eq!(
                        err.ssl().unwrap().verify_result().unwrap_err().as_raw(),
                        expected,
                        "{case}"
                    );
                    assert!(server.is_err());
                }
                (Err(err), expected) => panic!("{case}: {err}, expected {expected:?}"),
                (Ok(_), Some(expected)) => panic!("{case}: expected verification error {expected}"),
            }
        }
    }
}
