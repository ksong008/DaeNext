use super::*;
use crate::test_support::{
    TestCertificateValidity, TestTlsIdentity, boring_quic_client_endpoint,
    boring_quic_server_endpoint, signed_tls_certificate_chain,
};

const NAME: &str = "quic-anchor.invalid";
const ID: &[u8] = &[0x32];

fn install_alternate(ctx: &mut boring_v4_compat::ssl::SslContext, identity: &TestTlsIdentity) {
    let der = identity.certificate.to_der().unwrap();
    unsafe {
        let leaf = boring_sys::CRYPTO_BUFFER_new(der.as_ptr(), der.len(), std::ptr::null_mut());
        let credential = boring_sys::SSL_CREDENTIAL_new_x509();
        assert!(!leaf.is_null() && !credential.is_null());
        assert_eq!(
            boring_sys::SSL_CREDENTIAL_set1_cert_chain(credential, &leaf, 1),
            1
        );
        assert_eq!(
            boring_sys::SSL_CREDENTIAL_set1_private_key(credential, identity.private_key.as_ptr()),
            1
        );
        boring_sys::SSL_CREDENTIAL_set_must_match_issuer(credential, 1);
        assert_eq!(
            boring_sys::SSL_CREDENTIAL_set1_trust_anchor_id(credential, ID.as_ptr(), ID.len()),
            1
        );
        assert_eq!(
            boring_sys::SSL_CTX_add1_credential(ctx.as_ptr(), credential),
            1
        );
        boring_sys::SSL_CREDENTIAL_free(credential);
        boring_sys::CRYPTO_BUFFER_free(leaf);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn quic_retries_with_only_the_selected_trusted_anchor() {
    let fallback = signed_tls_certificate_chain(NAME, TestCertificateValidity::Current).unwrap();
    let alternate = signed_tls_certificate_chain(NAME, TestCertificateValidity::Current).unwrap();
    let mut server = quinn_boring::ServerConfig::new().unwrap();
    server.set_alpn(&[b"h3".to_vec()]).unwrap();
    let ctx = server.ctx_mut();
    ctx.set_certificate(fallback.leaf_identity.certificate)
        .unwrap();
    ctx.set_private_key(fallback.leaf_identity.private_key)
        .unwrap();
    install_alternate(ctx, &alternate.leaf_identity);
    let server = boring_quic_server_endpoint(
        quinn_boring::helpers::server_config(Arc::new(server)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let remote = server.local_addr().unwrap();
    let client = boring_quic_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut crypto = quinn_boring::ClientConfig::new().unwrap();
    crypto.set_alpn(&[b"h3".to_vec()]).unwrap();
    configure_chrome_152(&mut crypto, None).unwrap();
    let wrong_id = [1, 0x21];
    unsafe {
        let store = boring_sys::SSL_CTX_get_cert_store(crypto.ctx().as_ptr());
        assert_eq!(
            boring_sys::X509_STORE_add_cert(store, alternate.root_certificate.as_ptr()),
            1
        );
        assert_eq!(
            boring_sys::SSL_CTX_set1_requested_trust_anchors(
                crypto.ctx().as_ptr(),
                wrong_id.as_ptr(),
                wrong_id.len()
            ),
            1
        );
    }
    let configs = BoringQuicTrustAnchorConfig {
        crypto: Arc::new(crypto),
        transport: Arc::new(quinn::TransportConfig::default()),
        trusted_ids: Arc::from([1, ID[0]]),
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            async {
                let (config, observed) = configs.observe_selection_failure();
                assert!(
                    client
                        .connect_with(config, remote, NAME)
                        .unwrap()
                        .await
                        .is_err()
                );
                let id = observed.take_selected().unwrap();
                assert_eq!(id, [1, ID[0]]);
                assert!(observed.take_selected().is_none());
                let connection = client
                    .connect_with(configs.retry(id.clone()), remote, NAME)
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(selected_connection_alpn(&connection), Some(b"h3".to_vec()));
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(b"verified").await.unwrap();
                stream.finish().unwrap();
                connection.closed().await;
                assert!(
                    client
                        .connect_with(configs.retry(id), remote, "wrong.invalid")
                        .unwrap()
                        .await
                        .is_err()
                );
            },
            async {
                assert!(server.accept().await.unwrap().await.is_err());
                let connection = server.accept().await.unwrap().await.unwrap();
                let mut stream = connection.accept_uni().await.unwrap();
                assert_eq!(stream.read_to_end(32).await.unwrap(), b"verified");
                connection.close(0_u32.into(), b"done");
                assert!(server.accept().await.unwrap().await.is_err());
            }
        );
    })
    .await
    .unwrap();
    client.wait_idle().await;
    server.wait_idle().await;
}

#[tokio::test(flavor = "current_thread")]
async fn quic_verifies_mtc_and_requires_a_fresh_handshake() {
    use std::fs;

    let temp = std::env::temp_dir().join(format!("dae-quic-mtc-{}", std::process::id()));
    fs::create_dir(&temp).unwrap();
    let ca_path = temp.join("ca.pem");
    fs::write(
        &ca_path,
        include_bytes!("../../../../testdata/utls_clienthello/isrg-root-x2.pem"),
    )
    .unwrap();
    let metadata_path = temp.join("mtc.json");
    fs::write(
        &metadata_path,
        include_bytes!("../../../../testdata/tls_trust/mtc.json"),
    )
    .unwrap();
    let plain = Arc::new(SystemCaSnapshot::load_from_path(ca_path.clone()).unwrap());
    let configured = Arc::new(
        SystemCaSnapshot::load_from_path_with_trust_metadata(ca_path, metadata_path).unwrap(),
    );
    fs::remove_dir_all(&temp).unwrap();

    let mut server = quinn_boring::ServerConfig::new().unwrap();
    server.set_alpn(&[b"h3".to_vec()]).unwrap();
    let cert = boring_v4_compat::x509::X509::from_pem(include_bytes!(
        "../../../../testdata/tls_trust/mtc-leaf.pem"
    ))
    .unwrap();
    let key = boring_v4_compat::pkey::PKey::private_key_from_pem(include_bytes!(
        "../../../../testdata/tls_trust/mtc-test-key.pem"
    ))
    .unwrap();
    server.ctx_mut().set_certificate(cert).unwrap();
    server.ctx_mut().set_private_key(key).unwrap();
    let server = boring_quic_server_endpoint(
        quinn_boring::helpers::server_config(Arc::new(server)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let remote = server.local_addr().unwrap();
    let client = boring_quic_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    let policy = BoringQuicClientPolicy::new([b"h3"])
        .unwrap()
        .client_hello_profile(BoringQuicClientHelloProfile::Chrome152)
        .zero_rtt(true);
    let cache = new_boring_quic_session_cache();
    for (snapshot, host, valid) in [
        (&configured, "a.example", true),
        (&configured, "a.example", true),
        (&configured, "wrong.example", false),
        (&plain, "a.example", false),
    ] {
        let config = build_boring_quic_client_config_with_session_cache_and_system_ca_snapshot(
            &policy,
            Arc::new(quinn::TransportConfig::default()),
            Some(cache.clone()),
            Some(snapshot.clone()),
        )
        .unwrap();
        let (client_result, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let connecting = client.connect_with(config, remote, host).unwrap();
                    let connecting = match connecting.into_0rtt() {
                        Ok(_) => panic!("MTC connector unexpectedly enabled 0-RTT"),
                        Err(connecting) => connecting,
                    };
                    let connection = connecting.await;
                    if let Ok(connection) = &connection {
                        assert_eq!(selected_connection_alpn(connection), Some(b"h3".to_vec()));
                        assert!(
                            !connection
                                .handshake_data()
                                .unwrap()
                                .downcast::<quinn_boring::HandshakeData>()
                                .unwrap()
                                .session_reused
                        );
                        let mut stream = connection.open_uni().await.unwrap();
                        stream.write_all(b"verified").await.unwrap();
                        stream.finish().unwrap();
                        connection.closed().await;
                    }
                    connection
                },
                async {
                    let connection = server.accept().await.unwrap().await;
                    assert_eq!(connection.is_ok(), valid);
                    if let Ok(connection) = connection {
                        let mut stream = connection.accept_uni().await.unwrap();
                        assert_eq!(stream.read_to_end(32).await.unwrap(), b"verified");
                        connection.close(0_u32.into(), b"done");
                    }
                },
            )
        })
        .await
        .unwrap();
        assert_eq!(
            client_result.is_ok(),
            valid,
            "{host}: {:?}",
            client_result.err()
        );
    }
    client.wait_idle().await;
    server.wait_idle().await;
}
