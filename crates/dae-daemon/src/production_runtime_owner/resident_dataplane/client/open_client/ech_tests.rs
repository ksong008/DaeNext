use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use boring::hpke::HpkeKey;
use boring::pkey::{PKey, Private};
use boring::ssl::{SslAcceptor, SslConnector, SslEchKeys, SslMethod, SslVersion};
use boring::x509::X509;
use rcgen::generate_simple_self_signed;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::*;
use crate::production_runtime_owner::resident_dataplane::client::config::configure_boring_certificate_verification;

const INNER_NAME: &str = "foobar.com";
const ECH_CONFIG_LIST: &str =
    "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";
const ECH_CONFIG: &str =
    "/g0AOgAAIAAguy8p4+MFfgQZ1S/F9EEYd2+NthzqT992B5uTYGxaYkgACAABAAEAAQADAAdlY2guY29tAAA=";
const ECH_KEY: &str = "nx3rjPVWNbMfaatuM+8AnorXKBktqxI3lEvHfD+pH4I=";
const ECH_CONFIG_2: &str =
    "/g0AOgEAIAAgfvtf7qKidLP//mlRnvrh+kmMYSz60A+MIocOvLAtdiUACAABAAEAAQADAAdlY2guY29tAAA=";
const ECH_KEY_2: &str = "pzVEJGz+sFNMYn7KLhGPVjzALmqi5686fbRyEx6ItoU=";

struct TestIdentity {
    certificate: X509,
    private_key: PKey<Private>,
}

fn test_identity() -> TestIdentity {
    let certified =
        generate_simple_self_signed(vec![INNER_NAME.to_owned(), "ech.com".to_owned()]).unwrap();
    TestIdentity {
        certificate: X509::from_der(certified.cert.der().as_ref()).unwrap(),
        private_key: PKey::private_key_from_der(&certified.key_pair.serialize_der()).unwrap(),
    }
}

fn ech_acceptor(identity: &TestIdentity, config_base64: &str, key_base64: &str) -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor.set_certificate(&identity.certificate).unwrap();
    acceptor.set_private_key(&identity.private_key).unwrap();
    acceptor.check_private_key().unwrap();

    let hpke_key = HpkeKey::dhkem_p256_sha256(&STANDARD.decode(key_base64).unwrap()).unwrap();
    let mut ech_keys = SslEchKeys::builder().unwrap();
    ech_keys
        .add_key(true, &STANDARD.decode(config_base64).unwrap(), hpke_key)
        .unwrap();
    acceptor.set_ech_keys(&ech_keys.build()).unwrap();
    acceptor.build()
}

fn ech_connector(certificate: &X509) -> SslConnector {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    connector
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    connector.cert_store_mut().add_cert(certificate).unwrap();
    configure_boring_certificate_verification(&mut connector, false);
    connector.build()
}

async fn spawn_ech_server(
    acceptor: SslAcceptor,
    connection_count: usize,
) -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = Arc::new(acceptor);
    let task = tokio::spawn(async move {
        for _ in 0..connection_count {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_boring::accept(&acceptor, tcp).await;
        }
    });
    (address, task)
}

async fn client_attempt(
    address: std::net::SocketAddr,
    connector: &SslConnector,
    config_list: &[u8],
) -> Result<(), ResidentEchHandshakeError> {
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut config = connector.configure().unwrap();
    config.set_ech_config_list(config_list).unwrap();
    let tcp = AsyncResidentTcpStream::new(tcp, None);
    match tokio_boring::connect(config, INNER_NAME, tcp).await {
        Ok(tls) if tls.ssl().ech_accepted() => Ok(()),
        Ok(_) => Err(ResidentEchHandshakeError::Failed(
            "test handshake completed without required ECH".to_owned(),
        )),
        Err(error) => Err(classify_boring_ech_handshake_error(
            ResidentBoringTlsConnectError::Handshake(error),
            false,
            "test",
        )),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boring_ech_loopback_accepts_official_config() {
    let identity = test_identity();
    let connector = ech_connector(&identity.certificate);
    let (address, server) = spawn_ech_server(ech_acceptor(&identity, ECH_CONFIG, ECH_KEY), 1).await;
    let config_list = STANDARD.decode(ECH_CONFIG_LIST).unwrap();

    client_attempt(address, &connector, &config_list)
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boring_ech_loopback_uses_one_authenticated_retry() {
    let identity = test_identity();
    let connector = ech_connector(&identity.certificate);
    let (address, server) =
        spawn_ech_server(ech_acceptor(&identity, ECH_CONFIG_2, ECH_KEY_2), 2).await;
    let stale = STANDARD.decode(ECH_CONFIG_LIST).unwrap();

    let retry = match client_attempt(address, &connector, &stale).await {
        Err(ResidentEchHandshakeError::Rejected(retry)) => validated_ech_retry_config(retry)
            .expect("authenticated retry config must remain a valid ECHConfigList"),
        result => panic!("expected authenticated ECH rejection, got {result:?}"),
    };
    assert_ne!(retry.bytes(), stale);
    finish_boring_ech_retry_result(
        client_attempt(address, &connector, retry.bytes()).await,
        "test",
    )
    .unwrap();
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boring_ech_loopback_rejects_a_second_retry() {
    let identity = test_identity();
    let connector = ech_connector(&identity.certificate);
    let (first_address, first_server) =
        spawn_ech_server(ech_acceptor(&identity, ECH_CONFIG_2, ECH_KEY_2), 1).await;
    let stale = STANDARD.decode(ECH_CONFIG_LIST).unwrap();
    let retry = match client_attempt(first_address, &connector, &stale).await {
        Err(ResidentEchHandshakeError::Rejected(retry)) => validated_ech_retry_config(retry)
            .expect("first authenticated retry config must be valid"),
        result => panic!("expected first ECH rejection, got {result:?}"),
    };
    first_server.await.unwrap();

    let (second_address, second_server) =
        spawn_ech_server(ech_acceptor(&identity, ECH_CONFIG, ECH_KEY), 1).await;
    let error = finish_boring_ech_retry_result(
        client_attempt(second_address, &connector, retry.bytes()).await,
        "test",
    )
    .unwrap_err();
    assert_eq!(
        error,
        "test BoringSSL ECH rejected after one authenticated retry"
    );
    second_server.await.unwrap();
}
