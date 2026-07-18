use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    date_time_ymd,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::*;
use crate::hysteria2::Hysteria2TlsIdentity;
use crate::hysteria2::underlay::raw_cert_sha256_hex;

const TRUSTED_SERVER_NAME: &str = "trusted.hysteria2.test";
const WRONG_SERVER_NAME: &str = "wrong.hysteria2.test";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
enum LeafValidity {
    Current,
    Expired,
    NotYetValid,
}

struct CertificateChain {
    root_der: CertificateDer<'static>,
    leaf_der: CertificateDer<'static>,
    leaf_key_der: Vec<u8>,
}

impl CertificateChain {
    fn signed(server_name: &str, validity: LeafValidity) -> Self {
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let root = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec![server_name.to_owned()]).unwrap();
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        match validity {
            LeafValidity::Current => {}
            LeafValidity::Expired => {
                leaf_params.not_before = date_time_ymd(2010, 1, 1);
                leaf_params.not_after = date_time_ymd(2011, 1, 1);
            }
            LeafValidity::NotYetValid => {
                leaf_params.not_before = date_time_ymd(2099, 1, 1);
                leaf_params.not_after = date_time_ymd(2100, 1, 1);
            }
        }
        let leaf = leaf_params.signed_by(&leaf_key, &root, &root_key).unwrap();
        Self {
            root_der: root.der().clone(),
            leaf_der: leaf.der().clone(),
            leaf_key_der: leaf_key.serialize_der(),
        }
    }

    fn leaf_pin(&self) -> String {
        raw_cert_sha256_hex(self.leaf_der.as_ref())
    }

    fn wrong_leaf_pin(&self) -> String {
        let mut pin = self.leaf_pin().into_bytes();
        pin[0] = if pin[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(pin).unwrap()
    }

    fn server_config(&self) -> quinn::ServerConfig {
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key_der.clone()));
        let mut crypto =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![self.leaf_der.clone()], private_key)
                .unwrap();
        crypto.alpn_protocols = vec![DEFAULT_HYSTERIA2_ALPN.as_bytes().to_vec()];
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()))
    }
}

fn identity(
    server_name: &str,
    node_allow_insecure: bool,
    global_allow_insecure: bool,
    pin: &str,
) -> Hysteria2TlsIdentity {
    Hysteria2TlsIdentity::from_node_and_global(
        server_name,
        node_allow_insecure,
        global_allow_insecure,
        pin,
    )
    .unwrap()
}

async fn completes_handshake(
    chain: &CertificateChain,
    identity: &Hysteria2TlsIdentity,
    trust_fixture_root: bool,
) -> bool {
    let server_endpoint = quinn::Endpoint::server(
        chain.server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let Some(incoming) = server_endpoint.accept().await else {
            return;
        };
        if let Ok(connection) = incoming.await {
            connection.close(0_u32.into(), b"TLS policy test complete");
        }
        server_endpoint.wait_idle().await;
    });

    let mut roots = RootCertStore::empty();
    if trust_fixture_root {
        roots.add(chain.root_der.clone()).unwrap();
    }
    let Ok(crypto) = build_hysteria2_rustls_client_config(identity, roots) else {
        server_task.abort();
        return false;
    };
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let connected = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        client_endpoint
            .connect(server_addr, identity.server_name())
            .unwrap()
            .await
    })
    .await
    .is_ok_and(|result| result.is_ok());
    client_endpoint.close(0_u32.into(), b"TLS policy test complete");
    client_endpoint.wait_idle().await;
    if tokio::time::timeout(HANDSHAKE_TIMEOUT, server_task)
        .await
        .is_err()
    {
        return false;
    }
    connected
}

#[tokio::test(flavor = "current_thread")]
async fn webpki_and_leaf_pin_are_composed_during_real_handshakes() {
    let chain = CertificateChain::signed(TRUSTED_SERVER_NAME, LeafValidity::Current);
    let right_pin = chain.leaf_pin();
    let wrong_pin = chain.wrong_leaf_pin();

    assert!(
        completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, false, false, ""),
            true,
        )
        .await
    );
    assert!(
        completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, false, false, &right_pin),
            true,
        )
        .await
    );
    assert!(
        !completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, false, false, &wrong_pin),
            true,
        )
        .await
    );
    assert!(
        !completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, false, false, ""),
            false,
        )
        .await
    );
    assert!(
        !completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, false, false, &right_pin),
            false,
        )
        .await
    );
    assert!(
        !completes_handshake(
            &chain,
            &identity(WRONG_SERVER_NAME, false, false, &right_pin),
            true,
        )
        .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn certificate_validity_remains_required_when_a_pin_matches() {
    for validity in [LeafValidity::Expired, LeafValidity::NotYetValid] {
        let chain = CertificateChain::signed(TRUSTED_SERVER_NAME, validity);
        assert!(
            !completes_handshake(
                &chain,
                &identity(TRUSTED_SERVER_NAME, false, false, &chain.leaf_pin(),),
                true,
            )
            .await
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_insecure_mode_accepts_any_certificate_but_still_enforces_a_pin() {
    let chain = CertificateChain::signed(TRUSTED_SERVER_NAME, LeafValidity::Current);
    assert!(
        completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, true, false, ""),
            false,
        )
        .await
    );
    assert!(
        completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, true, false, &chain.leaf_pin(),),
            false,
        )
        .await
    );
    assert!(
        !completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, true, false, &chain.wrong_leaf_pin(),),
            false,
        )
        .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn inherited_insecure_mode_and_node_pin_form_pin_only_verification() {
    let chain = CertificateChain::signed(TRUSTED_SERVER_NAME, LeafValidity::Current);
    assert!(
        completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, false, true, &chain.leaf_pin(),),
            false,
        )
        .await
    );
    assert!(
        !completes_handshake(
            &chain,
            &identity(TRUSTED_SERVER_NAME, false, true, &chain.wrong_leaf_pin(),),
            false,
        )
        .await
    );
}

#[test]
fn typed_identity_fixes_the_application_and_client_security_shape() {
    let identity = identity(TRUSTED_SERVER_NAME, false, false, "");
    assert_eq!(
        identity.application_protocol(),
        Hysteria2ApplicationProtocol::Http3
    );
    assert_eq!(
        identity.trust_anchor(),
        crate::hysteria2::Hysteria2TrustAnchorIdentity::BundledWebPki
    );
    assert_eq!(
        identity.client_certificate(),
        crate::hysteria2::Hysteria2ClientCertificateIdentity::None
    );
    assert_eq!(
        identity.encrypted_client_hello(),
        crate::hysteria2::Hysteria2EncryptedClientHelloIdentity::Disabled
    );
}

#[test]
fn udp_wrapper_overhead_is_accounted_in_quinn_mtu_discovery() {
    assert_eq!(hysteria2_mtu_discovery_upper_bound(0).unwrap(), 1_452);
    assert_eq!(hysteria2_mtu_discovery_upper_bound(8).unwrap(), 1_444);
    assert!(
        hysteria2_transport_config(8, None).is_ok(),
        "a Salamander-sized UDP wrapper overhead must produce a valid Quinn transport config"
    );
    assert!(
        hysteria2_mtu_discovery_upper_bound(
            usize::from(DEFAULT_HYSTERIA2_MTU_DISCOVERY_UPPER_BOUND)
                - usize::from(HYSTERIA2_MINIMUM_QUIC_UDP_PAYLOAD)
                + 1,
        )
        .is_err()
    );
}
