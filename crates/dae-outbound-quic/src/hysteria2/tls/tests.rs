use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::hysteria2::Hysteria2TlsIdentity;
use crate::hysteria2::underlay::raw_cert_sha256_hex;
use crate::test_support::{
    TestCertificateValidity, TestTlsCertificateChain, boring_quic_server_config,
    signed_tls_certificate_chain,
};

const TRUSTED_SERVER_NAME: &str = "trusted.hysteria2.test";
const WRONG_SERVER_NAME: &str = "wrong.hysteria2.test";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

struct CertificateChain {
    material: TestTlsCertificateChain,
}

impl CertificateChain {
    fn signed(server_name: &str, validity: TestCertificateValidity) -> Self {
        Self {
            material: signed_tls_certificate_chain(server_name, validity).unwrap(),
        }
    }

    fn leaf_pin(&self) -> String {
        raw_cert_sha256_hex(&self.material.leaf_identity.certificate_der().unwrap())
    }

    fn wrong_leaf_pin(&self) -> String {
        let mut pin = self.leaf_pin().into_bytes();
        pin[0] = if pin[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(pin).unwrap()
    }

    fn server_config(&self) -> quinn::ServerConfig {
        boring_quic_server_config(
            &self.material.leaf_identity,
            &[DEFAULT_HYSTERIA2_ALPN.as_bytes().to_vec()],
            Arc::new(hysteria2_transport_config(0, None).unwrap()),
        )
        .unwrap()
    }

    fn system_ca_snapshot(&self) -> Arc<crate::system_ca::SystemCaSnapshot> {
        let path = std::env::temp_dir().join(format!(
            "daenext-hysteria2-ca-{}-{}.pem",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::write(&path, self.material.root_pem().unwrap()).unwrap();
        let snapshot = crate::system_ca::SystemCaSnapshot::load_from_path(path.clone())
            .map(Arc::new)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        snapshot
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
    let server_endpoint = crate::test_support::boring_quic_server_endpoint(
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

    let system_ca = trust_fixture_root.then(|| chain.system_ca_snapshot());
    let Ok(client_config) = build_hysteria2_test_client_config(identity, system_ca) else {
        server_task.abort();
        return false;
    };
    let mut client_endpoint = crate::test_support::boring_quic_client_endpoint(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    ))
    .unwrap();
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
    let chain = CertificateChain::signed(TRUSTED_SERVER_NAME, TestCertificateValidity::Current);
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
    for validity in [
        TestCertificateValidity::Expired,
        TestCertificateValidity::NotYetValid,
    ] {
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
    let chain = CertificateChain::signed(TRUSTED_SERVER_NAME, TestCertificateValidity::Current);
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
    let chain = CertificateChain::signed(TRUSTED_SERVER_NAME, TestCertificateValidity::Current);
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
        crate::hysteria2::Hysteria2TrustAnchorIdentity::SystemCaBundle
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
