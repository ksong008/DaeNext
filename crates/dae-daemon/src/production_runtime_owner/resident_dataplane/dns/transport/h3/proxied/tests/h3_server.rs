use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::task::JoinHandle;

const SERVER_NAME: &str = "proxied-doh3.fixture.invalid";

pub(super) struct H3TestServer {
    address: std::net::SocketAddr,
    certificate: CertificateDer<'static>,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl H3TestServer {
    pub(super) async fn start() -> Self {
        let certified = generate_simple_self_signed(vec![SERVER_NAME.to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut crypto =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], private_key)
                .unwrap();
        crypto.alpn_protocols = vec![super::super::DNS_DOH3_ALPN.as_bytes().to_vec()];
        let server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
        let endpoint =
            quinn::Endpoint::server(server_config, (std::net::Ipv4Addr::LOCALHOST, 0).into())
                .unwrap();
        let address = endpoint.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let task_connections = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let task_connections = Arc::clone(&task_connections);
                tokio::spawn(async move {
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    task_connections.fetch_add(1, Ordering::Relaxed);
                    connection.closed().await;
                });
            }
        });
        Self {
            address,
            certificate,
            connections,
            task,
        }
    }

    pub(super) fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    pub(super) fn server_name(&self) -> &'static str {
        SERVER_NAME
    }

    pub(super) fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }

    pub(super) fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
}

impl Drop for H3TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
