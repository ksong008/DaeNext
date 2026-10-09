use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use dae_outbound::shared_transport::test_support::{
    boring_quic_server_config, self_signed_tls_identity,
};
use tokio::task::JoinHandle;

const SERVER_NAME: &str = "proxied-doh3.fixture.invalid";

pub struct H3TestServer {
    address: std::net::SocketAddr,
    certificate: Vec<u8>,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl H3TestServer {
    pub async fn start() -> Self {
        let identity = self_signed_tls_identity(&[SERVER_NAME]).unwrap();
        let certificate = identity.certificate_der().unwrap();
        let server_config = boring_quic_server_config(
            &identity,
            &[super::super::DNS_DOH3_ALPN.as_bytes().to_vec()],
            Arc::new(quinn::TransportConfig::default()),
        )
        .unwrap();
        let endpoint = dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config,
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
        )
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

    pub fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    pub fn server_name(&self) -> &'static str {
        SERVER_NAME
    }

    pub fn certificate(&self) -> Vec<u8> {
        self.certificate.clone()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
}

impl Drop for H3TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
