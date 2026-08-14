use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use h3::server;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::*;
use crate::production_runtime_owner::resident_dataplane::plan::ResidentProxyProtocolPlan;
use crate::production_runtime_owner::resident_dataplane::tcp::shutdown_xhttp_xmux_generation_owner;

const XHTTP_H3_OWNER_TEST_STACK_BYTES: usize = 1024 * 1024;

fn h3_server_config() -> quinn::ServerConfig {
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()))
}

fn xhttp_h3_owner_plan(
    generation: u64,
    server_address: SocketAddr,
) -> (ResidentProxyPlan, ResidentXhttpEndpointPlan) {
    let xmux = ResidentXhttpXmuxPlan {
        runtime_generation: generation,
        physical_connection_limit: 1,
        max_concurrency: None,
        max_connections: Some((1, 1)),
        c_max_reuse_times: None,
        h_max_request_times: None,
        h_max_reusable_secs: None,
        h_keep_alive_period: 0,
    };
    let endpoint = ResidentXhttpEndpointPlan {
        server_host: server_address.ip().to_string(),
        server_port: server_address.port(),
        server_name: "localhost".to_owned(),
        alpn: vec!["h3".to_owned()],
        stream_host: "localhost".to_owned(),
        stream_path: "/xhttp".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings: super::super::h3_boring_tls::tests::endpoint_plan().settings,
        xmux: Some(xmux.clone()),
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
    };
    let proxy = ResidentProxyPlan {
        graph_id: format!("resident-graph:xhttp-h3-owner-{generation}"),
        graph_link_hash: format!("sha256:xhttp-h3-owner-{generation}"),
        redacted_link_source: "vless://<redacted>".to_owned(),
        protocol: "vless",
        group_name: "group".to_owned(),
        group_policy: "fixed".to_owned(),
        node_tag: "node".to_owned(),
        server_host: endpoint.server_host.clone(),
        server_port: endpoint.server_port,
        server_name: endpoint.server_name.clone(),
        alpn: endpoint.alpn.clone(),
        flow: String::new(),
        net: "xhttp".to_owned(),
        stream_host: endpoint.stream_host.clone(),
        stream_path: endpoint.stream_path.clone(),
        grpc_mode: GrpcMode::Gun,
        xhttp_download: None,
        xhttp_mode: endpoint.mode,
        xhttp_settings: endpoint.settings.clone(),
        xhttp_xmux: Some(xmux),
        tls: "tls".to_owned(),
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: endpoint.ech.clone(),
        reality: None,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls {
            key: [1; 16],
            encryption: None,
        },
        execution: None,
        chain_parent: None,
        mark: 0,
        mptcp: false,
    };
    (proxy, endpoint)
}

async fn serve_h3_request(incoming: &mut server::Connection<h3_quinn::Connection, Bytes>) {
    let request = incoming.accept().await.unwrap().unwrap();
    let (_, mut stream) = request.resolve_request().await.unwrap();
    while stream.recv_data().await.unwrap().is_some() {}
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(()).unwrap())
        .await
        .unwrap();
    stream.finish().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_goaway_retires_the_old_physical_before_rebuild() {
    let server_endpoint =
        quinn::Endpoint::server(h3_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let accepting_endpoint = server_endpoint.clone();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let server_connections = Arc::clone(&accepted_connections);
    let (goaway_sent, goaway_observed) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut goaway_sent = Some(goaway_sent);
        for index in 0..2 {
            let connection = accepting_endpoint.accept().await.unwrap().await.unwrap();
            server_connections.fetch_add(1, Ordering::Relaxed);
            let closed = connection.clone();
            let h3_connection = h3_quinn::Connection::new(connection);
            let mut incoming: server::Connection<h3_quinn::Connection, Bytes> =
                server::Connection::new(h3_connection).await.unwrap();
            serve_h3_request(&mut incoming).await;
            if index == 0 {
                incoming.shutdown(0).await.unwrap();
                if let Some(goaway_sent) = goaway_sent.take() {
                    let _ = goaway_sent.send(());
                }
                let _ = incoming.accept().await;
                let _ = closed.closed().await;
            } else {
                let _ = closed.closed().await;
            }
        }
    });

    let generation = fastrand::u64(..);
    let (owner, owner_thread) = super::super::xmux::start_xhttp_xmux_generation_owner(
        generation,
        XHTTP_H3_OWNER_TEST_STACK_BYTES,
        2,
    )
    .unwrap();
    let (mut proxy, endpoint) = xhttp_h3_owner_plan(generation, server_address);
    proxy.materialize_execution();
    let binding = ResidentProxyBinding::resident(
        Arc::new(proxy),
        dae_runtime_control::OwnerGeneration::new(generation),
    )
    .unwrap();

    let first = open_xhttp_h3_proxy_client(&binding, &endpoint)
        .await
        .unwrap();
    let mut first_response = open_xhttp_h3_download_stream(
        &endpoint,
        first.client.clone(),
        "first",
        first.xmux_lease.as_ref(),
    )
    .await
    .unwrap();
    assert!(first_response.recv_data().await.unwrap().is_none());
    goaway_observed.await.unwrap();

    let rejected = match open_xhttp_h3_download_stream(
        &endpoint,
        first.client.clone(),
        "after-goaway",
        first.xmux_lease.as_ref(),
    )
    .await
    {
        Ok(_) => panic!("HTTP/3 request unexpectedly opened after GOAWAY"),
        Err(error) => error,
    };
    assert!(
        rejected.contains("RemoteClosing")
            || rejected.contains("H3_REQUEST_REJECTED")
            || rejected.contains("RemoteTerminate"),
        "unexpected request rejection after GOAWAY: {rejected}"
    );
    drop(first);

    let replacement = open_xhttp_h3_proxy_client(&binding, &endpoint)
        .await
        .unwrap();
    let mut replacement_response = open_xhttp_h3_download_stream(
        &endpoint,
        replacement.client.clone(),
        "replacement",
        replacement.xmux_lease.as_ref(),
    )
    .await
    .unwrap();
    assert!(replacement_response.recv_data().await.unwrap().is_none());
    assert_eq!(accepted_connections.load(Ordering::Relaxed), 2);
    drop(replacement);

    let report = shutdown_xhttp_xmux_generation_owner(
        &owner,
        owner_thread,
        RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE,
    );
    assert_eq!(report.h3.managers, 1);
    assert_eq!(report.h3.clients, 1);
    assert!(!report.cleanup_timed_out);
    assert!(report.owner_thread_joined);

    server_task.await.unwrap();
    server_endpoint.close(0_u32.into(), b"xhttp h3 owner test complete");
    server_endpoint.wait_idle().await;
}
