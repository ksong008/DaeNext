use super::*;

use crate::production_runtime_owner::resident_dataplane::ResidentRuntimeProfile;
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[tokio::test]
async fn port_hopping_preserves_the_live_quic_connection_across_streams() {
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
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
    let server_endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        for expected in [b"before-hop".as_slice(), b"after-hop".as_slice()] {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), expected);
            send.write_all(b"ok").await.unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
        }
    });

    let generation = dae_runtime_control::OwnerGeneration::new(8_206);
    let context = QuicEndpointOpenContext::from_identity_parts(
        QuicEndpointProtocol::Hysteria2,
        QuicEndpointCallerClass::BackgroundHealth,
        generation,
        QuicEndpointIdentityRole::ProtocolCarrier,
        &[b"port-hopping-live-connection-test"],
    );
    let cancellation = OwnerCancellationSignal::new();
    let metrics = Arc::new(Hysteria2PortHoppingMetrics::default());
    let resources =
        Hysteria2OwnerResourceProfile::from_runtime_profile(ResidentRuntimeProfile::LowMemory);
    let port_hopping = Hysteria2PortHoppingRuntimeConfig::new(
        vec![server_addr.ip()],
        Arc::new(vec![server_addr.port()]),
        Duration::from_millis(25),
        0,
        resources.port_hop_transition_socket_limit(),
        Arc::clone(&metrics),
    )
    .unwrap();
    let tls_identity = dae_outbound::hysteria2::Hysteria2TlsIdentity::from_node_and_global(
        "localhost".to_owned(),
        true,
        false,
        "",
    )
    .unwrap();
    let mut endpoint = open_marked_hysteria2_quic_endpoint_for_remote(
        0,
        &ResidentHysteria2ObfsPlan::none(),
        Some(port_hopping),
        server_addr,
        context,
        AbsoluteDeadline::from_now(Instant::now(), Duration::from_secs(2)),
        &cancellation,
    )
    .unwrap();
    endpoint.set_default_client_config(
        build_hysteria2_runtime_client_config_with_udp_overhead(&tls_identity, 0).unwrap(),
    );
    let initial_local = endpoint.local_addr().unwrap();
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    endpoint.mark_ready();
    let connection_id = connection.stable_id();

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"before-hop").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(8).await.unwrap(), b"ok");

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics.snapshot()["cumulativeSuccesses"]
                .as_u64()
                .unwrap_or_default()
                >= 1
                && endpoint.local_addr().unwrap() != initial_local
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client changed its UDP source socket");

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"after-hop").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(8).await.unwrap(), b"ok");
    assert_eq!(connection.stable_id(), connection_id);
    assert_eq!(metrics.snapshot()["activeSockets"], 2);

    connection.close(0_u32.into(), b"port hopping connection test complete");
    endpoint.close(0_u32.into(), b"port hopping endpoint test complete");
    endpoint.wait_idle().await;
    drop(endpoint);
    server_task.await.unwrap();
}
