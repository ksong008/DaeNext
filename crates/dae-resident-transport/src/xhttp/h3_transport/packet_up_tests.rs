use super::*;
use bytes::Buf;
use dae_outbound::shared_transport::test_support::{
    boring_quic_server_config, self_signed_tls_identity,
};
use dae_resident_plan::{ResidentEchPlan, ResidentUtlsFingerprintPlan};
use h3::server;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use tokio::sync::{mpsc, oneshot};

use super::super::xmux::xhttp_xmux_test_lease;

fn server_config() -> quinn::ServerConfig {
    let identity = self_signed_tls_identity(&["localhost"]).unwrap();
    boring_quic_server_config(
        &identity,
        &[b"h3".to_vec()],
        Arc::new(quinn::TransportConfig::default()),
    )
    .unwrap()
}

fn packet_up_endpoint(server: SocketAddr) -> ResidentXhttpEndpointPlan {
    ResidentXhttpEndpointPlan {
        server_host: server.ip().to_string(),
        server_port: server.port(),
        server_name: "localhost".to_owned(),
        alpn: vec!["h3".to_owned()],
        stream_host: "localhost".to_owned(),
        stream_path: "/xhttp".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings: ResidentXhttpSettingsPlan::official_default(),
        xmux: None,
        allow_insecure: true,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
    }
}

#[test]
fn h3_ech_fails_closed_for_every_quic_tls_provider() {
    const ECH_CONFIG_LIST: &str =
        "AD7+DQA6AAAgACC7Lynj4wV+BBnVL8X0QRh3b422HOpP33YHm5NgbFpiSAAIAAEAAQABAAMAB2VjaC5jb20AAA==";

    let mut endpoint = packet_up_endpoint("127.0.0.1:443".parse().unwrap());
    endpoint.ech = Some(ResidentEchPlan::new(
        dae_outbound::shared_transport::EchConfigList::parse_base64(ECH_CONFIG_LIST).unwrap(),
    ));

    for provider in [
        ResidentXhttpQuicTlsProvider::Boring,
        ResidentXhttpQuicTlsProvider::ChromeBoring,
    ] {
        let error = match build_xhttp_h3_client_config(&endpoint, provider, None) {
            Ok(_) => panic!("{} silently accepted ECH", provider.as_str()),
            Err(error) => error,
        };
        assert!(error.contains("xHTTP H3 ECH is unavailable"));
        assert!(error.contains(provider.as_str()));
        assert!(error.contains("authenticated retry configs"));
    }
}

#[test]
fn h3_download_provider_and_session_namespace_follow_the_endpoint_plan() {
    let mut endpoint = packet_up_endpoint("127.0.0.1:443".parse().unwrap());
    endpoint.utls_fingerprint = Some(ResidentUtlsFingerprintPlan {
        source: "downloadSettings.tlsSettings.fingerprint",
        requested: "chrome".to_owned(),
        name: "chrome".to_owned(),
        canonical: "chrome_auto".to_owned(),
        family: dae_outbound::shared_transport::UTLS_FAMILY_CHROME.to_owned(),
        client: "Chrome".to_owned(),
        randomized: false,
        alpn_policy: dae_outbound::shared_transport::UTLS_ALPN_POLICY_AUTO.to_owned(),
        default_alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
    });
    let provider =
        xhttp_h3_tls_provider(&endpoint, QuicEndpointIdentityRole::XhttpDownload).unwrap();
    assert_eq!(provider, ResidentXhttpQuicTlsProvider::ChromeBoring);

    let primary = xhttp_h3_session_namespace(
        &endpoint,
        QuicEndpointIdentityRole::XhttpPrimary,
        provider,
        None,
    );
    let download = xhttp_h3_session_namespace(
        &endpoint,
        QuicEndpointIdentityRole::XhttpDownload,
        provider,
        None,
    );
    assert_ne!(primary, download);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_h3_responses_do_not_serialize_packet_up_requests() {
    let server_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let accepting_endpoint = server_endpoint.clone();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (release_tx, mut release_rx) = mpsc::channel::<u64>(3);
    let server_task = tokio::spawn(async move {
        let connection = accepting_endpoint.accept().await.unwrap().await.unwrap();
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut incoming: server::Connection<h3_quinn::Connection, Bytes> =
            server::Connection::new(h3_connection).await.unwrap();
        let mut accepted = Vec::new();
        let mut responses = BTreeMap::new();
        for _ in 0..3 {
            let request = incoming.accept().await.unwrap().unwrap();
            let (request, mut stream) = request.resolve_request().await.unwrap();
            let seq = request
                .uri()
                .path()
                .rsplit('/')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            let mut payload = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                while chunk.has_remaining() {
                    let read = chunk.chunk().len();
                    payload.extend_from_slice(chunk.chunk());
                    chunk.advance(read);
                }
            }
            accepted.push((seq, Bytes::from(payload)));
            responses.insert(seq, stream);
        }
        accepted_tx.send(accepted).unwrap();
        while let Some(seq) = release_rx.recv().await {
            let mut stream = responses.remove(&seq).unwrap();
            stream.send_response(http::Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
        }
    });

    let endpoint = packet_up_endpoint(server_address);
    let mut client_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_client_endpoint(
            "0.0.0.0:0".parse().unwrap(),
        )
        .unwrap();
    client_endpoint.set_default_client_config(
        build_xhttp_h3_client_config(&endpoint, ResidentXhttpQuicTlsProvider::Boring, None)
            .unwrap(),
    );
    let connection = client_endpoint
        .connect(server_address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut client) = h3::client::new(h3_connection).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|context| driver.poll_close(context)).await;
    });

    let mut completions = Vec::new();
    for (seq, payload) in [
        (1, Bytes::from_static(b"first")),
        (2, Bytes::from_static(b"second")),
        (3, Bytes::from_static(b"third")),
    ] {
        let completion = time::timeout(
            Duration::from_secs(1),
            begin_xhttp_h3_packet_up_request(&mut client, &endpoint, "session", seq, payload, None),
        )
        .await
        .expect("packet-up begin waited for response")
        .unwrap();
        completions.push(completion);
    }

    let accepted = time::timeout(Duration::from_secs(1), accepted_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted,
        vec![
            (1, Bytes::from_static(b"first")),
            (2, Bytes::from_static(b"second")),
            (3, Bytes::from_static(b"third")),
        ]
    );

    release_tx.send(3).await.unwrap();
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();
    release_tx.send(2).await.unwrap();
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();
    release_tx.send(1).await.unwrap();
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();

    drop(release_tx);
    drop(client);
    server_task.await.unwrap();
    connection.close(0_u32.into(), b"xhttp h3 packet-up test complete");
    driver_task.abort();
    client_endpoint.wait_idle().await;
    server_endpoint.close(0_u32.into(), b"xhttp h3 packet-up test complete");
    server_endpoint.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn low_request_budget_h3_rotation_keeps_the_replacement_lease() {
    let server_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let accepting_endpoint = server_endpoint.clone();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let connection = accepting_endpoint.accept().await.unwrap().await.unwrap();
        let h3_connection = h3_quinn::Connection::new(connection);
        let mut incoming: server::Connection<h3_quinn::Connection, Bytes> =
            server::Connection::new(h3_connection).await.unwrap();
        accepted_tx.send(()).unwrap();
        let _ = incoming.accept().await;
    });

    let endpoint = packet_up_endpoint(server_address);
    let mut client_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_client_endpoint(
            "0.0.0.0:0".parse().unwrap(),
        )
        .unwrap();
    client_endpoint.set_default_client_config(
        build_xhttp_h3_client_config(&endpoint, ResidentXhttpQuicTlsProvider::Boring, None)
            .unwrap(),
    );
    let connection = client_endpoint
        .connect(server_address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, client) = h3::client::new(h3_connection).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|context| driver.poll_close(context)).await;
    });
    accepted_rx.await.unwrap();

    let (old_lease, old_usage) = xhttp_xmux_test_lease(1);
    let old_request = old_lease.request_handle();
    assert!(
        !old_request.use_for_packet_up_post(),
        "the first POST must exhaust a one-request physical budget"
    );

    let (new_lease, new_usage) = xhttp_xmux_test_lease(2);
    let replacement = XhttpH3EndpointClient {
        client: client.clone(),
        connection: None,
        xmux_lease: Some(new_lease),
    };
    let mut active_client = client;
    let mut active_connection = None;
    let mut active_lease = Some(old_lease);
    let mut active_request = Some(old_request);
    assert!(
        install_xhttp_h3_packet_up_replacement(
            &mut active_client,
            &mut active_connection,
            &mut active_lease,
            &mut active_request,
            replacement,
        )
        .is_none()
    );

    assert_eq!(old_usage.open_usage.load(Ordering::Acquire), 0);
    assert_eq!(new_usage.open_usage.load(Ordering::Acquire), 1);
    let active_request = active_request.as_ref().unwrap();
    assert!(active_request.use_for_packet_up_post());
    assert!(
        !active_request.use_for_packet_up_post(),
        "each H3 POST must consume exactly one request-budget unit"
    );
    assert_eq!(new_usage.left_requests.load(Ordering::Acquire), 0);

    drop(active_lease.take());
    assert_eq!(new_usage.open_usage.load(Ordering::Acquire), 0);
    drop(active_client);
    connection.close(0_u32.into(), b"xhttp h3 packet-up rotation test complete");
    server_task.await.unwrap();
    driver_task.abort();
    client_endpoint.wait_idle().await;
    server_endpoint.close(0_u32.into(), b"xhttp h3 packet-up rotation test complete");
    server_endpoint.wait_idle().await;
}
