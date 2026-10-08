use super::*;
use bytes::Buf;
use dae_outbound::shared_transport::test_support::{
    boring_quic_server_config, self_signed_tls_identity,
};
use dae_resident_model::{ResidentEchPlan, ResidentUtlsFingerprintPlan};
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

async fn delayed_h3_download_headers(stream_one: bool, ua: Option<&'static str>) {
    let server_endpoint =
        dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
            server_config(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
    let address = server_endpoint.local_addr().unwrap();
    let accepting = server_endpoint.clone();
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let connection = accepting.accept().await.unwrap().await.unwrap();
        let mut incoming: server::Connection<h3_quinn::Connection, Bytes> =
            server::Connection::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let (request, mut download) = incoming
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        let mut received = Vec::new();
        let marker = match ua {
            None => "Chrome/",
            Some("firefox") => "Firefox/",
            Some(custom) => custom,
        };
        assert!(
            request.headers()["user-agent"]
                .to_str()
                .unwrap()
                .contains(marker)
        );
        assert_eq!(
            request
                .headers()
                .get("sec-fetch-mode")
                .map(|v| v.to_str().unwrap()),
            (ua != Some("Custom-UA/1")).then_some("cors")
        );
        if stream_one {
            assert_eq!(request.method(), http::Method::POST);
            while let Some(mut chunk) = download.recv_data().await.unwrap() {
                let remaining = chunk.remaining();
                received.extend_from_slice(&chunk.copy_to_bytes(remaining));
            }
            assert_eq!(received, b"prefixpayload");
        } else {
            assert_eq!(request.method(), http::Method::GET);
            let (request, mut upload) = incoming
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.method(), http::Method::POST);
            while let Some(mut chunk) = upload.recv_data().await.unwrap() {
                let remaining = chunk.remaining();
                received.extend_from_slice(&chunk.copy_to_bytes(remaining));
            }
            assert_eq!(received, b"first packet");
            upload.send_response(http::Response::new(())).await.unwrap();
            upload.finish().await.unwrap();
        }
        download
            .send_response(http::Response::new(()))
            .await
            .unwrap();
        download
            .send_data(Bytes::from_static(b"reply"))
            .await
            .unwrap();
        download.finish().await.unwrap();
        let _ = released.await;
    });

    let mut endpoint = packet_up_endpoint(address);
    if let Some(ua) = ua {
        endpoint
            .settings
            .headers
            .insert("user-agent".into(), ua.into());
    }
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
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut client) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut download;
    let mut stream_upload = None;
    if stream_one {
        let request = xhttp_h3_request(http::Method::POST, &endpoint, "", true).unwrap();
        let mut stream = client.send_request(request).await.unwrap();
        stream
            .send_data(Bytes::from_static(b"prefix"))
            .await
            .unwrap();
        let (send, recv) = stream.split();
        download = XhttpDownloadClient::H3StreamOne {
            recv: xhttp_h3_response_body(recv, None, "xHTTP H3 stream-one"),
        };
        let mut upload = XhttpStreamUploadClient::H3StreamOne {
            send,
            connection: None,
            xmux_lease: None,
        };
        assert!(
            poll_xhttp_download_data(&mut download)
                .await
                .unwrap()
                .is_none()
        );
        send_xhttp_stream_data(&mut upload, Bytes::from_static(b"payload"), true)
            .await
            .unwrap();
        stream_upload = Some(upload);
    } else {
        let recv = time::timeout(
            Duration::from_secs(2),
            open_xhttp_h3_download_stream(&endpoint, client.clone(), "session", None),
        )
        .await
        .expect("download waited for response headers before allowing upload")
        .unwrap();
        download = XhttpDownloadClient::H3 {
            recv,
            connection: None,
            xmux_lease: None,
        };
        assert!(
            poll_xhttp_download_data(&mut download)
                .await
                .unwrap()
                .is_none()
        );
        time::timeout(Duration::from_secs(2), async {
            begin_xhttp_h3_packet_up_request(
                &mut client,
                &endpoint,
                "session",
                0,
                Bytes::from_static(b"first packet"),
                None,
            )
            .await
            .unwrap()
            .await
            .unwrap();
        })
        .await
        .expect("upload blocked behind download response headers");
    }
    assert_eq!(
        time::timeout(
            Duration::from_secs(2),
            read_xhttp_download_data(&mut download)
        )
        .await
        .unwrap()
        .unwrap(),
        Some(Bytes::from_static(b"reply"))
    );
    close_xhttp_download_client(download).await;
    if let Some(upload) = stream_upload {
        close_xhttp_stream_upload_client(upload).await;
    }
    release.send(()).unwrap();
    server.await.unwrap();
    drop(client);
    connection.close(0_u32.into(), b"deferred headers test complete");
    driver.abort();
    let _ = driver.await;
    client_endpoint.wait_idle().await;
    server_endpoint.close(0_u32.into(), b"deferred headers test complete");
    server_endpoint.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_headers_waiting_for_upload_do_not_block_h3_packet_up() {
    for ua in [None, Some("firefox"), Some("Custom-UA/1")] {
        delayed_h3_download_headers(false, ua).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_one_headers_are_read_after_further_h3_upload() {
    delayed_h3_download_headers(true, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_keep_alive_parameter_reaches_both_tls_providers() {
    for provider in [
        ResidentXhttpQuicTlsProvider::Boring,
        ResidentXhttpQuicTlsProvider::ChromeBoring,
    ] {
        let server_endpoint =
            dae_outbound::shared_transport::test_support::boring_quic_server_endpoint(
                server_config(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
        let address = server_endpoint.local_addr().unwrap();
        let accepting = server_endpoint.clone();
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = accepting.accept().await.unwrap().await.unwrap();
            let _ = released.await;
            drop(connection);
        });
        let mut endpoint = packet_up_endpoint(address);
        let mut xmux = ResidentXhttpXmuxPlan::official_default();
        xmux.h_keep_alive_period = 1;
        endpoint.xmux = Some(xmux);
        let mut client_endpoint =
            dae_outbound::shared_transport::test_support::boring_quic_client_endpoint(
                "0.0.0.0:0".parse().unwrap(),
            )
            .unwrap();
        client_endpoint.set_default_client_config(
            build_xhttp_h3_client_config(&endpoint, provider, None).unwrap(),
        );
        let connection = client_endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        // Let handshake ACKs settle before observing the idle keepalive.
        time::sleep(Duration::from_millis(100)).await;
        let initial_pings = connection.stats().frame_tx.ping;
        time::timeout(Duration::from_millis(2500), async {
            while connection.stats().frame_tx.ping == initial_pings {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("configured 1-second H3 keepalive was not sent");
        release.send(()).unwrap();
        server.await.unwrap();
        connection.close(0_u32.into(), b"keepalive test complete");
        client_endpoint.wait_idle().await;
        server_endpoint.close(0_u32.into(), b"keepalive test complete");
        server_endpoint.wait_idle().await;
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
