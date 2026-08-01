use super::*;
use bytes::Buf;
use h3::server;
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::BTreeMap;
use tokio::sync::{mpsc, oneshot};

fn server_config() -> quinn::ServerConfig {
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
        reality: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_h3_responses_do_not_serialize_packet_up_requests() {
    let server_endpoint =
        quinn::Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
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
    let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(
        build_xhttp_h3_client_config(&endpoint, ResidentXhttpQuicTlsProvider::Rustls).unwrap(),
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
