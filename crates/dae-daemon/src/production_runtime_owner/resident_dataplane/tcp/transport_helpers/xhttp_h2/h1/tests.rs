use super::*;
use tokio::sync::oneshot;

fn packet_up_endpoint() -> ResidentXhttpEndpointPlan {
    ResidentXhttpEndpointPlan {
        server_host: "xhttp.test".to_owned(),
        server_port: 443,
        server_name: "xhttp.test".to_owned(),
        alpn: vec!["http/1.1".to_owned()],
        stream_host: "xhttp.test".to_owned(),
        stream_path: "/xhttp".to_owned(),
        mode: ResidentXhttpMode::PacketUp,
        settings: ResidentXhttpSettingsPlan::official_default(),
        xmux: None,
        allow_insecure: false,
        tls_fragment: None,
        utls_fingerprint: None,
        ech: None,
        reality: None,
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(head: &[u8]) -> usize {
    std::str::from_utf8(head)
        .unwrap()
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0)
}

async fn serve_delayed_h1_request(
    mut server: tokio::io::DuplexStream,
    accepted: oneshot::Sender<Vec<u8>>,
    release: oneshot::Receiver<()>,
) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = server.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&buffer[..read]);
        let Some(end) = header_end(&request) else {
            continue;
        };
        let expected = end + 4 + content_length(&request[..end]);
        if request.len() >= expected {
            break;
        }
    }
    accepted.send(request).unwrap();
    release.await.unwrap();
    server
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn delayed_h1_responses_do_not_serialize_independent_packet_up_connections() {
    let endpoint = packet_up_endpoint();
    let (first_client, first_server) = tokio::io::duplex(16 * 1024);
    let (second_client, second_server) = tokio::io::duplex(16 * 1024);
    let (first_accepted_tx, first_accepted_rx) = oneshot::channel();
    let (second_accepted_tx, second_accepted_rx) = oneshot::channel();
    let (first_release_tx, first_release_rx) = oneshot::channel();
    let (second_release_tx, second_release_rx) = oneshot::channel();
    let first_server_task = tokio::spawn(serve_delayed_h1_request(
        first_server,
        first_accepted_tx,
        first_release_rx,
    ));
    let second_server_task = tokio::spawn(serve_delayed_h1_request(
        second_server,
        second_accepted_tx,
        second_release_rx,
    ));

    let first_request =
        xhttp_h1_packet_up_request_bytes(&endpoint, "session", 1, Bytes::from_static(b"one"))
            .unwrap();
    let second_request =
        xhttp_h1_packet_up_request_bytes(&endpoint, "session", 2, Bytes::from_static(b"two"))
            .unwrap();
    let first_completion = time::timeout(
        Duration::from_secs(1),
        begin_xhttp_h1_packet_up_request_on_client(first_client, first_request),
    )
    .await
    .expect("first packet-up begin waited for response")
    .unwrap();
    let second_completion = time::timeout(
        Duration::from_secs(1),
        begin_xhttp_h1_packet_up_request_on_client(second_client, second_request),
    )
    .await
    .expect("second packet-up begin waited for response")
    .unwrap();

    let first_received = time::timeout(Duration::from_secs(1), first_accepted_rx)
        .await
        .unwrap()
        .unwrap();
    let second_received = time::timeout(Duration::from_secs(1), second_accepted_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(first_received.ends_with(b"one"));
    assert!(second_received.ends_with(b"two"));

    second_release_tx.send(()).unwrap();
    time::timeout(Duration::from_secs(1), second_completion)
        .await
        .unwrap()
        .unwrap();
    first_release_tx.send(()).unwrap();
    time::timeout(Duration::from_secs(1), first_completion)
        .await
        .unwrap()
        .unwrap();
    first_server_task.await.unwrap();
    second_server_task.await.unwrap();
}
