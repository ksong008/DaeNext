use super::*;
use tokio::sync::oneshot;

#[tokio::test]
async fn h1_pool_reuses_only_fully_drained_responses() {
    let pool = XhttpH1UploadPool::new(1);
    let (client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n".as_slice(),
        ] {
            let _ = read_h1_request(&mut server).await;
            server.write_all(response).await.unwrap();
        }
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    });
    let mut client = Some(client);
    for _ in 0..2 {
        let (pooled, owner, permit) = pool.take().await.unwrap();
        let client = pooled
            .or_else(|| client.take())
            .expect("connection was not reused");
        send_on_connection(
            client,
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nx".to_vec(),
            Some((owner, permit)),
        )
        .await
        .unwrap()
        .await
        .unwrap();
    }
    drop(pool);
    time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn h1_pool_cancellation_releases_capacity_and_drops_the_socket() {
    let pool = XhttpH1UploadPool::new(1);
    let (client, mut server) = tokio::io::duplex(8192);
    let (_, owner, permit) = pool.take().await.unwrap();
    assert!(
        time::timeout(Duration::from_millis(10), pool.take())
            .await
            .is_err()
    );
    let completion = send_on_connection(
        client,
        b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec(),
        Some((owner, permit)),
    )
    .await
    .unwrap();
    read_h1_request(&mut server).await;
    drop(completion);
    let (idle, _, permit) = pool.take().await.unwrap();
    assert!(idle.is_none());
    drop(permit);
    let mut byte = [0];
    assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    pool.close();
    assert!(pool.take().await.is_err());
}

#[tokio::test]
async fn h1_pool_rejects_unframed_close_ambiguous_or_excessive_responses() {
    for head in [
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0",
        "HTTP/1.1 200 OK",
        "HTTP/1.1 200 OK\r\nContent-Length: 1000000",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0",
    ] {
        let response = parse_xhttp_h1_response_head(head.as_bytes(), Vec::new(), "test").unwrap();
        assert!(
            !drain_response(&mut tokio::io::empty(), response)
                .await
                .unwrap()
        );
    }
    let response = parse_xhttp_h1_response_head(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
        b"bad!\r\n".to_vec(),
        "test",
    )
    .unwrap();
    assert!(
        drain_response(&mut tokio::io::empty(), response)
            .await
            .is_err()
    );
}

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

async fn read_h1_request<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0; 2048];
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&buffer[..read]);
        if let Some(end) = header_end(&request)
            && request.len() >= end + 4 + content_length(&request[..end])
        {
            return request;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_headers_waiting_for_upload_do_not_block_h1_packet_up() {
    for ua in [None, Some("firefox"), Some("Custom-UA/1")] {
        delayed_h1_download_headers(ua).await;
    }
}

async fn delayed_h1_download_headers(ua: Option<&'static str>) {
    use boring::ssl::{SslAcceptor, SslMethod};
    use dae_outbound::shared_transport::test_support::self_signed_tls_identity;

    let identity = self_signed_tls_identity(&["xhttp.test"]).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(&identity.certificate).unwrap();
    acceptor.set_private_key(&identity.private_key).unwrap();
    let acceptor = acceptor.build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut download = tokio_boring::accept(&acceptor, stream).await.unwrap();
        assert!(
            read_h1_request(&mut download)
                .await
                .starts_with(b"GET /xhttp/session ")
        );
        // Simulate a CDN which forwards response headers only with origin data.
        let (stream, _) = listener.accept().await.unwrap();
        let mut upload = tokio_boring::accept(&acceptor, stream).await.unwrap();
        let request = read_h1_request(&mut upload).await;
        assert!(request.starts_with(b"POST /xhttp/session/0 "));
        let head = std::str::from_utf8(&request[..header_end(&request).unwrap()]).unwrap();
        let marker = match ua {
            None => "Chrome/",
            Some("firefox") => "Firefox/",
            Some(custom) => custom,
        };
        assert!(head.contains(marker));
        assert_eq!(
            head.contains("Sec-Fetch-Mode: cors\r\n"),
            ua != Some("Custom-UA/1")
        );
        assert!(request.ends_with(b"first packet"));
        upload
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        upload.flush().await.unwrap();
        download
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nreply\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
        download.flush().await.unwrap();
    });
    let mut endpoint = packet_up_endpoint();
    if let Some(ua) = ua {
        endpoint
            .settings
            .headers
            .insert("user-agent".into(), ua.into());
    }
    endpoint.server_host = address.ip().to_string();
    endpoint.server_port = address.port();
    endpoint.allow_insecure = true;
    let client = open_async_xhttp_endpoint_tls_client(&endpoint, 0, false)
        .await
        .unwrap();
    let body = time::timeout(
        Duration::from_secs(2),
        open_xhttp_h1_download_stream_with_client(client, &endpoint, "session"),
    )
    .await
    .expect("download waited for response headers before allowing upload")
    .unwrap();
    let mut download = XhttpDownloadClient::H1 { body };
    assert!(
        poll_xhttp_download_data(&mut download)
            .await
            .unwrap()
            .is_none()
    );
    time::timeout(Duration::from_secs(2), async {
        let upload = open_async_xhttp_endpoint_tls_client(&endpoint, 0, false)
            .await
            .unwrap();
        let request = xhttp_h1_packet_up_request_bytes(
            &endpoint,
            "session",
            0,
            Bytes::from_static(b"first packet"),
        )
        .unwrap();
        begin_xhttp_h1_packet_up_request_on_client(upload, request)
            .await
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            read_xhttp_download_data(&mut download).await.unwrap(),
            Some(Bytes::from_static(b"reply"))
        );
    })
    .await
    .expect("upload and delayed download did not make progress");
    close_xhttp_download_client(download).await;
    server.await.unwrap();
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
