use super::*;
use std::collections::BTreeMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_keep_alive_waits_for_read_idle() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let activity = Arc::new(ReadActivity::new());
    let (sender, connection) = h2::client::handshake(ReadActivityIo::new(client, activity.clone()))
        .await
        .unwrap();
    let driver = tokio::spawn(drive_xhttp_h2_connection(
        connection,
        Some(Duration::from_millis(60)),
        Duration::from_secs(1),
        Some(activity),
    ));
    let (mut reader, mut writer) = tokio::io::split(server);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let reader_task = tokio::spawn(async move {
        let mut preface = [0; 24];
        reader.read_exact(&mut preface).await.unwrap();
        loop {
            let mut head = [0; 9];
            if reader.read_exact(&mut head).await.is_err() {
                break;
            }
            let size =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            let mut payload = vec![0; size];
            reader.read_exact(&mut payload).await.unwrap();
            if head[3] == 6 && head[4] == 0 {
                let _ = tx.send(());
            }
        }
    });
    writer
        .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    for _ in 0..12 {
        writer
            .write_all(&[0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            .await
            .unwrap();
        time::sleep(Duration::from_millis(10)).await;
        assert!(
            rx.try_recv().is_err(),
            "active reads must postpone the probe"
        );
    }
    time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    drop(sender);
    driver.abort();
    reader_task.abort();
}

#[test]
fn keep_alive_parameter_selects_default_explicit_or_disabled() {
    let mut xmux = ResidentXhttpXmuxPlan::official_default();
    for default in [Duration::from_secs(45), Duration::from_secs(10)] {
        assert_eq!(
            xhttp_keep_alive_interval(None, default).unwrap(),
            Some(default)
        );
        for (configured, expected) in [
            (0, Some(default)),
            (7, Some(Duration::from_secs(7))),
            (-1, None),
        ] {
            xmux.h_keep_alive_period = configured;
            assert_eq!(
                xhttp_keep_alive_interval(Some(&xmux), default).unwrap(),
                expected
            );
        }
    }
    xmux.h_keep_alive_period = i64::MAX;
    assert!(xhttp_keep_alive_interval(Some(&xmux), Duration::from_secs(45)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_carrier_keep_alive_emits_ping_and_bounds_missing_pong() {
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(drive_xhttp_h2_connection(
        connection,
        Some(Duration::from_millis(5)),
        Duration::from_millis(50),
        None,
    ));
    let server = tokio::spawn(async move {
        let mut preface = [0; 24];
        server_io.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        server_io
            .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut pings = 0;
        loop {
            let mut head = [0; 9];
            if server_io.read_exact(&mut head).await.is_err() {
                break;
            }
            let len =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            assert!(len <= 64 * 1024);
            let mut payload = vec![0; len];
            server_io.read_exact(&mut payload).await.unwrap();
            if head[3] == 6 && head[4] == 0 {
                assert_eq!(len, 8);
                pings += 1;
                if pings == 1 {
                    head[4] = 1;
                    server_io.write_all(&head).await.unwrap();
                    server_io.write_all(&payload).await.unwrap();
                }
                // The second PING is deliberately unanswered.
            }
        }
        assert_eq!(pings, 2);
    });
    time::timeout(Duration::from_secs(2), driver)
        .await
        .expect("unresponsive H2 carrier was not closed")
        .unwrap();
    time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    drop(sender);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_h2_keep_alive_leaves_the_carrier_open() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let mut driver = tokio::spawn(drive_xhttp_h2_connection(
        connection,
        None,
        Duration::from_millis(5),
        None,
    ));
    assert!(
        time::timeout(Duration::from_millis(25), &mut driver)
            .await
            .is_err()
    );
    drop(sender);
    drop(server_io);
    time::timeout(Duration::from_secs(1), driver)
        .await
        .unwrap()
        .unwrap();
}

fn packet_up_endpoint() -> ResidentXhttpEndpointPlan {
    ResidentXhttpEndpointPlan {
        server_host: "xhttp.test".to_owned(),
        server_port: 443,
        server_name: "xhttp.test".to_owned(),
        alpn: vec!["h2".to_owned()],
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn download_headers_waiting_for_upload_do_not_block_h2_packet_up() {
    for ua in [None, Some("firefox"), Some("Custom-UA/1")] {
        delayed_h2_download_headers(ua).await;
    }
}

async fn delayed_h2_download_headers(ua: Option<&'static str>) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (download, mut download_response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(download.method(), http::Method::GET);
        let (upload, mut upload_response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(upload.method(), http::Method::POST);
        let marker = match ua {
            None => "Chrome/",
            Some("firefox") => "Firefox/",
            Some(custom) => custom,
        };
        assert!(
            upload.headers()["user-agent"]
                .to_str()
                .unwrap()
                .contains(marker)
        );
        assert_eq!(
            upload
                .headers()
                .get("sec-fetch-mode")
                .map(|v| v.to_str().unwrap()),
            (ua != Some("Custom-UA/1")).then_some("cors")
        );
        let handler = tokio::spawn(async move {
            let mut body = upload.into_body();
            let mut received = Vec::new();
            while let Some(bytes) = body.data().await {
                let bytes = bytes.unwrap();
                body.flow_control().release_capacity(bytes.len()).unwrap();
                received.extend_from_slice(&bytes);
            }
            assert_eq!(received, b"first packet");
            upload_response
                .send_response(http::Response::new(()), true)
                .unwrap();
            let mut body = download_response
                .send_response(http::Response::new(()), false)
                .unwrap();
            body.send_data(Bytes::from_static(b"reply"), true).unwrap();
        });
        tokio::select! {
            _ = released => {},
            extra = connection.accept() => assert!(extra.is_none()),
        }
        handler.await.unwrap();
    });
    let mut endpoint = packet_up_endpoint();
    if let Some(ua) = ua {
        endpoint
            .settings
            .headers
            .insert("user-agent".into(), ua.into());
    }
    let download = time::timeout(
        Duration::from_secs(2),
        open_xhttp_h2_download_stream(&mut sender, &endpoint, "session", None),
    )
    .await
    .expect("download waited for response headers before allowing upload")
    .unwrap();
    let mut download_client = XhttpDownloadClient::H2 {
        recv: download,
        _keepalive_sender: None,
        connection_task: None,
        xmux_lease: None,
    };
    assert!(
        poll_xhttp_download_data(&mut download_client)
            .await
            .unwrap()
            .is_none()
    );
    time::timeout(Duration::from_secs(2), async {
        begin_xhttp_h2_packet_up_request(
            &mut sender,
            &endpoint,
            "session",
            0,
            Bytes::from_static(b"first packet"),
        )
        .await
        .unwrap()
        .await
        .unwrap();
        assert_eq!(
            read_xhttp_download_data(&mut download_client)
                .await
                .unwrap(),
            Some(Bytes::from_static(b"reply"))
        );
    })
    .await
    .expect("upload and delayed download did not make progress");
    release.send(()).unwrap();
    drop(download_client);
    drop(sender);
    server.await.unwrap();
    driver.abort();
    let _ = driver.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_one_headers_are_read_after_further_h2_upload() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        let handler = tokio::spawn(async move {
            let mut body = request.into_body();
            let mut received = Vec::new();
            while let Some(bytes) = body.data().await {
                let bytes = bytes.unwrap();
                body.flow_control().release_capacity(bytes.len()).unwrap();
                received.extend_from_slice(&bytes);
            }
            assert_eq!(received, b"prefixpayload");
            let mut body = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            body.send_data(Bytes::from_static(b"reply"), true).unwrap();
        });
        tokio::select! {
            _ = released => {},
            extra = connection.accept() => assert!(extra.is_none()),
        }
        handler.await.unwrap();
    });
    let request = xhttp_h2_request(http::Method::POST, &packet_up_endpoint(), "", true).unwrap();
    let (response, mut upload) = sender.send_request(request, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"prefix"), false)
        .unwrap();
    let mut download = xhttp_h2_response_body(response, "xHTTP HTTP/2 stream-one");
    upload
        .send_data(Bytes::from_static(b"payload"), true)
        .unwrap();
    let received = time::timeout(Duration::from_secs(2), async {
        download
            .resolve()
            .await
            .unwrap()
            .data()
            .await
            .unwrap()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(received, Bytes::from_static(b"reply"));
    release.send(()).unwrap();
    drop(download);
    drop(upload);
    drop(sender);
    server.await.unwrap();
    driver.abort();
    let _ = driver.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_h2_response_still_rejects_http_errors() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let (release, released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (_, mut response) = connection.accept().await.unwrap().unwrap();
        response
            .send_response(
                http::Response::builder().status(403).body(()).unwrap(),
                true,
            )
            .unwrap();
        tokio::select! {
            _ = released => {},
            _ = connection.accept() => {},
        }
    });
    let mut download =
        open_xhttp_h2_download_stream(&mut sender, &packet_up_endpoint(), "session", None)
            .await
            .unwrap();
    let error = time::timeout(Duration::from_secs(2), download.resolve())
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.contains("403"), "{error}");
    assert_eq!(download.resolve().await.unwrap_err(), error);
    release.send(()).unwrap();
    server.await.unwrap();
    driver.abort();
    let _ = driver.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_h2_responses_do_not_serialize_packet_up_requests() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let (accepted_tx, mut accepted_rx) = mpsc::channel(3);
    let (response_sent_tx, mut response_sent_rx) = mpsc::channel(3);
    let (server_release_tx, server_release_rx) = oneshot::channel();
    let mut release_senders = BTreeMap::new();
    let mut release_receivers = BTreeMap::new();
    for seq in 1..=3 {
        let (release_tx, release_rx) = oneshot::channel();
        release_senders.insert(seq, release_tx);
        release_receivers.insert(seq, release_rx);
    }
    let server_task = tokio::spawn(async move {
        let mut builder = h2::server::Builder::new();
        builder.max_concurrent_streams(100);
        let mut server = builder.handshake::<_, Bytes>(server_io).await.unwrap();
        let mut handlers = tokio::task::JoinSet::new();
        for _ in 0..3 {
            let (request, mut response) = server.accept().await.unwrap().unwrap();
            let seq = request
                .uri()
                .path()
                .rsplit('/')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            let accepted_tx = accepted_tx.clone();
            let response_sent_tx = response_sent_tx.clone();
            let release = release_receivers.remove(&seq).unwrap();
            handlers.spawn(async move {
                let mut response_stream = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                accepted_tx.send(seq).await.unwrap();
                release.await.unwrap();
                drop(request);
                response_stream
                    .send_data(Bytes::from_static(b"ok"), true)
                    .unwrap();
                response_sent_tx.send(seq).await.unwrap();
            });
        }
        drop(accepted_tx);
        drop(response_sent_tx);
        while !handlers.is_empty() {
            tokio::select! {
                result = handlers.join_next() => result.unwrap().unwrap(),
                accepted = server.accept() => {
                    assert!(accepted.is_none(), "unexpected extra H2 packet-up request");
                }
            }
        }
        tokio::pin!(server_release_rx);
        loop {
            tokio::select! {
                result = &mut server_release_rx => {
                    result.unwrap();
                    break;
                }
                accepted = server.accept() => {
                    assert!(accepted.is_none(), "unexpected extra H2 packet-up request");
                }
            }
        }
    });

    let endpoint = packet_up_endpoint();
    let mut completions = Vec::new();
    for (seq, payload) in [
        (1, Bytes::from_static(b"first")),
        (2, Bytes::from_static(b"second")),
        (3, Bytes::from_static(b"third")),
    ] {
        let completion = time::timeout(
            Duration::from_secs(1),
            begin_xhttp_h2_packet_up_request(&mut sender, &endpoint, "session", seq, payload),
        )
        .await
        .expect("packet-up begin waited for response")
        .unwrap();
        completions.push(completion);
    }

    let mut accepted = Vec::new();
    for _ in 0..3 {
        accepted.push(
            time::timeout(Duration::from_secs(1), accepted_rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    accepted.sort_unstable();
    assert_eq!(accepted, vec![1, 2, 3]);

    release_senders.remove(&3).unwrap().send(()).unwrap();
    assert_eq!(
        time::timeout(Duration::from_secs(1), response_sent_rx.recv())
            .await
            .unwrap(),
        Some(3)
    );
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();
    release_senders.remove(&2).unwrap().send(()).unwrap();
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();
    release_senders.remove(&1).unwrap().send(()).unwrap();
    time::timeout(Duration::from_secs(1), completions.pop().unwrap())
        .await
        .unwrap()
        .unwrap();

    server_release_tx.send(()).unwrap();
    drop(sender);
    server_task.await.unwrap();
    connection_task.await.unwrap();
}
