use super::*;

#[test]
fn prefixed_owned_grpc_hunk_matches_the_allocating_encoder() {
    for payload_len in [0, 1, 127, 128, 16 * 1024] {
        let payload = vec![payload_len as u8; payload_len];
        let mut owned = vec![0_u8; GRPC_HUNK_IN_PLACE_PREFIX_BYTES];
        owned.extend_from_slice(&payload);

        let actual =
            grpc_hunk_from_prefixed_payload(owned, GRPC_HUNK_IN_PLACE_PREFIX_BYTES).unwrap();
        let expected = grpc_hunk_frame(&payload).unwrap();
        assert_eq!(&actual[..], expected);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn h2_data_larger_than_the_stream_window_is_sent_incrementally() {
    const INITIAL_WINDOW_BYTES: u32 = 1024;
    const PAYLOAD_BYTES: usize = 128 * 1024;

    let payload = Bytes::from(
        (0..PAYLOAD_BYTES)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let expected = payload.clone();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);

    let server_task = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(INITIAL_WINDOW_BYTES)
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap();
        let (request, _) = connection.accept().await.unwrap().unwrap();
        let mut receive_task = tokio::spawn(async move {
            let mut body = request.into_body();
            let mut received = Vec::with_capacity(PAYLOAD_BYTES);
            let mut chunks = 0usize;
            let mut ended_before_payload_complete = false;

            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                chunks += 1;
                received.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len()).unwrap();
                if body.is_end_stream() && received.len() < PAYLOAD_BYTES {
                    ended_before_payload_complete = true;
                }
            }

            (received, chunks, ended_before_payload_complete)
        });
        loop {
            tokio::select! {
                result = &mut receive_task => return result.unwrap(),
                accepted = connection.accept() => {
                    if accepted.is_none() {
                        return receive_task.await.unwrap();
                    }
                }
            }
        }
    });

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let connection_task = tokio::spawn(connection);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://h2.fixture.invalid/upload")
        .body(())
        .unwrap();
    let (_, mut send_stream) = client.send_request(request, false).unwrap();

    time::timeout(
        Duration::from_secs(2),
        send_h2_data_with_context(&mut send_stream, payload, true, "H2 window test"),
    )
    .await
    .expect("sending a body larger than the H2 stream window stalled")
    .unwrap();

    let (received, chunks, ended_before_payload_complete) =
        time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("server did not receive the complete H2 body")
            .unwrap();
    assert_eq!(received, expected);
    assert!(chunks > 1, "the fixture did not exercise DATA splitting");
    assert!(!ended_before_payload_complete);

    connection_task.abort();
    let _ = connection_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn h2_data_send_error_is_propagated_after_stream_reset() {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let server_task = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let _ = connection.accept().await;
    });
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let connection_task = tokio::spawn(connection);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://h2.fixture.invalid/reset")
        .body(())
        .unwrap();
    let (_, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream.send_reset(h2::Reason::CANCEL);

    let error = send_h2_data_with_context(
        &mut send_stream,
        Bytes::from_static(b"payload after reset"),
        true,
        "H2 reset test",
    )
    .await
    .unwrap_err();
    assert!(
        error.contains("send H2 reset test data")
            || error.contains("reserve H2 reset test send capacity")
            || error.contains("send stream closed"),
        "unexpected reset error: {error}"
    );

    connection_task.abort();
    let _ = connection_task.await;
    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_stream_open_does_not_wait_for_response_headers_before_upload_can_continue() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (first_hunk_seen_tx, first_hunk_seen_rx) = tokio::sync::oneshot::channel();

    let server_task = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut body = request.into_body();
        tokio::spawn(async move {
            let first = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(first.len()).unwrap();
            let _ = first_hunk_seen_tx.send(());
            let second = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(second.len()).unwrap();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from(grpc_hunk_frame(b"server-data").unwrap()), true)
                .unwrap();
        });
        while connection.accept().await.is_some() {}
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://grpc.fixture.invalid/GunService/Tun")
        .body(())
        .unwrap();
    let opened = time::timeout(
        Duration::from_millis(200),
        open_grpc_h2_stream_on_io(client_io, request, b"protocol-header"),
    )
    .await;

    time::timeout(Duration::from_millis(200), first_hunk_seen_rx)
        .await
        .expect("server did not receive the first gRPC hunk")
        .expect("server dropped first-hunk observation");
    let (mut send_stream, mut response, connection_task) = opened.expect(
        "gRPC stream opening waited for response headers before application upload could continue"
    ).unwrap();
    send_grpc_hunk(&mut send_stream, b"application-data", false)
        .await
        .unwrap();
    let response_data = time::timeout(Duration::from_millis(200), response.next_data())
        .await
        .expect("gRPC response did not arrive after later upload")
        .unwrap()
        .unwrap();
    assert_eq!(
        response_data,
        Bytes::from(grpc_hunk_frame(b"server-data").unwrap())
    );

    connection_task.abort();
    let _ = connection_task.await;
    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_response_requires_a_success_terminal_status() {
    for (status, expected_error) in [
        (Some("0"), None),
        (Some("7"), Some("reported grpc-status 7")),
        (None, Some("ended without grpc-status")),
    ] {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let response = http::Response::builder()
                .status(200)
                .version(http::Version::HTTP_2)
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, status.is_none()).unwrap();
            if let Some(status) = status {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", status.parse().unwrap());
                send.send_trailers(trailers).unwrap();
            }
            drop(request);
            let _ = time::timeout(Duration::from_millis(200), connection.accept()).await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .version(http::Version::HTTP_2)
            .uri("https://grpc.fixture.invalid/GunService/Tun")
            .body(())
            .unwrap();
        let (_, mut response, connection_task) =
            open_grpc_h2_stream_on_io(client_io, request, b"protocol-header")
                .await
                .unwrap();
        let terminal = response.next_data().await;
        match expected_error {
            Some(expected) => {
                let error = terminal.unwrap_err();
                assert!(error.contains(expected), "{error}");
            }
            None => assert!(terminal.unwrap().is_none()),
        }
        connection_task.abort();
        let _ = connection_task.await;
        server_task.abort();
        let _ = server_task.await;
    }
}
