use super::*;

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
