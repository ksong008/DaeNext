use super::*;
use tokio::sync::oneshot;

#[tokio::test(flavor = "current_thread")]
async fn xhttp_udp_download_progresses_while_packet_up_completion_is_pending() {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .uri("https://xhttp.test/download")
        .body(())
        .unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let (body_release_tx, body_release_rx) = oneshot::channel();
    let (download_read_tx, download_read_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut server = h2::server::handshake(server_io).await.unwrap();
        let (_request, mut response) = server.accept().await.unwrap().unwrap();
        let response_task = tokio::spawn(async move {
            let mut body = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            body_release_rx.await.unwrap();
            body.send_data(Bytes::from_static(b"\0\0\0\x04pong"), true)
                .unwrap();
        });
        tokio::pin!(response_task);
        loop {
            tokio::select! {
                result = &mut response_task => {
                    result.unwrap();
                    break;
                }
                accepted = server.accept() => {
                    assert!(accepted.is_none(), "unexpected extra xHTTP UDP download request");
                }
            }
        }
        tokio::pin!(download_read_rx);
        loop {
            tokio::select! {
                result = &mut download_read_rx => {
                    result.unwrap();
                    break;
                }
                accepted = server.accept() => {
                    assert!(accepted.is_none(), "unexpected extra xHTTP UDP download request");
                }
            }
        }
    });
    let response = response.await.unwrap();

    let (completion_tx, completion_rx) = oneshot::channel::<Result<(), String>>();
    let pipeline = XhttpPacketUpPipeline::for_test(2);
    pipeline.push_test_completion(Box::pin(async move {
        completion_rx
            .await
            .map_err(|_| "test packet-up completion sender dropped".to_owned())?
    }));
    let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let mut session = VlessXhttpH2UdpSession {
        packet_pipeline: Some(pipeline),
        download: Some(XhttpDownloadClient::H2 {
            recv: response.into_body(),
            _keepalive_sender: Some(sender),
            connection_task: Some(connection_task),
            xmux_lease: None,
        }),
        ..VlessXhttpH2UdpSession::default()
    };
    session
        .fixed_target
        .bind(target, "VLESS xHTTP UDP session")
        .unwrap();

    body_release_tx.send(()).unwrap();
    let mut response = time::timeout(Duration::from_secs(1), session.wait_response())
        .await
        .expect("pending packet-up completion blocked xHTTP UDP download")
        .unwrap()
        .unwrap();
    let expectation = response.fixed_target_expectation(target);
    assert_eq!(
        response
            .take_fixed_target_payload(expectation)
            .into_payload()
            .unwrap(),
        b"pong"
    );
    download_read_tx.send(()).unwrap();
    assert!(session.packet_pipeline.as_ref().unwrap().has_in_flight());

    completion_tx.send(Ok(())).unwrap();
    let _ = time::timeout(Duration::from_secs(1), session.poll_response())
        .await
        .expect("xHTTP UDP completion reclaim blocked");
    assert!(!session.packet_pipeline.as_ref().unwrap().has_in_flight());
    time::timeout(Duration::from_secs(1), session.shutdown())
        .await
        .expect("xHTTP UDP shutdown blocked");
    time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("xHTTP UDP fixture server did not stop")
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn xhttp_udp_packet_up_completion_error_is_terminal() {
    let pipeline = XhttpPacketUpPipeline::for_test(2);
    pipeline.push_test_completion(Box::pin(async { Err("packet-up failed".to_owned()) }));
    let mut session = VlessXhttpH2UdpSession {
        packet_pipeline: Some(pipeline),
        ..VlessXhttpH2UdpSession::default()
    };

    assert_eq!(
        session.poll_response().await.unwrap_err(),
        "packet-up failed"
    );
}
