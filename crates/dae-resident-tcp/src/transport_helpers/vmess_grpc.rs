use super::*;
pub async fn relay_tcp_over_vmess_grpc_h2(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    send_stream: &mut h2::SendStream<Bytes>,
    response: &mut GrpcH2Response,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let grpc_mode = response.grpc_mode();
    let mut upload_codec = session.upload;
    let mut vmess_response = VmessAeadResponseBuffer::new(session.request);
    let (progress, activity) = resident_duplex_progress();
    if stats.client_to_direct != 0 {
        progress.record_upload(stats.client_to_direct);
    }
    if stats.direct_to_client != 0 {
        progress.record_download(stats.direct_to_client);
    }
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut inbound_buf = Box::new([0_u8; VMESS_AEAD_TCP_UPLOAD_BUFFER_SIZE]);
        loop {
            let read = match inbound_read
                .read(upload_codec.chunk_payload_buffer(inbound_buf.as_mut()))
                .await
            {
                Ok(0) => {
                    send_h2_data(send_stream, Bytes::new(), true).await?;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    send_h2_data(send_stream, Bytes::new(), true).await?;
                    return Ok(());
                }
                Err(err) => {
                    return Err(format!("read inbound TCP for VMess gRPC relay: {err}"));
                }
            };
            let wire_len = upload_codec
                .seal_chunk_in_place(inbound_buf.as_mut(), read)
                .map_err(|err| format!("encode VMess gRPC upload chunk: {err}"))?;
            send_grpc_data(send_stream, &inbound_buf[..wire_len], false, grpc_mode).await?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut response_buf = GrpcHunkReadBuffer::with_mode(grpc_mode);
        loop {
            let Some(bytes) = response.next_data().await? else {
                if !response_buf.is_empty() {
                    return Err("VMess gRPC response stream ended with partial hunk".to_owned());
                }
                if !vmess_response.response_header_received() {
                    return Err("VMess gRPC closed before the response header".to_owned());
                }
                let _ = inbound_write.shutdown().await;
                return Ok(());
            };
            response_buf.extend_from_slice(&bytes);
            while let Some(payload) = response_buf.next_payload()? {
                vmess_response.extend_from_slice(payload)?;
                while let Some(plain) = vmess_response.next_chunk()? {
                    if plain.is_empty() {
                        continue;
                    }
                    inbound_write
                        .write_all(plain)
                        .await
                        .map_err(|err| format!("write VMess gRPC response to inbound: {err}"))?;
                    download_progress.record_download(plain.len());
                    metrics.add_download(plain.len());
                }
            }
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident VMess gRPC relay idle timeout",
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use dae_outbound::shared_transport::grpc_hunk_frame;

    const TEST_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const TEST_TARGET: &str = "example.com:443";
    const RESPONSE_PAYLOAD: &[u8] = b"response while the upload window is blocked";

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_grpc_upload_window_does_not_block_vmess_download() {
        const INITIAL_WINDOW_BYTES: u32 = 8 * 1024;
        const UPLOAD_BYTES: usize = 256 * 1024;

        let session =
            dae_outbound::vmess::aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[])
                .unwrap();
        let request = session.request.clone();
        let initial_request = session.first_write.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (blocked_upload_seen, blocked_upload_observed) = tokio::sync::oneshot::channel();

        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(INITIAL_WINDOW_BYTES)
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let (http_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut body = http_request.into_body();
            tokio::spawn(async move {
                let first = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(first.len()).unwrap();

                let blocked_chunk = body.data().await.unwrap().unwrap();
                assert!(!blocked_chunk.is_empty());
                let _ = blocked_upload_seen.send(());

                let response = http::Response::builder()
                    .status(200)
                    .version(http::Version::HTTP_2)
                    .body(())
                    .unwrap();
                let mut response_stream = respond.send_response(response, false).unwrap();
                let vmess_response =
                    dae_outbound::vmess::aead_tcp_response_packet(&request, RESPONSE_PAYLOAD)
                        .unwrap();
                response_stream
                    .send_data(
                        Bytes::from(grpc_hunk_frame(&vmess_response).unwrap()),
                        false,
                    )
                    .unwrap();

                std::future::pending::<()>().await;
            });
            while connection.accept().await.is_some() {}
        });

        let request = http::Request::builder()
            .method(http::Method::POST)
            .version(http::Version::HTTP_2)
            .uri("https://grpc.fixture.invalid/GunService/Tun")
            .body(())
            .unwrap();
        let (mut send_stream, mut response, connection_task) =
            open_grpc_h2_stream_on_io(client_io, request, &initial_request)
                .await
                .unwrap();
        let (mut inbound, application) = tokio::io::duplex(64 * 1024);
        let (mut application_read, mut application_write) = tokio::io::split(application);
        let stop = ResidentStopSignal::shared();
        let application_stop = Arc::clone(&stop);
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_grpc_h2(
            &mut inbound,
            &mut send_stream,
            &mut response,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
        );
        let application = async move {
            let upload = tokio::spawn(async move {
                application_write.write_all(&vec![0x5a; UPLOAD_BYTES]).await
            });
            time::timeout(Duration::from_secs(1), blocked_upload_observed)
                .await
                .expect("VMess gRPC fixture did not fill the upload window")
                .expect("VMess gRPC fixture dropped the upload observation");

            let mut response = vec![0_u8; RESPONSE_PAYLOAD.len()];
            time::timeout(
                Duration::from_secs(1),
                application_read.read_exact(&mut response),
            )
            .await
            .expect("VMess gRPC download stalled behind the blocked upload window")
            .unwrap();
            assert_eq!(response, RESPONSE_PAYLOAD);

            application_stop.store(true, Ordering::Release);
            upload.abort();
            let _ = upload.await;
        };

        let (relay, ()) = tokio::join!(relay, application);
        let stats = relay.unwrap();
        assert_eq!(stats.direct_to_client, RESPONSE_PAYLOAD.len());

        connection_task.abort();
        let _ = connection_task.await;
        server_task.abort();
        let _ = server_task.await;
    }
}
