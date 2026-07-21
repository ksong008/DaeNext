use super::*;

pub(super) trait VmessRelayTransport {
    fn label(&self) -> &'static str;

    async fn read_payload(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;

    async fn write_payload(&mut self, payload: &[u8]) -> Result<(), String>;

    async fn shutdown(&mut self);
}

pub(super) struct VmessRawTransport<'a, S> {
    stream: &'a mut S,
    label: &'static str,
}

impl<'a, S> VmessRawTransport<'a, S> {
    pub(super) fn new(stream: &'a mut S, label: &'static str) -> Self {
        Self { stream, label }
    }
}

impl<S> VmessRelayTransport for VmessRawTransport<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn label(&self) -> &'static str {
        self.label
    }

    async fn read_payload(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf).await
    }

    async fn write_payload(&mut self, payload: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(payload)
            .await
            .map_err(|err| format!("write {} upload chunk: {err}", self.label))?;
        self.stream
            .flush()
            .await
            .map_err(|err| format!("flush {} upload chunk: {err}", self.label))
    }

    async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

pub(super) struct VmessWebSocketTransport<'a, S> {
    stream: &'a mut S,
    state: AsyncWebSocketPayloadState,
    label: &'static str,
}

impl<'a, S> VmessWebSocketTransport<'a, S> {
    pub(super) fn new(stream: &'a mut S, label: &'static str) -> Self {
        Self {
            stream,
            state: AsyncWebSocketPayloadState::default(),
            label,
        }
    }
}

impl<S> VmessRelayTransport for VmessWebSocketTransport<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn label(&self) -> &'static str {
        self.label
    }

    async fn read_payload(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut reader = AsyncWebSocketPayloadReader::new(self.stream, &mut self.state);
        reader.read(buf).await
    }

    async fn write_payload(&mut self, payload: &[u8]) -> Result<(), String> {
        write_websocket_binary_frame_to_async_stream(
            self.stream,
            payload,
            "write VMess WebSocket upload frame",
        )
        .await?;
        self.stream
            .flush()
            .await
            .map_err(|err| format!("flush {} upload frame: {err}", self.label))
    }

    async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

pub(super) async fn relay_tcp_over_vmess_transport_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin),
    mut transport: impl VmessRelayTransport,
    stop: SharedResidentStopSignal,
    session: VMessAeadTcpClientSessionStart,
    mut stats: DirectTcpRelayStats,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let label = transport.label();
    let mut upload_codec = session.upload;
    let mut response = VmessAeadResponseBuffer::new(session.request);
    let mut inbound_closed = false;
    let mut inbound_buf = [0_u8; 16 * 1024];
    let mut response_buf = [0_u8; 16 * 1024];
    let mut stop_listener = stop.listener();
    let idle_deadline = resident_relay_idle_deadline(RESIDENT_TCP_IDLE_TIMEOUT);
    let close_drain_deadline =
        resident_relay_idle_deadline(RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);
    tokio::pin!(close_drain_deadline);
    let mut close_drain_active = false;

    loop {
        tokio::select! {
            _ = stop_listener.cancelled() => break,
            inbound_read = inbound.read(&mut inbound_buf), if !inbound_closed => {
                match inbound_read {
                    Ok(0) => {
                        inbound_closed = true;
                        transport.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Ok(read) => {
                        let encrypted = upload_codec
                            .seal_chunk(&inbound_buf[..read])
                            .map_err(|err| format!("encode {label} upload chunk: {err}"))?;
                        transport.write_payload(&encrypted).await?;
                        stats.client_to_direct += read;
                        metrics.add_upload(read);
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                    }
                    Err(err) if is_graceful_stream_close_error(&err) => {
                        inbound_closed = true;
                        transport.shutdown().await;
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        reset_resident_relay_idle_deadline(
                            close_drain_deadline.as_mut(),
                            RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                        );
                        close_drain_active = true;
                    }
                    Err(err) => return Err(format!("read inbound TCP for {label} upload: {err}")),
                }
            }
            response_read = transport.read_payload(&mut response_buf) => {
                match response_read {
                    Ok(0) if response.response_header_received() => break,
                    Ok(0) => return Err(format!("{label} closed before the response header")),
                    Ok(read) => {
                        let chunks = response.push(&response_buf[..read])?;
                        for plain in chunks {
                            if plain.is_empty() {
                                continue;
                            }
                            inbound
                                .write_all(&plain)
                                .await
                                .map_err(|err| format!("write {label} response to inbound: {err}"))?;
                            stats.direct_to_client += plain.len();
                            metrics.add_download(plain.len());
                        }
                        reset_resident_relay_idle_deadline(idle_deadline.as_mut(), RESIDENT_TCP_IDLE_TIMEOUT);
                        if close_drain_active {
                            reset_resident_relay_idle_deadline(
                                close_drain_deadline.as_mut(),
                                RESIDENT_TCP_HALF_CLOSE_DRAIN_IDLE_TIMEOUT,
                            );
                        }
                    }
                    Err(err) => {
                        let message = err.to_string();
                        if response.response_header_received()
                            && is_graceful_vmess_response_message(&message)
                        {
                            break;
                        }
                        return Err(format!("read {label} response: {message}"));
                    }
                }
            }
            _ = &mut close_drain_deadline, if close_drain_active => break,
            _ = &mut idle_deadline => {
                return Err(format!("resident {label} relay idle timeout"));
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const TEST_TARGET: &str = "example.com:443";
    const DELAYED_REQUEST: &[u8] = b"delayed application request";
    const DELAYED_RESPONSE: &[u8] = b"delayed application response";

    #[tokio::test]
    async fn raw_relay_uploads_delayed_first_payload_before_response_header() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let request = session.request.clone();
        let request_header_len = session.first_write.len();
        let (mut inbound, mut application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, mut server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&session.first_write).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
        );
        let server = async move {
            let mut header = vec![0_u8; request_header_len];
            server.read_exact(&mut header).await.unwrap();
            let mut delayed_upload = [0_u8; 1];
            time::timeout(
                Duration::from_secs(1),
                server.read_exact(&mut delayed_upload),
            )
            .await
            .expect("VMess relay must upload application data before a response header")
            .unwrap();
            let response =
                dae_outbound::vmess::aead_tcp_response_packet(&request, DELAYED_RESPONSE).unwrap();
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
        };
        let application = async move {
            time::sleep(Duration::from_millis(20)).await;
            application.write_all(DELAYED_REQUEST).await.unwrap();
            application.shutdown().await.unwrap();
            let mut response = vec![0_u8; DELAYED_RESPONSE.len()];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, DELAYED_RESPONSE);
        };

        let (relay, (), ()) = tokio::join!(relay, server, application);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, DELAYED_REQUEST.len());
        assert_eq!(stats.direct_to_client, DELAYED_RESPONSE.len());
    }

    #[tokio::test]
    async fn websocket_relay_uploads_delayed_first_payload_before_response_header() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let request = session.request.clone();
        let first_frame =
            dae_outbound::shared_transport::websocket_client_binary_frame_with_random_mask(
                &session.first_write,
            )
            .unwrap();
        let first_frame_len = first_frame.len();
        let (mut inbound, mut application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, mut server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&first_frame).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_websocket_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
        );
        let server = async move {
            let mut header_frame = vec![0_u8; first_frame_len];
            server.read_exact(&mut header_frame).await.unwrap();
            let mut delayed_upload_frame = [0_u8; 1];
            time::timeout(
                Duration::from_secs(1),
                server.read_exact(&mut delayed_upload_frame),
            )
            .await
            .expect("VMess WebSocket relay must upload before a response header")
            .unwrap();
            let response =
                dae_outbound::vmess::aead_tcp_response_packet(&request, DELAYED_RESPONSE).unwrap();
            let response_frame =
                dae_outbound::shared_transport::websocket_server_binary_frame(&response).unwrap();
            server.write_all(&response_frame).await.unwrap();
            server.shutdown().await.unwrap();
        };
        let application = async move {
            time::sleep(Duration::from_millis(20)).await;
            application.write_all(DELAYED_REQUEST).await.unwrap();
            application.shutdown().await.unwrap();
            let mut response = vec![0_u8; DELAYED_RESPONSE.len()];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, DELAYED_RESPONSE);
        };

        let (relay, (), ()) = tokio::join!(relay, server, application);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, DELAYED_REQUEST.len());
        assert_eq!(stats.direct_to_client, DELAYED_RESPONSE.len());
    }

    #[tokio::test]
    async fn websocket_relay_answers_ping_while_waiting_for_response_payload() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let request = session.request.clone();
        let first_frame =
            dae_outbound::shared_transport::websocket_client_binary_frame_with_random_mask(
                &session.first_write,
            )
            .unwrap();
        let first_frame_len = first_frame.len();
        let (mut inbound, mut application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, mut server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&first_frame).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_websocket_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
        );
        let server = async move {
            let mut header_frame = vec![0_u8; first_frame_len];
            server.read_exact(&mut header_frame).await.unwrap();

            let ping_payload = b"keepalive";
            let mut ping = vec![0x89, ping_payload.len() as u8];
            ping.extend_from_slice(ping_payload);
            server.write_all(&ping).await.unwrap();

            let mut pong = vec![0_u8; 2 + 4 + ping_payload.len()];
            time::timeout(Duration::from_secs(1), server.read_exact(&mut pong))
                .await
                .expect("VMess WebSocket relay must answer a server ping")
                .unwrap();
            assert_eq!(pong[0] & 0x0f, 0x0a);
            assert_ne!(pong[1] & 0x80, 0);

            let response =
                dae_outbound::vmess::aead_tcp_response_packet(&request, DELAYED_RESPONSE).unwrap();
            let response_frame =
                dae_outbound::shared_transport::websocket_server_binary_frame(&response).unwrap();
            server.write_all(&response_frame).await.unwrap();
            server.shutdown().await.unwrap();
        };
        let application = async move {
            let mut response = vec![0_u8; DELAYED_RESPONSE.len()];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, DELAYED_RESPONSE);
        };

        let (relay, (), ()) = tokio::join!(relay, server, application);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, 0);
        assert_eq!(stats.direct_to_client, DELAYED_RESPONSE.len());
    }

    #[tokio::test]
    async fn raw_relay_stop_cancels_wait_before_response_header() {
        let session = aead_tcp_client_session_start(TEST_UUID, TEST_TARGET, &[]).unwrap();
        let (mut inbound, _application) = tokio::io::duplex(64 * 1024);
        let (mut proxy, _server) = tokio::io::duplex(64 * 1024);
        proxy.write_all(&session.first_write).await.unwrap();
        let stop = ResidentStopSignal::shared();
        let relay_stop = Arc::clone(&stop);
        let metrics = ResidentDataplaneMetrics::default();

        let relay = relay_tcp_over_vmess_aead_async(
            &mut inbound,
            &mut proxy,
            stop,
            session,
            DirectTcpRelayStats::default(),
            &metrics,
        );
        let cancel = async move {
            time::sleep(Duration::from_millis(20)).await;
            relay_stop.store(true, Ordering::Relaxed);
        };

        let (relay, ()) = tokio::join!(relay, cancel);
        let stats = relay.unwrap();
        assert_eq!(stats.client_to_direct, 0);
        assert_eq!(stats.direct_to_client, 0);
    }
}
