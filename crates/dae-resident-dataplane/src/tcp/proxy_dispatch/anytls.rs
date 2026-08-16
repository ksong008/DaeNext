use super::*;
use bytes::BytesMut;
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_anytls_tls_tcp_connection_async(
    inbound: &mut TokioTcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    selection: TcpProxySelection,
    stop: SharedResidentStopSignal,
    sniff: &mut TcpSniffReport,
    metrics: &ResidentDataplaneMetrics,
    owner_registry: Option<&AnyTlsOwnerRegistryHandle>,
    owner_deadline: Option<dae_runtime_control::AbsoluteDeadline>,
) -> Result<Value, String> {
    let owner_registry = owner_registry.ok_or_else(|| {
        "AnyTLS generation transport owner is unavailable for TCP execution".to_owned()
    })?;
    let owner_deadline = owner_deadline.unwrap_or_else(|| {
        dae_runtime_control::AbsoluteDeadline::from_now(Instant::now(), RESIDENT_CONNECT_TIMEOUT)
    });
    let mut logical = owner_registry
        .acquire(
            selection.proxy.clone(),
            selection.route.dial_target.clone(),
            owner_deadline,
        )
        .await?;
    let tls_underlay = logical.tls_underlay();
    let sid = logical.sid();
    let physical_instance = logical.physical_instance_id();
    let physical_reused = logical.reused();
    let initial_payload = sniff.take_payload();
    let initial_payload_len = initial_payload.len();
    if initial_payload_len != 0 {
        logical
            .write_all(&initial_payload)
            .await
            .map_err(|error| format!("write AnyTLS initial logical payload: {error}"))?;
        metrics.add_upload(initial_payload_len);
    }
    drop(initial_payload);

    match relay_tcp_over_anytls_async(inbound, &mut logical, stop, metrics).await {
        Ok(mut stats) => {
            stats.client_to_direct += initial_payload_len;
            let mut event = generic_proxy_tcp_finished_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "anytls",
                &stats,
                "async-proxy-frame-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_anytls_owner_event_fields(&mut event, sid, physical_instance, physical_reused);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-frame-tls",
                "anytls",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
        Err(err) => {
            let mut event = generic_proxy_tcp_failed_event(
                peer,
                original_dst,
                &selection,
                sniff,
                "anytls",
                &err,
                "async-proxy-frame-tls",
            );
            event["tls_underlay"] = json!(tls_underlay);
            append_anytls_owner_event_fields(&mut event, sid, physical_instance, physical_reused);
            append_proxy_tcp_execution_fields(
                &mut event,
                "async-proxy-frame-tls",
                "anytls",
                Some(tls_underlay),
                None,
            );
            Ok(event)
        }
    }
}

fn append_anytls_owner_event_fields(
    event: &mut Value,
    sid: u32,
    physical_instance: u64,
    physical_reused: bool,
) {
    event["anytlsSid"] = json!(sid);
    event["anytlsPhysicalInstance"] = json!(physical_instance);
    event["anytlsPhysicalReused"] = json!(physical_reused);
    event["anytlsMode"] = json!("bounded-idle-reuse");
}

pub(crate) async fn relay_tcp_over_anytls_async(
    inbound: &mut (impl AsyncRead + AsyncWrite + Unpin + Send),
    logical: &mut AnyTlsLogicalStreamLease,
    stop: SharedResidentStopSignal,
    metrics: &ResidentDataplaneMetrics,
) -> Result<DirectTcpRelayStats, String> {
    let (progress, activity) = resident_duplex_progress();
    let (inbound_read, inbound_write) = tokio::io::split(&mut *inbound);
    let (logical_read, logical_write) = tokio::io::split(&mut *logical);
    let upload_progress = progress.clone();
    let upload = async move {
        let mut inbound_read = inbound_read;
        let mut logical_write = logical_write;
        let mut buffer = [0_u8; RESIDENT_ANYTLS_RELAY_BUFFER_SIZE];
        loop {
            let read = match inbound_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = logical_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    let _ = logical_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(format!("read inbound TCP for AnyTLS relay: {err}")),
            };
            logical_write
                .write_all(&buffer[..read])
                .await
                .map_err(|error| {
                    format!("write client payload to AnyTLS logical stream: {error}")
                })?;
            upload_progress.record_upload(read);
            metrics.add_upload(read);
        }
    };
    let download_progress = progress.clone();
    let download = async move {
        let mut inbound_write = inbound_write;
        let mut logical_read = logical_read;
        let mut buffer = [0_u8; RESIDENT_ANYTLS_RELAY_BUFFER_SIZE];
        loop {
            let read = match logical_read.read(&mut buffer).await {
                Ok(0) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Ok(read) => read,
                Err(err) if is_graceful_stream_close_error(&err) => {
                    let _ = inbound_write.shutdown().await;
                    return Ok(());
                }
                Err(err) => return Err(format!("read AnyTLS logical response: {err}")),
            };
            if let Err(err) = inbound_write.write_all(&buffer[..read]).await {
                if is_graceful_stream_close_error(&err) {
                    return Ok(());
                }
                return Err(format!("write AnyTLS payload to client: {err}"));
            }
            download_progress.record_download(read);
            metrics.add_download(read);
        }
    };
    run_resident_duplex_relay(
        Box::pin(upload),
        Box::pin(download),
        stop,
        &progress,
        activity,
        "resident AnyTLS relay idle timeout",
        Some(ANYTLS_LOCAL_CLOSE_DRAIN_TIMEOUT),
    )
    .await
}

#[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
const ANYTLS_FRAME_READ_CHUNK_SIZE: usize = 32 * 1024;

pub(crate) struct AnyTlsFrameReader {
    #[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
    buffered: BytesMut,
}

impl Default for AnyTlsFrameReader {
    fn default() -> Self {
        Self {
            #[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
            buffered: BytesMut::with_capacity(ANYTLS_FRAME_READ_CHUNK_SIZE),
        }
    }
}

impl AnyTlsFrameReader {
    pub(crate) async fn read_frame(
        &mut self,
        client: &mut (impl AsyncRead + Unpin),
    ) -> Result<AnyTlsFrame, String> {
        let mut data = BytesMut::new();
        let (cmd, sid) = self.read_into(client, &mut data).await?;
        Ok(AnyTlsFrame {
            cmd,
            sid,
            data: data.to_vec(),
        })
    }

    /// Read one frame while retaining plaintext already returned by the TLS
    /// engine. Small AnyTLS frames commonly arrive in one TLS record; keeping
    /// that record buffered avoids a separate SSL read for every 7-byte header.
    pub(crate) async fn read_into(
        &mut self,
        client: &mut (impl AsyncRead + Unpin),
        data: &mut BytesMut,
    ) -> Result<(u8, u32), String> {
        #[cfg(feature = "test-anytls-legacy-frame-reader")]
        {
            return read_anytls_frame_into_legacy(client, data).await;
        }

        #[cfg(not(feature = "test-anytls-legacy-frame-reader"))]
        loop {
            if self.buffered.len() >= anytls_contract::HEADER_OVERHEAD_SIZE {
                let len = u16::from_be_bytes([self.buffered[5], self.buffered[6]]) as usize;
                let frame_len = anytls_contract::HEADER_OVERHEAD_SIZE + len;
                if self.buffered.len() >= frame_len {
                    let frame = self.buffered.split_to(frame_len);
                    data.clear();
                    data.reserve(len);
                    data.extend_from_slice(&frame[anytls_contract::HEADER_OVERHEAD_SIZE..]);
                    return Ok((
                        frame[0],
                        u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]),
                    ));
                }
            }

            let needed = if self.buffered.len() >= anytls_contract::HEADER_OVERHEAD_SIZE {
                let len = u16::from_be_bytes([self.buffered[5], self.buffered[6]]) as usize;
                (anytls_contract::HEADER_OVERHEAD_SIZE + len) - self.buffered.len()
            } else {
                ANYTLS_FRAME_READ_CHUNK_SIZE
            };
            let read_limit = needed.clamp(1, ANYTLS_FRAME_READ_CHUNK_SIZE);
            self.buffered.reserve(read_limit);
            let mut limited = client.take(read_limit as u64);
            let read = time::timeout(
                RESIDENT_TCP_IDLE_TIMEOUT,
                limited.read_buf(&mut self.buffered),
            )
            .await
            .map_err(|_| "read AnyTLS frame: timeout".to_owned())?
            .map_err(|err| format!("read AnyTLS frame: {err}"))?;
            if read == 0 {
                return Err("read AnyTLS frame: early eof".to_owned());
            }
        }
    }

    #[cfg(all(test, not(feature = "test-anytls-legacy-frame-reader")))]
    pub(crate) fn buffered_len(&self) -> usize {
        self.buffered.len()
    }
}

#[cfg(feature = "test-anytls-legacy-frame-reader")]
async fn read_anytls_frame_into_legacy(
    client: &mut (impl AsyncRead + Unpin),
    data: &mut BytesMut,
) -> Result<(u8, u32), String> {
    let mut header = [0_u8; anytls_contract::HEADER_OVERHEAD_SIZE];
    read_anytls_exact_legacy(client, &mut header, "read AnyTLS frame header").await?;
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    data.clear();
    data.reserve(len);
    let mut limited = client.take(len as u64);
    while data.len() < len {
        let read = time::timeout(RESIDENT_TCP_IDLE_TIMEOUT, limited.read_buf(data))
            .await
            .map_err(|_| "read AnyTLS frame data: timeout".to_owned())?
            .map_err(|err| format!("read AnyTLS frame data: {err}"))?;
        if read == 0 {
            return Err("read AnyTLS frame data: early eof".to_owned());
        }
    }
    Ok((
        header[0],
        u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
    ))
}

#[cfg(feature = "test-anytls-legacy-frame-reader")]
async fn read_anytls_exact_legacy(
    client: &mut (impl AsyncRead + Unpin),
    buffer: &mut [u8],
    label: &str,
) -> Result<(), String> {
    let mut offset = 0;
    while offset < buffer.len() {
        let read = time::timeout(
            RESIDENT_TCP_IDLE_TIMEOUT,
            client.read(&mut buffer[offset..]),
        )
        .await
        .map_err(|_| format!("{label}: timeout"))?
        .map_err(|err| format!("{label}: {err}"))?;
        if read == 0 {
            return Err(format!("{label}: early eof"));
        }
        offset += read;
    }
    Ok(())
}
