use super::*;
use dae_outbound_stream::vless::VlessEncryptedStream;
use tokio::io::AsyncWriteExt;

async fn write_vless_encrypted_xhttp_bytes(
    stream: &mut VlessEncryptedStream<SpawnedLogicalStream>,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        stream
            .write_all(payload)
            .await
            .map_err(|err| format!("{label}: {err}"))?;
        stream
            .flush()
            .await
            .map_err(|err| format!("flush {label}: {err}"))
    })
    .await
    .map_err(|_| format!("{label} timeout"))?
}

#[derive(Default)]
pub(in crate::udp) struct VlessXudpStreamSession {
    client: Option<AsyncResidentTlsClient>,
    encrypted: Option<VlessEncryptedStream<AsyncResidentTlsClient>>,
    key: Option<[u8; 16]>,
    uuid_sent: bool,
    response_header_seen: bool,
    tls_underlay: Option<&'static str>,
    response_unpadder: Option<VisionUnpadder>,
    response_plaintext: Vec<u8>,
    response_xudp_payload: Vec<u8>,
    fixed_target: UdpSessionFixedTarget,
}

impl VlessXudpStreamSession {
    pub(super) async fn exchange(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if binding.execution().protocol != ResidentProtocolShape::VlessVision {
            return Err(
                "VLESS Vision XUDP stream executor requires an official Vision flow; other admitted VLESS UDP shapes use their own executor"
                    .to_owned(),
            );
        }
        let proxy = binding.plan();
        self.fixed_target
            .bind(original_dst, "VLESS Vision XUDP stream")?;
        let key = match self.key {
            Some(key) => key,
            None => {
                let key = proxy.vless_key()?;
                self.key = Some(key);
                key
            }
        };
        // An encrypted session owns the physical TLS/Reality stream in
        // `encrypted` rather than `client`.  Check both branches so every
        // subsequent UDP packet reuses the same VLESS Encryption handshake
        // and record counters instead of renegotiating a new stream.
        if self.client.is_none() && self.encrypted.is_none() {
            let frame = xudp_new_frame(original_dst, payload)?;
            let mut client =
                open_async_resident_tls_client_with_binding(binding, proxy.mptcp).await?;
            self.tls_underlay = Some(async_resident_tls_underlay_name(&client));
            let mut request =
                packet::request_header(&key, &proxy.flow, "tcp", XUDP_MUX_TARGET, true, &[])
                    .map_err(|err| format!("build VLESS Vision XUDP mux request header: {err}"))?;
            request.extend_from_slice(&vision_padding_block(
                &frame,
                VISION_COMMAND_CONTINUE,
                key,
                &mut self.uuid_sent,
                false,
            ));
            if let Some(encryption) = proxy.vless_encryption()? {
                let mut encrypted = VlessEncryptedStream::handshake(client, encryption)
                    .await
                    .map_err(|err| format!("VLESS Encryption XUDP handshake: {err}"))?;
                write_vless_xudp_encrypted_bytes(
                    &mut encrypted,
                    &request,
                    "write VLESS encrypted XUDP session first packet",
                )
                .await?;
                self.encrypted = Some(encrypted);
            } else {
                write_async_tls_plain_all(
                    &mut client,
                    &request,
                    "write VLESS XUDP session first packet",
                )
                .await?;
                self.client = Some(client);
            }
        } else {
            let frame = xudp_keep_frame(payload)?;
            let block = vision_padding_block(
                &frame,
                VISION_COMMAND_CONTINUE,
                key,
                &mut self.uuid_sent,
                false,
            );
            if let Some(encrypted) = self.encrypted.as_mut() {
                write_vless_xudp_encrypted_bytes(
                    encrypted,
                    &block,
                    "write VLESS encrypted XUDP session packet",
                )
                .await?;
            } else {
                let client = self
                    .client
                    .as_mut()
                    .ok_or_else(|| "VLESS XUDP client is not initialized".to_owned())?;
                write_async_tls_plain_all(client, &block, "write VLESS XUDP session packet")
                    .await?;
            }
            if let Some(response) = self.poll_response().await? {
                return Ok(response);
            }
            return Ok(self.pending_response_result());
        }
        if let Some(response) = self.poll_response().await? {
            Ok(response)
        } else {
            Ok(self.pending_response_result())
        }
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::ReadyOnly).await
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::Wait).await
    }

    async fn read_response(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        if self.client.is_none() && self.encrypted.is_none() && mode.waits_for_readiness() {
            return std::future::pending().await;
        }
        let mut buf = [0_u8; 2048];
        let read = if let Some(encrypted) = self.encrypted.as_mut() {
            read_udp_stream_once(
                encrypted,
                &mut buf,
                mode,
                "read VLESS encrypted XUDP session plaintext",
            )
            .await?
        } else if let Some(client) = self.client.as_mut() {
            read_udp_stream_once(client, &mut buf, mode, "read VLESS XUDP session plaintext")
                .await?
        } else {
            return Ok(None);
        };
        match read {
            None => Ok(None),
            Some(read) => {
                self.response_plaintext.extend_from_slice(&buf[..read]);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
        }
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        let key = match self.key {
            Some(key) => key,
            None => return Ok(None),
        };
        loop {
            if let Some((payload, consumed)) =
                parse_xudp_response_frame(&self.response_xudp_payload)?
            {
                self.response_xudp_payload.drain(..consumed);
                return Ok(Some(payload));
            }
            if !self.response_header_seen {
                if self.response_plaintext.len() < 2 {
                    return Ok(None);
                }
                if self.response_plaintext[0] != VLESS_RESPONSE_VERSION {
                    return Err(format!(
                        "unexpected VLESS response version: {}",
                        self.response_plaintext[0]
                    ));
                }
                let header_len = 2 + self.response_plaintext[1] as usize;
                if self.response_plaintext.len() < header_len {
                    return Ok(None);
                }
                self.response_plaintext.drain(..header_len);
                self.response_header_seen = true;
                self.response_unpadder = Some(VisionUnpadder::new(key));
                continue;
            }
            if self.response_plaintext.is_empty() {
                return Ok(None);
            }
            let unpadder = self
                .response_unpadder
                .get_or_insert_with(|| VisionUnpadder::new(key));
            let payload = unpadder.consume(&self.response_plaintext)?;
            self.response_plaintext.clear();
            self.response_xudp_payload.extend(payload);
        }
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        UdpExchangeResult::new(payload, "vless-xudp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused")
            .with_session_fixed_target(self.fixed_target)
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("vless-xudp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused")
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(encrypted) = self.encrypted.as_mut() {
            let _ = encrypted.shutdown().await;
        }
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.client.take();
        self.encrypted.take();
        self.fixed_target.clear();
    }
}

async fn write_vless_xudp_encrypted_bytes(
    stream: &mut VlessEncryptedStream<AsyncResidentTlsClient>,
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, async {
        stream
            .write_all(payload)
            .await
            .map_err(|err| format!("{label}: {err}"))?;
        stream
            .flush()
            .await
            .map_err(|err| format!("flush {label}: {err}"))
    })
    .await
    .map_err(|_| format!("{label} timeout"))?
}

#[derive(Default)]
pub(in crate::udp) struct VlessXhttpH2UdpSession {
    packet_upload: Option<XhttpUploadClient>,
    packet_pipeline: Option<XhttpPacketUpPipeline>,
    stream_upload: Option<XhttpStreamUploadClient>,
    download: Option<XhttpDownloadClient>,
    encrypted: Option<VlessEncryptedStream<SpawnedLogicalStream>>,
    session_id: Option<String>,
    seq: u64,
    response_header_seen: bool,
    response_plaintext: Vec<u8>,
    upload_underlay: Option<&'static str>,
    upload_http_version: Option<ResidentXhttpHttpVersion>,
    xhttp_mode: Option<ResidentXhttpMode>,
    fixed_target: UdpSessionFixedTarget,
}

impl VlessXhttpH2UdpSession {
    pub(super) async fn exchange(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if binding.execution().protocol != ResidentProtocolShape::VlessStandard {
            return Err(
                "VLESS xHTTP UDP uses the standard VLESS UDP-over-stream command; flow must be empty"
                    .to_owned(),
            );
        }
        let proxy = binding.plan();
        self.fixed_target
            .bind(original_dst, "VLESS xHTTP UDP session")?;
        let key = proxy.vless_key()?;
        let request = if self.seq == 0 {
            packet::first_write_bytes(
                &key,
                &proxy.flow,
                "udp",
                &original_dst.to_string(),
                false,
                payload,
            )
            .map_err(|err| format!("build VLESS xHTTP UDP first packet: {err}"))?
        } else {
            vless_udp_length_frame(payload)?
        };
        let request = Bytes::from(request);
        if self.is_open() {
            self.send_packet(request).await?;
        } else {
            self.open_with_initial_packet(binding, request).await?;
        }
        if let Some(response) = self.poll_response().await? {
            Ok(response)
        } else {
            Ok(self.pending_response_result())
        }
    }

    fn is_open(&self) -> bool {
        self.encrypted.is_some()
            || (self.download.is_some()
                && (self.packet_upload.is_some() || self.stream_upload.is_some()))
    }

    async fn open_with_initial_packet(
        &mut self,
        binding: &ResidentProxyBinding,
        initial_packet: Bytes,
    ) -> Result<(), String> {
        let proxy = binding.plan();
        let encryption = proxy.vless_encryption()?;
        match proxy.xhttp_mode {
            ResidentXhttpMode::PacketUp => {
                let parts = open_xhttp_packet_up_parts(binding, proxy.mptcp).await?;
                let upload_underlay = parts.upload_underlay;
                let upload_http_version = parts.upload_http_version;
                self.upload_underlay = Some(upload_underlay);
                self.upload_http_version = Some(upload_http_version);
                self.xhttp_mode = Some(ResidentXhttpMode::PacketUp);
                self.reset_response_state();
                if let Some(encryption) = encryption {
                    let logical = spawn_xhttp_packet_up_payload_stream(parts);
                    let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                        .await
                        .map_err(|err| format!("VLESS Encryption xHTTP UDP handshake: {err}"))?;
                    write_vless_encrypted_xhttp_bytes(
                        &mut encrypted,
                        &initial_packet,
                        "write VLESS encrypted xHTTP UDP first packet",
                    )
                    .await?;
                    self.encrypted = Some(encrypted);
                    self.seq = 1;
                    Ok(())
                } else {
                    let XhttpPacketUpParts {
                        session_id,
                        upload,
                        download,
                        ..
                    } = parts;
                    self.packet_pipeline = Some(XhttpPacketUpPipeline::for_upload(&upload));
                    self.packet_upload = Some(upload);
                    self.download = Some(download);
                    self.session_id = Some(session_id);
                    self.send_packet(initial_packet).await
                }
            }
            ResidentXhttpMode::StreamUp | ResidentXhttpMode::StreamOne => {
                if let Some(encryption) = encryption {
                    let parts = open_xhttp_stream_parts(binding, proxy.mptcp, Bytes::new()).await?;
                    let upload_underlay = parts.upload_underlay;
                    let upload_http_version = parts.upload_http_version;
                    let logical = spawn_xhttp_stream_payload_stream(parts);
                    let mut encrypted = VlessEncryptedStream::handshake(logical, encryption)
                        .await
                        .map_err(|err| format!("VLESS Encryption xHTTP UDP handshake: {err}"))?;
                    write_vless_encrypted_xhttp_bytes(
                        &mut encrypted,
                        &initial_packet,
                        "write VLESS encrypted xHTTP UDP first packet",
                    )
                    .await?;
                    self.encrypted = Some(encrypted);
                    self.upload_underlay = Some(upload_underlay);
                    self.upload_http_version = Some(upload_http_version);
                    self.xhttp_mode = Some(proxy.xhttp_mode);
                    self.reset_response_state();
                    self.seq = 1;
                    Ok(())
                } else {
                    let XhttpStreamParts {
                        session_id,
                        upload,
                        download,
                        upload_underlay,
                        upload_http_version,
                        ..
                    } = open_xhttp_stream_parts(binding, proxy.mptcp, initial_packet).await?;
                    self.stream_upload = Some(upload);
                    self.download = Some(download);
                    self.session_id = session_id;
                    self.upload_underlay = Some(upload_underlay);
                    self.upload_http_version = Some(upload_http_version);
                    self.xhttp_mode = Some(proxy.xhttp_mode);
                    self.reset_response_state();
                    self.seq = 1;
                    Ok(())
                }
            }
        }
    }

    fn reset_response_state(&mut self) {
        self.seq = 0;
        self.response_header_seen = false;
        self.response_plaintext.clear();
    }

    async fn send_packet(&mut self, payload: Bytes) -> Result<(), String> {
        if let Some(encrypted) = self.encrypted.as_mut() {
            write_vless_encrypted_xhttp_bytes(
                encrypted,
                &payload,
                "write VLESS encrypted xHTTP UDP packet",
            )
            .await?;
            self.seq = self.seq.saturating_add(1);
            return Ok(());
        } else if let Some(upload) = self.packet_upload.as_mut() {
            let session_id = self
                .session_id
                .as_deref()
                .ok_or_else(|| "VLESS xHTTP UDP session id is not initialized".to_owned())?;
            let pipeline = self.packet_pipeline.as_mut().ok_or_else(|| {
                "VLESS xHTTP UDP packet-up pipeline is not initialized".to_owned()
            })?;
            pipeline
                .send(upload, session_id, &mut self.seq, payload)
                .await?;
            return Ok(());
        } else if let Some(upload) = self.stream_upload.as_mut() {
            send_xhttp_stream_data(upload, payload, false).await?;
        } else {
            return Err("VLESS xHTTP UDP upload client is not initialized".to_owned());
        }
        self.seq = self.seq.saturating_add(1);
        Ok(())
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::ReadyOnly).await
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.read_response(UdpStreamReadMode::Wait).await
    }

    async fn read_response(
        &mut self,
        mode: UdpStreamReadMode,
    ) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(pipeline) = self.packet_pipeline.as_mut() {
            pipeline.poll_ready()?;
        }
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        if self.encrypted.is_some() {
            let mut buf = [0_u8; 8192];
            let stream = self
                .encrypted
                .as_mut()
                .ok_or_else(|| "VLESS encrypted xHTTP UDP stream disappeared".to_owned())?;
            let read = read_udp_stream_once(
                stream,
                &mut buf,
                mode,
                "read VLESS encrypted xHTTP UDP response",
            )
            .await?;
            if let Some(read) = read {
                self.response_plaintext.extend_from_slice(&buf[..read]);
                return self
                    .try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)));
            }
            return Ok(None);
        }
        if self.download.is_none() && mode.waits_for_readiness() {
            return std::future::pending().await;
        }
        let data = if mode.waits_for_readiness() {
            loop {
                let completion_in_flight = self
                    .packet_pipeline
                    .as_ref()
                    .is_some_and(XhttpPacketUpPipeline::has_in_flight);
                if !completion_in_flight {
                    let Some(download) = self.download.as_mut() else {
                        return std::future::pending().await;
                    };
                    break read_xhttp_download_data(download).await?;
                }
                let (pipeline, download) = (&mut self.packet_pipeline, &mut self.download);
                let pipeline = pipeline
                    .as_mut()
                    .ok_or_else(|| "VLESS xHTTP UDP packet-up pipeline disappeared".to_owned())?;
                let Some(download) = download.as_mut() else {
                    pipeline.wait_one().await?;
                    continue;
                };
                let data = tokio::select! {
                    completion = pipeline.wait_one() => {
                        completion?;
                        None
                    }
                    data = read_xhttp_download_data(download) => Some(data),
                };
                if let Some(data) = data {
                    break data?;
                }
            }
        } else {
            let Some(download) = self.download.as_mut() else {
                return Ok(None);
            };
            poll_xhttp_download_data(download).await?
        };
        match data {
            Some(bytes) => {
                self.response_plaintext.extend_from_slice(&bytes);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
            None if mode.waits_for_readiness() => {
                Err("VLESS xHTTP UDP download stream closed".to_owned())
            }
            None => Ok(None),
        }
    }

    pub(super) async fn shutdown(&mut self) {
        if let Some(mut encrypted) = self.encrypted.take() {
            let _ = encrypted.shutdown().await;
        }
        self.packet_pipeline.take();
        if let Some(download) = self.download.take() {
            close_xhttp_download_client(download).await;
        }
        if let Some(upload) = self.packet_upload.take() {
            close_xhttp_upload_client(upload).await;
        }
        if let Some(upload) = self.stream_upload.take() {
            close_xhttp_stream_upload_client(upload).await;
        }
        self.session_id = None;
        self.fixed_target.clear();
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        if !self.response_header_seen {
            if self.response_plaintext.len() < 2 {
                return Ok(None);
            }
            if self.response_plaintext[0] != VLESS_RESPONSE_VERSION {
                return Err(format!(
                    "unexpected VLESS xHTTP UDP response version: {}",
                    self.response_plaintext[0]
                ));
            }
            let header_len = 2 + self.response_plaintext[1] as usize;
            if self.response_plaintext.len() < header_len {
                return Ok(None);
            }
            self.response_plaintext.drain(..header_len);
            self.response_header_seen = true;
        }
        if self.response_plaintext.len() < 2 {
            return Ok(None);
        }
        let payload_len =
            u16::from_be_bytes([self.response_plaintext[0], self.response_plaintext[1]]) as usize;
        if self.response_plaintext.len() < 2 + payload_len {
            return Ok(None);
        }
        self.response_plaintext.drain(..2);
        Ok(Some(self.response_plaintext.drain(..payload_len).collect()))
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        let result = if self.upload_http_version() == ResidentXhttpHttpVersion::H3 {
            UdpExchangeResult::new(payload, "quic-udp-stream-packet")
                .with_session_executor(self.session_executor_label())
                .with_underlay_reuse(self.underlay_reuse_label())
                .with_quic_underlay("quinn-h3")
        } else {
            UdpExchangeResult::new(payload, "tls-udp-over-tcp")
                .with_session_executor(self.session_executor_label())
                .with_underlay_reuse(self.underlay_reuse_label())
                .with_tls_underlay(self.upload_underlay.unwrap_or("standard-tls"))
        };
        result.with_session_fixed_target(self.fixed_target)
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        if self.upload_http_version() == ResidentXhttpHttpVersion::H3 {
            UdpExchangeResult::pending_response("quic-udp-stream-packet")
                .with_session_executor(self.session_executor_label())
                .with_underlay_reuse(self.underlay_reuse_label())
                .with_quic_underlay("quinn-h3")
        } else {
            UdpExchangeResult::pending_response("tls-udp-over-tcp")
                .with_session_executor(self.session_executor_label())
                .with_underlay_reuse(self.underlay_reuse_label())
                .with_tls_underlay(self.upload_underlay.unwrap_or("standard-tls"))
        }
    }

    fn upload_http_version(&self) -> ResidentXhttpHttpVersion {
        self.upload_http_version
            .unwrap_or(ResidentXhttpHttpVersion::H2)
    }

    fn session_executor_label(&self) -> &'static str {
        match (self.upload_http_version(), self.xhttp_mode()) {
            (ResidentXhttpHttpVersion::H1, ResidentXhttpMode::PacketUp) => {
                "tokio-xhttp-h1-packet-up"
            }
            (ResidentXhttpHttpVersion::H1, ResidentXhttpMode::StreamUp) => {
                "tokio-xhttp-h1-stream-up"
            }
            (ResidentXhttpHttpVersion::H1, ResidentXhttpMode::StreamOne) => {
                "tokio-xhttp-h1-stream-one"
            }
            (ResidentXhttpHttpVersion::H2, ResidentXhttpMode::PacketUp) => {
                "tokio-xhttp-h2-packet-up"
            }
            (ResidentXhttpHttpVersion::H2, ResidentXhttpMode::StreamUp) => {
                "tokio-xhttp-h2-stream-up"
            }
            (ResidentXhttpHttpVersion::H2, ResidentXhttpMode::StreamOne) => {
                "tokio-xhttp-h2-stream-one"
            }
            (ResidentXhttpHttpVersion::H3, ResidentXhttpMode::PacketUp) => {
                "tokio-xhttp-h3-packet-up"
            }
            (ResidentXhttpHttpVersion::H3, ResidentXhttpMode::StreamUp) => {
                "tokio-xhttp-h3-stream-up"
            }
            (ResidentXhttpHttpVersion::H3, ResidentXhttpMode::StreamOne) => {
                "tokio-xhttp-h3-stream-one"
            }
        }
    }

    fn xhttp_mode(&self) -> ResidentXhttpMode {
        self.xhttp_mode.unwrap_or(ResidentXhttpMode::PacketUp)
    }

    fn underlay_reuse_label(&self) -> &'static str {
        match (self.upload_http_version(), self.xhttp_mode()) {
            (ResidentXhttpHttpVersion::H1, ResidentXhttpMode::PacketUp) => {
                "tls-h1-download-stream-with-fresh-packet-up-connections"
            }
            (ResidentXhttpHttpVersion::H1, ResidentXhttpMode::StreamUp)
            | (ResidentXhttpHttpVersion::H1, ResidentXhttpMode::StreamOne) => {
                "tls-h1-stream-reused"
            }
            (ResidentXhttpHttpVersion::H2, ResidentXhttpMode::PacketUp) => "tls-h2-session-reused",
            (ResidentXhttpHttpVersion::H2, ResidentXhttpMode::StreamUp)
            | (ResidentXhttpHttpVersion::H2, ResidentXhttpMode::StreamOne) => {
                "tls-h2-stream-reused"
            }
            (ResidentXhttpHttpVersion::H3, ResidentXhttpMode::PacketUp) => "quic-h3-session-reused",
            (ResidentXhttpHttpVersion::H3, ResidentXhttpMode::StreamUp)
            | (ResidentXhttpHttpVersion::H3, ResidentXhttpMode::StreamOne) => {
                "quic-h3-stream-reused"
            }
        }
    }
}

#[derive(Default)]
pub(in crate::udp) struct VlessXhttpH3UdpSession {
    inner: VlessXhttpH2UdpSession,
}

impl VlessXhttpH3UdpSession {
    pub(super) async fn exchange(
        &mut self,
        binding: &ResidentProxyBinding,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.inner.exchange(binding, original_dst, payload).await
    }

    pub(super) async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.inner.poll_response().await
    }

    pub(super) async fn wait_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.inner.wait_response().await
    }

    pub(super) async fn shutdown(&mut self) {
        self.inner.shutdown().await;
    }
}

pub fn vless_udp_length_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > u16::MAX as usize {
        return Err(format!(
            "VLESS UDP payload too large: {} bytes",
            payload.len()
        ));
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod fixed_target_tests {
    use super::*;

    fn assert_response_is_bound(mut response: UdpExchangeResult, target: SocketAddr) {
        let expectation = response.fixed_target_expectation(target);
        assert_eq!(
            response.take_fixed_target_payload(expectation).validation(),
            UdpFixedTargetValidation::Validated
        );
    }

    #[test]
    fn xudp_and_xhttp_responses_use_their_bound_targets() {
        let target: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let mut xudp = VlessXudpStreamSession::default();
        xudp.fixed_target
            .bind(target, "VLESS Vision XUDP stream")
            .unwrap();
        assert_response_is_bound(xudp.response_result(b"xudp".to_vec()), target);

        let mut xhttp = VlessXhttpH2UdpSession::default();
        xhttp
            .fixed_target
            .bind(target, "VLESS xHTTP UDP session")
            .unwrap();
        assert_response_is_bound(xhttp.response_result(b"xhttp".to_vec()), target);
    }
}

#[cfg(test)]
#[path = "vless/packet_up_tests.rs"]
mod packet_up_tests;
