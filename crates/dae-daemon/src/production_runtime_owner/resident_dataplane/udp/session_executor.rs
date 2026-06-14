use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

use super::*;

pub(super) enum UdpSessionExecutor {
    Dns,
    ShadowsocksAead(ShadowsocksAeadDatagramSession),
    Shadowsocks2022(Shadowsocks2022DatagramSession),
    Socks5(Socks5UdpAssociateSession),
    VlessVision(VlessXudpStreamSession),
    VlessXhttpH2(VlessXhttpH2UdpSession),
    VlessXhttpH3(VlessXhttpH3UdpSession),
    Trojan(TrojanUdpStreamSession),
    VmessAead(VmessAeadUdpOverTcpSession),
    AnyTls(AnyTlsPacketStreamSession),
    Hysteria2(Hysteria2QuicDatagramSession),
    Tuic(TuicQuicDatagramSession),
    Juicity(JuicityQuicStreamPacketSession),
    FailClosed { reason: String },
}

mod datagram;
mod dispatch;
mod selection;
use self::datagram::*;

pub(super) struct ShadowsocksAeadDatagramSession {
    cipher: String,
    password: String,
    salt_len: usize,
    relay: DatagramRelay,
}

impl ShadowsocksAeadDatagramSession {
    fn new(cipher: String, password: String, salt_len: usize) -> Self {
        Self {
            cipher,
            password,
            salt_len,
            relay: DatagramRelay::default(),
        }
    }

    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        let mut salt = vec![0_u8; self.salt_len];
        fastrand::fill(&mut salt);
        let request = encode_udp_packet(
            &self.cipher,
            &self.password,
            &salt,
            &original_dst.to_string(),
            payload,
        )
        .map_err(|err| format!("encode Shadowsocks UDP packet: {err}"))?;
        self.relay.send(proxy, &request, "Shadowsocks").await?;
        if let Some(response) = self.poll_response()? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let Some(response) = self.relay.poll_response("Shadowsocks")? else {
            return Ok(None);
        };
        let decoded = decode_shadowsocks_udp_packet(&self.cipher, &self.password, &response)
            .map_err(|err| format!("decode Shadowsocks UDP packet: {err}"))?;
        Ok(Some(
            UdpExchangeResult::new(decoded.payload, "udp-datagram-aead")
                .with_session_executor("tokio-datagram-relay")
                .with_underlay_reuse("udp-socket-reused"),
        ))
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("udp-datagram-aead")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-reused")
    }
}

pub(super) struct Shadowsocks2022DatagramSession {
    cipher: String,
    password: String,
    packet_nonce_len: usize,
    codec: Option<Ss2022UdpCodec>,
    relay: DatagramRelay,
}

impl Shadowsocks2022DatagramSession {
    fn new(cipher: String, password: String, packet_nonce_len: usize) -> Self {
        Self {
            cipher,
            password,
            packet_nonce_len,
            codec: None,
            relay: DatagramRelay::default(),
        }
    }

    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if self.codec.is_none() {
            let mut session_id = [0_u8; 8];
            fastrand::fill(&mut session_id);
            self.codec = Some(
                Ss2022UdpCodec::new(&self.cipher, &self.password, session_id)
                    .map_err(|err| format!("create Shadowsocks 2022 UDP codec: {err}"))?,
            );
        }
        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| "Shadowsocks 2022 UDP codec is not initialized".to_owned())?;
        let mut packet_nonce = vec![0_u8; self.packet_nonce_len];
        if self.packet_nonce_len > 0 {
            fastrand::fill(&mut packet_nonce);
        }
        let request = codec
            .encode_client_packet(
                &original_dst.to_string(),
                payload,
                ss2022_udp_unix_timestamp_now(),
                if self.packet_nonce_len > 0 {
                    Some(packet_nonce.as_slice())
                } else {
                    None
                },
            )
            .map_err(|err| format!("encode Shadowsocks 2022 UDP packet: {err}"))?;
        self.relay
            .send(proxy, &request.wire, "Shadowsocks 2022")
            .await?;
        if let Some(response) = self.poll_response()? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let Some(response) = self.relay.poll_response("Shadowsocks 2022")? else {
            return Ok(None);
        };
        let codec = self
            .codec
            .as_mut()
            .ok_or_else(|| "Shadowsocks 2022 UDP codec is not initialized".to_owned())?;
        let decoded = codec
            .decode_server_packet(&response, ss2022_udp_unix_timestamp_now())
            .map_err(|err| format!("decode Shadowsocks 2022 UDP packet: {err}"))?;
        Ok(Some(
            UdpExchangeResult::new(decoded.payload, "udp-datagram-aead-2022")
                .with_session_executor("tokio-datagram-relay")
                .with_underlay_reuse("udp-socket-and-codec-session-reused"),
        ))
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("udp-datagram-aead-2022")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-and-codec-session-reused")
    }
}

#[derive(Default)]
pub(super) struct Socks5UdpAssociateSession {
    control: Option<tokio::net::TcpStream>,
    relay: Option<tokio::net::UdpSocket>,
    relay_addr: Option<SocketAddr>,
}

impl Socks5UdpAssociateSession {
    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(proxy).await?;
        let relay_addr = self
            .relay_addr
            .ok_or_else(|| "SOCKS5 UDP relay address is not initialized".to_owned())?;
        let relay = self
            .relay
            .as_ref()
            .ok_or_else(|| "SOCKS5 UDP relay socket is not initialized".to_owned())?;
        let request = udp_packet::wrap_target(&original_dst.to_string(), payload)
            .map_err(|err| format!("wrap SOCKS5 UDP packet: {err}"))?;
        relay
            .send_to(&request, relay_addr)
            .await
            .map_err(|err| format!("send SOCKS5 UDP datagram: {err}"))?;
        if let Some(response) = self.poll_response()? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let relay = match self.relay.as_ref() {
            Some(relay) => relay,
            None => return Ok(None),
        };
        let mut response = vec![0_u8; 64 * 1024];
        let (read, _) = match relay.try_recv_from(&mut response) {
            Ok(read) => read,
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(format!("receive SOCKS5 UDP datagram: {err}")),
        };
        response.truncate(read);
        let decoded = udp_packet::unwrap(&response)
            .map_err(|err| format!("unwrap SOCKS5 UDP packet: {err}"))?;
        Ok(Some(
            UdpExchangeResult::new(decoded.payload, "socks5-udp-associate")
                .with_session_executor("tokio-socks5-udp-associate")
                .with_underlay_reuse("tcp-control-and-udp-relay-reused"),
        ))
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("socks5-udp-associate")
            .with_session_executor("tokio-socks5-udp-associate")
            .with_underlay_reuse("tcp-control-and-udp-relay-reused")
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.control.is_some() && self.relay.is_some() && self.relay_addr.is_some() {
            return Ok(());
        }
        let ResidentProxyProtocolPlan::Socks5Tcp { username, password } = &proxy.handler else {
            return Err("SOCKS5 UDP associate executor received a non-SOCKS handler".to_owned());
        };
        let mut control = open_proxy_tcp_stream_async(proxy).await?;
        let bind =
            socks5_udp_associate_control_async(&mut control, "0.0.0.0:0", username, password)
                .await?;
        let relay_addr = socks5_udp_relay_addr_async(proxy, &bind).await?;
        let relay = open_marked_tokio_udp_socket(relay_addr, proxy.mark).await?;
        self.control = Some(control);
        self.relay = Some(relay);
        self.relay_addr = Some(relay_addr);
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct VlessXudpStreamSession {
    client: Option<AsyncResidentTlsClient>,
    key: Option<[u8; 16]>,
    uuid_sent: bool,
    response_header_seen: bool,
    tls_underlay: Option<&'static str>,
    response_unpadder: Option<VisionUnpadder>,
    response_plaintext: Vec<u8>,
    response_xudp_payload: Vec<u8>,
}

impl VlessXudpStreamSession {
    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if proxy.flow != XTLS_RPRX_VISION {
            return Err(
                "VLESS UDP session executor currently admits Vision XUDP only; non-Vision UDP remains fail-closed"
                    .to_owned(),
            );
        }
        let key = match self.key {
            Some(key) => key,
            None => {
                let key = proxy.vless_key()?;
                self.key = Some(key);
                key
            }
        };
        if self.client.is_none() {
            let frame = xudp_new_frame(original_dst, payload)?;
            let mut client = open_async_resident_tls_client(proxy).await?;
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
            write_async_tls_plain_all(
                &mut client,
                &request,
                "write VLESS XUDP session first packet",
            )
            .await?;
            self.client = Some(client);
        } else {
            let frame = xudp_keep_frame(payload)?;
            let block = vision_padding_block(
                &frame,
                VISION_COMMAND_CONTINUE,
                key,
                &mut self.uuid_sent,
                false,
            );
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| "VLESS XUDP client is not initialized".to_owned())?;
            write_async_tls_plain_all(client, &block, "write VLESS XUDP session packet").await?;
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

    async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if self.client.is_none() {
            return Ok(None);
        }
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        let mut buf = [0_u8; 2048];
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "VLESS XUDP client is not initialized".to_owned())?;
        let mut read_buf = ReadBuf::new(&mut buf);
        let read = poll_fn(
            |cx| match Pin::new(&mut *client).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Ready(Ok(None)),
            },
        )
        .await;
        match read {
            Ok(Some(0)) | Ok(None) => Ok(None),
            Ok(Some(read)) => {
                self.response_plaintext.extend_from_slice(&buf[..read]);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(format!("read VLESS XUDP session plaintext: {err}")),
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
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("vless-xudp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused")
    }

    async fn shutdown(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.client.take();
    }
}

#[derive(Default)]
pub(super) struct VlessXhttpH2UdpSession {
    packet_upload: Option<XhttpUploadClient>,
    stream_upload: Option<XhttpStreamUploadClient>,
    download: Option<XhttpDownloadClient>,
    session_id: Option<String>,
    seq: u64,
    response_header_seen: bool,
    response_plaintext: Vec<u8>,
    upload_underlay: Option<&'static str>,
    upload_http_version: Option<ResidentXhttpHttpVersion>,
    xhttp_mode: Option<ResidentXhttpMode>,
}

impl VlessXhttpH2UdpSession {
    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if !proxy.flow.is_empty() {
            return Err(
                "VLESS xHTTP UDP uses the standard VLESS UDP-over-stream command; flow must be empty"
                    .to_owned(),
            );
        }
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
            self.open_with_initial_packet(proxy, request).await?;
        }
        if let Some(response) = self.poll_response().await? {
            Ok(response)
        } else {
            Ok(self.pending_response_result())
        }
    }

    fn is_open(&self) -> bool {
        self.download.is_some() && (self.packet_upload.is_some() || self.stream_upload.is_some())
    }

    async fn open_with_initial_packet(
        &mut self,
        proxy: &ResidentProxyPlan,
        initial_packet: Bytes,
    ) -> Result<(), String> {
        match proxy.xhttp_mode {
            ResidentXhttpMode::PacketUp => {
                let XhttpPacketUpParts {
                    session_id,
                    upload,
                    download,
                    upload_underlay,
                    upload_http_version,
                    ..
                } = open_xhttp_packet_up_parts(proxy, proxy.mark, proxy.mptcp).await?;
                self.packet_upload = Some(upload);
                self.download = Some(download);
                self.session_id = Some(session_id);
                self.upload_underlay = Some(upload_underlay);
                self.upload_http_version = Some(upload_http_version);
                self.xhttp_mode = Some(ResidentXhttpMode::PacketUp);
                self.reset_response_state();
                self.send_packet(initial_packet).await
            }
            ResidentXhttpMode::StreamUp | ResidentXhttpMode::StreamOne => {
                let XhttpStreamParts {
                    session_id,
                    upload,
                    download,
                    upload_underlay,
                    upload_http_version,
                    ..
                } = open_xhttp_stream_parts(proxy, proxy.mark, proxy.mptcp, initial_packet).await?;
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

    fn reset_response_state(&mut self) {
        self.seq = 0;
        self.response_header_seen = false;
        self.response_plaintext.clear();
    }

    async fn send_packet(&mut self, payload: Bytes) -> Result<(), String> {
        if let Some(upload) = self.packet_upload.as_mut() {
            let session_id = self
                .session_id
                .as_deref()
                .ok_or_else(|| "VLESS xHTTP UDP session id is not initialized".to_owned())?;
            send_xhttp_packet_up_request(upload, session_id, self.seq, payload).await?;
        } else if let Some(upload) = self.stream_upload.as_mut() {
            send_xhttp_stream_data(upload, payload, false).await?;
        } else {
            return Err("VLESS xHTTP UDP upload client is not initialized".to_owned());
        }
        self.seq = self.seq.saturating_add(1);
        Ok(())
    }

    async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        let Some(download) = self.download.as_mut() else {
            return Ok(None);
        };
        match poll_xhttp_download_data(download).await? {
            Some(bytes) => {
                self.response_plaintext.extend_from_slice(&bytes);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
            None => Ok(None),
        }
    }

    async fn shutdown(&mut self) {
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
        if self.upload_http_version() == ResidentXhttpHttpVersion::H3 {
            UdpExchangeResult::new(payload, "quic-udp-stream-packet")
                .with_session_executor(self.session_executor_label())
                .with_underlay_reuse(self.underlay_reuse_label())
                .with_quic_underlay("quinn-h3")
        } else {
            UdpExchangeResult::new(payload, "tls-udp-over-tcp")
                .with_session_executor(self.session_executor_label())
                .with_underlay_reuse(self.underlay_reuse_label())
                .with_tls_underlay(self.upload_underlay.unwrap_or("standard-tls"))
        }
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
pub(super) struct VlessXhttpH3UdpSession {
    inner: VlessXhttpH2UdpSession,
}

impl VlessXhttpH3UdpSession {
    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.inner.exchange(proxy, original_dst, payload).await
    }

    async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        self.inner.poll_response().await
    }

    async fn shutdown(&mut self) {
        self.inner.shutdown().await;
    }
}

pub(super) fn vless_udp_length_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
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

pub(super) struct TrojanUdpStreamSession {
    password: String,
    client: Option<AsyncResidentTlsClient>,
    opened: bool,
    tls_underlay: Option<&'static str>,
    response_plaintext: Vec<u8>,
}

impl TrojanUdpStreamSession {
    fn new(password: String) -> Self {
        Self {
            password,
            client: None,
            opened: false,
            tls_underlay: None,
            response_plaintext: Vec::new(),
        }
    }

    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if self.client.is_none() {
            let client = open_async_resident_tls_client(proxy).await?;
            self.tls_underlay = Some(async_resident_tls_underlay_name(&client));
            self.client = Some(client);
        }
        let packet = trojan_packet::udp_packet(&original_dst.to_string(), payload)
            .map_err(|err| format!("build Trojan UDP packet: {err}"))?;
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "Trojan UDP stream client is not initialized".to_owned())?;
        if self.opened {
            write_async_tls_plain_all(client, &packet, "write Trojan UDP session packet").await?;
        } else {
            let request = trojan_packet::tcp_request_header(
                &self.password,
                "udp",
                &original_dst.to_string(),
                &packet,
            )
            .map_err(|err| format!("build Trojan UDP-over-TCP request: {err}"))?;
            write_async_tls_plain_all(client, &request, "write Trojan UDP session first packet")
                .await?;
            self.opened = true;
        }
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if self.client.is_none() {
            return Ok(None);
        }
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        let mut buf = [0_u8; 2048];
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "Trojan UDP stream client is not initialized".to_owned())?;
        let mut read_buf = ReadBuf::new(&mut buf);
        let read = poll_fn(
            |cx| match Pin::new(&mut *client).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Ready(Ok(None)),
            },
        )
        .await;
        match read {
            Ok(Some(0)) | Ok(None) => Ok(None),
            Ok(Some(read)) => {
                self.response_plaintext.extend_from_slice(&buf[..read]);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(format!("read Trojan UDP session plaintext: {err}")),
        }
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some((packet, consumed)) =
            dae_outbound::trojan::decode_udp_packet_prefix(&self.response_plaintext)
                .map_err(|err| format!("decode Trojan UDP session response: {err}"))?
        else {
            return Ok(None);
        };
        self.response_plaintext.drain(..consumed);
        Ok(Some(packet.payload))
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        UdpExchangeResult::new(payload, "tls-udp-over-tcp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused")
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("tls-udp-over-tcp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused")
    }

    async fn shutdown(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.client.take();
    }
}

#[cfg(test)]
mod trojan_udp_stream_tests {
    use super::*;

    #[test]
    fn trojan_udp_stream_session_pops_concatenated_response_packets() {
        let first = trojan_packet::udp_packet("1.2.3.4:443", b"one").unwrap();
        let second = trojan_packet::udp_packet("example.com:53", b"two").unwrap();
        let mut session = TrojanUdpStreamSession::new("password".to_owned());
        session.response_plaintext.extend_from_slice(&first);
        session.response_plaintext.extend_from_slice(&second);

        assert_eq!(
            session.try_pop_response_payload().unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            session.try_pop_response_payload().unwrap(),
            Some(b"two".to_vec())
        );
        assert_eq!(session.try_pop_response_payload().unwrap(), None);
    }

    #[test]
    fn trojan_udp_stream_pending_result_does_not_forward_empty_reply() {
        let session = TrojanUdpStreamSession::new("password".to_owned());
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload.is_empty());
        assert_eq!(pending.execution_label, "tls-udp-over-tcp");
    }
}

#[cfg(test)]
mod datagram_udp_pending_tests {
    use super::*;

    #[test]
    fn shadowsocks_datagram_pending_result_does_not_forward_empty_reply() {
        let session = ShadowsocksAeadDatagramSession::new(
            "aes-128-gcm".to_owned(),
            "password".to_owned(),
            16,
        );
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload.is_empty());
        assert_eq!(pending.execution_label, "udp-datagram-aead");
        assert_eq!(pending.session_executor, Some("tokio-datagram-relay"));
        assert_eq!(pending.underlay_reuse, Some("udp-socket-reused"));
    }

    #[test]
    fn shadowsocks_2022_datagram_pending_result_does_not_forward_empty_reply() {
        let session = Shadowsocks2022DatagramSession::new(
            "2022-blake3-aes-128-gcm".to_owned(),
            "password".to_owned(),
            16,
        );
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload.is_empty());
        assert_eq!(pending.execution_label, "udp-datagram-aead-2022");
        assert_eq!(pending.session_executor, Some("tokio-datagram-relay"));
        assert_eq!(
            pending.underlay_reuse,
            Some("udp-socket-and-codec-session-reused")
        );
    }

    #[test]
    fn socks5_datagram_pending_result_does_not_forward_empty_reply() {
        let session = Socks5UdpAssociateSession::default();
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload.is_empty());
        assert_eq!(pending.execution_label, "socks5-udp-associate");
        assert_eq!(pending.session_executor, Some("tokio-socks5-udp-associate"));
        assert_eq!(
            pending.underlay_reuse,
            Some("tcp-control-and-udp-relay-reused")
        );
    }

    #[test]
    fn quic_datagram_pending_results_do_not_forward_empty_reply() {
        let hysteria2 =
            Hysteria2QuicDatagramSession::new("auth".to_owned(), String::new(), 0, Vec::new())
                .pending_response_result();
        assert!(!hysteria2.reply_forwarded);
        assert!(hysteria2.payload.is_empty());
        assert_eq!(hysteria2.execution_label, "quic-udp-datagram");
        assert_eq!(hysteria2.quic_underlay, Some("quinn-h3"));
        assert_eq!(
            hysteria2.underlay_reuse,
            Some("quic-endpoint-and-connection-reused")
        );

        let tuic = TuicQuicDatagramSession::new(
            "uuid".to_owned(),
            "password".to_owned(),
            Vec::new(),
            true,
        )
        .pending_response_result();
        assert!(!tuic.reply_forwarded);
        assert!(tuic.payload.is_empty());
        assert_eq!(tuic.execution_label, "quic-udp-datagram");
        assert_eq!(tuic.quic_underlay, Some("quinn"));
        assert_eq!(
            tuic.underlay_reuse,
            Some("quic-endpoint-and-connection-reused")
        );
    }
}

#[cfg(test)]
mod anytls_udp_stream_tests {
    use super::*;

    #[test]
    fn anytls_udp_stream_pending_result_does_not_forward_empty_reply() {
        let session = AnyTlsPacketStreamSession::new("auth".to_owned());
        let pending = session.pending_response_result();
        assert!(!pending.reply_forwarded);
        assert!(pending.payload.is_empty());
        assert_eq!(pending.execution_label, "frame-tls-udp-packet-stream");
        assert_eq!(pending.session_executor, Some("tokio-stream-session"));
        assert_eq!(pending.underlay_reuse, Some("tls-frame-stream-reused"));
    }

    #[test]
    fn anytls_udp_stream_pops_concatenated_response_frames() {
        let first = anytls_link::frame(
            anytls_contract::CMD_PSH,
            1,
            &anytls_link::packet_next_write(b"one"),
        );
        let second = anytls_link::frame(
            anytls_contract::CMD_PSH,
            1,
            &anytls_link::packet_next_write(b"two"),
        );
        let mut session = AnyTlsPacketStreamSession::new("auth".to_owned());
        session.response_plaintext.extend_from_slice(&first);
        session.response_plaintext.extend_from_slice(&second);

        assert_eq!(
            session.try_pop_response_payload().unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            session.try_pop_response_payload().unwrap(),
            Some(b"two".to_vec())
        );
        assert_eq!(session.try_pop_response_payload().unwrap(), None);
    }
}

pub(super) struct AnyTlsPacketStreamSession {
    auth: String,
    client: Option<AsyncResidentTlsClient>,
    opened: bool,
    tls_underlay: Option<&'static str>,
    response_plaintext: Vec<u8>,
}

impl AnyTlsPacketStreamSession {
    fn new(auth: String) -> Self {
        Self {
            auth,
            client: None,
            opened: false,
            tls_underlay: None,
            response_plaintext: Vec::new(),
        }
    }

    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        if self.client.is_none() {
            let mut client = open_async_resident_tls_client(proxy).await?;
            self.tls_underlay = Some(async_resident_tls_underlay_name(&client));
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::handshake_auth_bytes(&self.auth),
                "write AnyTLS auth handshake",
            )
            .await?;
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::frame(
                    anytls_contract::CMD_SETTINGS,
                    1,
                    &anytls_link::settings_bytes(),
                ),
                "write AnyTLS settings",
            )
            .await?;
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::frame(anytls_contract::CMD_SYN, 1, &[]),
                "write AnyTLS SYN",
            )
            .await?;
            let stream_target = anytls_link::udp_stream_target(&original_dst.to_string())
                .map_err(|err| format!("build AnyTLS UDP stream target: {err}"))?;
            let stream_target_addr = anytls_link::socks_addr(&stream_target)
                .map_err(|err| format!("build AnyTLS UDP stream address: {err}"))?;
            write_async_tls_plain_all(
                &mut client,
                &anytls_link::frame(anytls_contract::CMD_PSH, 1, &stream_target_addr),
                "write AnyTLS UDP stream target",
            )
            .await?;
            self.client = Some(client);
        }
        let packet = if self.opened {
            anytls_link::packet_next_write(payload)
        } else {
            anytls_link::packet_first_write(&original_dst.to_string(), payload)
                .map_err(|err| format!("build AnyTLS UDP first packet write: {err}"))?
        };
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "AnyTLS packet stream client is not initialized".to_owned())?;
        write_async_tls_plain_all(
            client,
            &anytls_link::frame(anytls_contract::CMD_PSH, 1, &packet),
            "write AnyTLS UDP packet",
        )
        .await?;
        if !self.opened {
            wait_anytls_udp_synack_async(client).await?;
            self.opened = true;
        }
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        if let Some(payload) = self.try_pop_response_payload()? {
            return Ok(Some(self.response_result(payload)));
        }
        let Some(client) = self.client.as_mut() else {
            return Ok(None);
        };
        let mut buf = [0_u8; 2048];
        let mut read_buf = ReadBuf::new(&mut buf);
        let read = poll_fn(
            |cx| match Pin::new(&mut *client).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Ready(Ok(None)),
            },
        )
        .await;
        match read {
            Ok(Some(0)) | Ok(None) => Ok(None),
            Ok(Some(read)) => {
                self.response_plaintext.extend_from_slice(&buf[..read]);
                self.try_pop_response_payload()
                    .map(|payload| payload.map(|payload| self.response_result(payload)))
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(err) => Err(format!("read AnyTLS UDP packet stream plaintext: {err}")),
        }
    }

    fn try_pop_response_payload(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            if self.response_plaintext.len() < anytls_contract::HEADER_OVERHEAD_SIZE {
                return Ok(None);
            }
            let header = &self.response_plaintext[..anytls_contract::HEADER_OVERHEAD_SIZE];
            let cmd = header[0];
            let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let len = u16::from_be_bytes([header[5], header[6]]) as usize;
            let frame_len = anytls_contract::HEADER_OVERHEAD_SIZE + len;
            if self.response_plaintext.len() < frame_len {
                return Ok(None);
            }
            let data =
                self.response_plaintext[anytls_contract::HEADER_OVERHEAD_SIZE..frame_len].to_vec();
            self.response_plaintext.drain(..frame_len);
            if cmd == anytls_contract::CMD_PSH && sid == 1 {
                let packet = dae_outbound::anytls::decode_packet_next_write(&data)
                    .map_err(|err| format!("decode AnyTLS UDP response packet: {err}"))?;
                return Ok(Some(packet.payload));
            }
            if cmd == anytls_contract::CMD_ALERT {
                return Err(format!("AnyTLS UDP alert frame: {len} bytes"));
            }
            if matches!(
                cmd,
                anytls_contract::CMD_WASTE
                    | anytls_contract::CMD_SERVER_SETTINGS
                    | anytls_contract::CMD_UPDATE_PADDING
                    | anytls_contract::CMD_HEART_RESPONSE
            ) {
                continue;
            }
            return Err(format!(
                "unexpected AnyTLS UDP response frame: cmd={cmd} sid={sid} len={len}"
            ));
        }
    }

    fn response_result(&self, payload: Vec<u8>) -> UdpExchangeResult {
        UdpExchangeResult::new(payload, "frame-tls-udp-packet-stream")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-frame-stream-reused")
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("frame-tls-udp-packet-stream")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-frame-stream-reused")
    }

    async fn shutdown(&mut self) {
        if let Some(client) = self.client.as_mut() {
            let _ = write_async_tls_plain_all(
                client,
                &anytls_link::frame(anytls_contract::CMD_FIN, 1, &[]),
                "write AnyTLS UDP FIN",
            )
            .await;
            client.shutdown().await;
        }
        self.client.take();
        self.response_plaintext.clear();
    }
}

pub(super) struct Hysteria2QuicDatagramSession {
    auth: String,
    pin_sha256: String,
    max_rx: u64,
    port_hop_ports: Vec<u16>,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    session_id: u32,
}

impl Hysteria2QuicDatagramSession {
    fn new(auth: String, pin_sha256: String, max_rx: u64, port_hop_ports: Vec<u16>) -> Self {
        Self {
            auth,
            pin_sha256,
            max_rx,
            port_hop_ports,
            endpoint: None,
            connection: None,
            session_id: fastrand::u32(1..=u32::MAX),
        }
    }

    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(proxy).await?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "Hysteria2 QUIC connection is not initialized".to_owned())?;
        let packet_id = fastrand::u16(1..=u16::MAX);
        let request = build_hysteria2_udp_message(
            self.session_id,
            packet_id,
            &original_dst.to_string(),
            payload,
        )?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send Hysteria2 UDP datagram: {err}"))?;
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let connection = match self.connection.as_ref() {
            Some(connection) => connection,
            None => return Ok(None),
        };
        let read = connection.read_datagram();
        tokio::pin!(read);
        let response = poll_fn(|cx| match read.as_mut().poll(cx) {
            Poll::Ready(response) => Poll::Ready(Some(response)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        let Some(response) = response else {
            return Ok(None);
        };
        let response = response.map_err(|err| format!("read Hysteria2 UDP datagram: {err}"))?;
        let parsed = parse_hysteria2_udp_message(&response)?;
        Ok(Some(
            UdpExchangeResult::new(parsed.payload, "quic-udp-datagram")
                .with_quic_underlay("quinn-h3")
                .with_session_executor("tokio-quic-datagram-session")
                .with_underlay_reuse("quic-endpoint-and-connection-reused"),
        ))
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("quic-udp-datagram")
            .with_quic_underlay("quinn-h3")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused")
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.connection.is_some() {
            return Ok(());
        }
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_hysteria2_pinned_client_config(self.pin_sha256.clone())
                .map_err(|err| format!("build Hysteria2 QUIC client config: {err}"))?,
        );
        let remote = resolve_hysteria2_quic_remote_async(proxy, &self.port_hop_ports).await?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect Hysteria2 QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await Hysteria2 QUIC connect: {err}"))?;
        let auth_report =
            authenticate_hysteria2_connection(connection.clone(), &self.auth, self.max_rx)
                .await
                .map_err(|err| format!("authenticate Hysteria2 QUIC connection: {err}"))?;
        if !auth_report.auth_ok || !auth_report.udp_enabled {
            connection.close(0x101_u32.into(), b"resident hysteria2 udp auth failed");
            endpoint.wait_idle().await;
            return Err(format!(
                "Hysteria2 UDP unavailable after auth: status={} udp_enabled={}",
                auth_report.status, auth_report.udp_enabled
            ));
        }
        self.connection = Some(connection);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn shutdown(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"resident hysteria2 udp session done");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.wait_idle().await;
        }
    }
}

pub(super) struct TuicQuicDatagramSession {
    uuid: String,
    password: String,
    alpn: Vec<String>,
    allow_insecure: bool,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    assoc_id: u16,
}

impl TuicQuicDatagramSession {
    fn new(uuid: String, password: String, alpn: Vec<String>, allow_insecure: bool) -> Self {
        Self {
            uuid,
            password,
            alpn,
            allow_insecure,
            endpoint: None,
            connection: None,
            assoc_id: fastrand::u16(1..=u16::MAX),
        }
    }

    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(proxy).await?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "TUIC QUIC connection is not initialized".to_owned())?;
        let packet_id = fastrand::u16(1..=u16::MAX);
        let request =
            build_tuic_packet_frame(self.assoc_id, packet_id, &original_dst.to_string(), payload)?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send TUIC UDP datagram: {err}"))?;
        if let Some(response) = self.poll_response().await? {
            return Ok(response);
        }
        Ok(self.pending_response_result())
    }

    async fn poll_response(&mut self) -> Result<Option<UdpExchangeResult>, String> {
        let connection = match self.connection.as_ref() {
            Some(connection) => connection,
            None => return Ok(None),
        };
        let read = connection.read_datagram();
        tokio::pin!(read);
        let response = poll_fn(|cx| match read.as_mut().poll(cx) {
            Poll::Ready(response) => Poll::Ready(Some(response)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        let Some(response) = response else {
            return Ok(None);
        };
        let response = response.map_err(|err| format!("read TUIC UDP datagram: {err}"))?;
        let parsed = parse_tuic_packet_frame(&response)?;
        Ok(Some(
            UdpExchangeResult::new(parsed.payload, "quic-udp-datagram")
                .with_quic_underlay("quinn")
                .with_session_executor("tokio-quic-datagram-session")
                .with_underlay_reuse("quic-endpoint-and-connection-reused"),
        ))
    }

    fn pending_response_result(&self) -> UdpExchangeResult {
        UdpExchangeResult::pending_response("quic-udp-datagram")
            .with_quic_underlay("quinn")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused")
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.connection.is_some() {
            return Ok(());
        }
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_tuic_runtime_client_config(&self.alpn, self.allow_insecure)
                .map_err(|err| format!("build TUIC QUIC client config: {err}"))?,
        );
        let remote = resolve_proxy_udp_addr_async(proxy).await?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect TUIC QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await TUIC QUIC connect: {err}"))?;
        authenticate_tuic_connection(&connection, &self.uuid, &self.password)
            .await
            .map_err(|err| format!("authenticate TUIC QUIC connection: {err}"))?;
        self.connection = Some(connection);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn shutdown(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"resident tuic udp session done");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.wait_idle().await;
        }
    }
}

pub(super) struct JuicityQuicStreamPacketSession {
    uuid: String,
    password: String,
    allow_insecure: bool,
    pinned_certchain_sha256: String,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    auth_stream: Option<dae_outbound::juicity::JuicityAuthStream>,
}

impl JuicityQuicStreamPacketSession {
    fn new(
        uuid: String,
        password: String,
        allow_insecure: bool,
        pinned_certchain_sha256: String,
    ) -> Self {
        Self {
            uuid,
            password,
            allow_insecure,
            pinned_certchain_sha256,
            endpoint: None,
            connection: None,
            auth_stream: None,
        }
    }

    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<UdpExchangeResult, String> {
        self.ensure_open(proxy).await?;
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| "Juicity QUIC connection is not initialized".to_owned())?;
        let request_frame = seal_stream_packet_frame(&original_dst.to_string(), payload)
            .map_err(|err| format!("build Juicity UDP stream packet: {err}"))?;
        let request =
            build_juicity_stream_packet_request(&original_dst.to_string(), &request_frame.encoded)?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|err| format!("open Juicity UDP stream: {err}"))?;
        send.write_all(&request)
            .await
            .map_err(|err| format!("write Juicity UDP stream packet: {err}"))?;
        send.finish()
            .map_err(|err| format!("finish Juicity UDP stream packet: {err}"))?;
        let response = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            read_juicity_stream_packet_response(&mut recv),
        )
        .await
        .map_err(|_| "read Juicity UDP stream response timeout".to_owned())??;
        let parsed = decode_stream_packet_frame(&response)
            .map_err(|err| format!("decode Juicity UDP stream packet: {err}"))?;
        Ok(
            UdpExchangeResult::new(parsed.payload, "quic-udp-stream-packet")
                .with_quic_underlay("quinn-h3")
                .with_session_executor("tokio-quic-stream-packet-session")
                .with_underlay_reuse("quic-endpoint-connection-and-auth-stream-reused"),
        )
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.connection.is_some() && self.auth_stream.is_some() {
            return Ok(());
        }
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_juicity_runtime_client_config(self.allow_insecure, &self.pinned_certchain_sha256)
                .map_err(|err| format!("build Juicity QUIC client config: {err}"))?,
        );
        let remote = resolve_proxy_udp_addr_async(proxy).await?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect Juicity QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await Juicity QUIC connect: {err}"))?;
        let (_auth_report, auth_stream) =
            authenticate_juicity_connection(&connection, &self.uuid, &self.password)
                .await
                .map_err(|err| format!("authenticate Juicity QUIC connection: {err}"))?;
        self.auth_stream = Some(auth_stream);
        self.connection = Some(connection);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn shutdown(&mut self) {
        if let Some(auth_stream) = self.auth_stream.as_mut() {
            let _ = auth_stream.finish().await;
        }
        self.auth_stream.take();
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"resident juicity udp session done");
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.wait_idle().await;
        }
    }
}

async fn socks5_udp_associate_control_async(
    stream: &mut tokio::net::TcpStream,
    target: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let method = socks5_authenticate_async(stream, username, password).await?;
    let target =
        Socks5Address::parse(target).map_err(|err| format!("parse SOCKS5 target: {err}"))?;
    let request = dae_outbound::socks5::handshake::request(
        dae_outbound::socks5::Socks5Command::UdpAssociate,
        &target,
    )
    .map_err(|err| format!("build SOCKS5 UDP associate request: {err}"))?;
    stream
        .write_all(&request)
        .await
        .map_err(|err| format!("write SOCKS5 UDP associate request: {err}"))?;

    let mut reply_head = [0_u8; 3];
    stream
        .read_exact(&mut reply_head)
        .await
        .map_err(|err| format!("read SOCKS5 UDP associate reply head: {err}"))?;
    let mut reply_bytes = reply_head.to_vec();
    reply_bytes.extend(read_socks5_address_bytes_async(stream).await?);
    let parsed = dae_outbound::socks5::handshake::parse_server_reply(&reply_bytes)
        .map_err(|err| format!("parse SOCKS5 UDP associate reply: {err}"))?;
    if method == dae_outbound::socks5::handshake::AUTH_NO_ACCEPTABLE_METHODS {
        return Err("SOCKS5 UDP associate selected no acceptable auth method".to_owned());
    }
    Ok(parsed.bind.authority())
}

async fn socks5_authenticate_async(
    stream: &mut tokio::net::TcpStream,
    username: &str,
    password: &str,
) -> Result<u8, String> {
    let greeting = dae_outbound::socks5::handshake::greeting(username, password);
    stream
        .write_all(&greeting)
        .await
        .map_err(|err| format!("write SOCKS5 greeting: {err}"))?;
    let mut method_selection = [0_u8; 2];
    stream
        .read_exact(&mut method_selection)
        .await
        .map_err(|err| format!("read SOCKS5 method selection: {err}"))?;
    let method = dae_outbound::socks5::handshake::parse_method_selection(&method_selection)
        .map_err(|err| format!("parse SOCKS5 method selection: {err}"))?;

    if method == dae_outbound::socks5::handshake::AUTH_PASSWORD {
        let auth = dae_outbound::socks5::handshake::username_password_auth(username, password)
            .map_err(|err| format!("build SOCKS5 password auth: {err}"))?;
        stream
            .write_all(&auth)
            .await
            .map_err(|err| format!("write SOCKS5 password auth: {err}"))?;
        let mut auth_reply = [0_u8; 2];
        stream
            .read_exact(&mut auth_reply)
            .await
            .map_err(|err| format!("read SOCKS5 password auth reply: {err}"))?;
        if auth_reply[0] != dae_outbound::socks5::handshake::PASSWORD_AUTH_VERSION
            || auth_reply[1] != 0
        {
            return Err(format!(
                "SOCKS5 password auth rejected: {:02x?}",
                auth_reply
            ));
        }
    }
    Ok(method)
}

async fn read_socks5_address_bytes_async(
    stream: &mut tokio::net::TcpStream,
) -> Result<Vec<u8>, String> {
    let mut atyp = [0_u8; 1];
    stream
        .read_exact(&mut atyp)
        .await
        .map_err(|err| format!("read SOCKS5 address type: {err}"))?;
    let mut out = atyp.to_vec();
    match atyp[0] {
        1 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 IPv4 address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        3 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|err| format!("read SOCKS5 domain length: {err}"))?;
            out.extend_from_slice(&len);
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 domain address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|err| format!("read SOCKS5 IPv6 address: {err}"))?;
            out.extend_from_slice(&rest);
        }
        other => return Err(format!("unsupported SOCKS5 address type: {other}")),
    }
    Ok(out)
}
