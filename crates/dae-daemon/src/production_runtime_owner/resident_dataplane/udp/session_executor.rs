use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

pub(super) enum UdpSessionExecutor {
    Dns,
    ShadowsocksAead(ShadowsocksAeadDatagramSession),
    Shadowsocks2022(Shadowsocks2022DatagramSession),
    Socks5(Socks5UdpAssociateSession),
    VlessVision(VlessXudpStreamSession),
    Trojan(TrojanUdpStreamSession),
    VmessAead(VmessAeadUdpOverTcpSession),
    AnyTls(AnyTlsPacketStreamSession),
    Hysteria2(Hysteria2QuicDatagramSession),
    Tuic(TuicQuicDatagramSession),
    Juicity(JuicityQuicStreamPacketSession),
    FailClosed { reason: String },
}

impl UdpSessionExecutor {
    pub(super) fn new(proxy: &ResidentProxyPlan, original_dst: SocketAddr) -> Self {
        if original_dst.port() == 53 {
            return Self::Dns;
        }
        Self::new_proxy_packet(proxy)
    }

    pub(super) fn new_proxy_packet(proxy: &ResidentProxyPlan) -> Self {
        match &proxy.handler {
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
                cipher,
                password,
                salt_len,
            } => Self::ShadowsocksAead(ShadowsocksAeadDatagramSession::new(
                cipher.clone(),
                password.clone(),
                *salt_len,
            )),
            ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
                cipher,
                password,
                packet_nonce_len,
                ..
            } => Self::Shadowsocks2022(Shadowsocks2022DatagramSession::new(
                cipher.clone(),
                password.clone(),
                *packet_nonce_len,
            )),
            ResidentProxyProtocolPlan::Socks5Tcp { .. } => {
                Self::Socks5(Socks5UdpAssociateSession::default())
            }
            ResidentProxyProtocolPlan::VlessVisionTcpTls { .. } => {
                if matches!(proxy.net.as_str(), "" | "tcp") && proxy.flow == XTLS_RPRX_VISION {
                    Self::VlessVision(VlessXudpStreamSession::default())
                } else if proxy.net == "xhttp" {
                    Self::fail_closed(
                        "VLESS xHTTP UDP remains excluded from the non-xHTTP resident UDP closure",
                    )
                } else {
                    Self::fail_closed(
                        "VLESS wrapped-stream UDP requires a matching packet-over-wrapper executor for this transport and flow combination",
                    )
                }
            }
            ResidentProxyProtocolPlan::TrojanTcpTls { password } => match proxy.net.as_str() {
                "" | "tcp" => Self::Trojan(TrojanUdpStreamSession::new(password.clone())),
                "websocket" | "httpupgrade" | "grpc" => Self::fail_closed(
                    "Trojan wrapped-stream UDP requires a matching packet-over-wrapper executor for this transport",
                ),
                _ => Self::fail_closed(
                    "Trojan UDP requires a supported stream transport before resident UDP can admit this shape",
                ),
            },
            ResidentProxyProtocolPlan::VmessAeadTcp { id } => {
                match (proxy.net.as_str(), proxy.tls.as_str()) {
                    ("" | "tcp", "" | "none") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::plain(id.clone()))
                    }
                    ("websocket", "" | "none") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::websocket_plain(id.clone()))
                    }
                    ("websocket", "tls") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::websocket_tls(id.clone()))
                    }
                    ("httpupgrade", "" | "none") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::httpupgrade_plain(id.clone()))
                    }
                    ("httpupgrade", "tls") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::httpupgrade_tls(id.clone()))
                    }
                    ("grpc", "tls") => {
                        Self::VmessAead(VmessAeadUdpOverTcpSession::grpc_tls(id.clone()))
                    }
                    _ => Self::fail_closed(
                        "VMess UDP wrapper requires a matching packet-over-wrapper executor for this transport and security combination",
                    ),
                }
            }
            ResidentProxyProtocolPlan::AnyTlsTcpTls { auth } => {
                Self::AnyTls(AnyTlsPacketStreamSession::new(auth.clone()))
            }
            ResidentProxyProtocolPlan::Hysteria2QuicTcp {
                auth,
                pin_sha256,
                max_rx,
                port_hop_ports,
            } => Self::Hysteria2(Hysteria2QuicDatagramSession::new(
                auth.clone(),
                pin_sha256.clone(),
                *max_rx,
                port_hop_ports.clone(),
            )),
            ResidentProxyProtocolPlan::TuicQuicTcp {
                uuid,
                password,
                alpn,
                allow_insecure,
            } => Self::Tuic(TuicQuicDatagramSession::new(
                uuid.clone(),
                password.clone(),
                alpn.clone(),
                *allow_insecure,
            )),
            ResidentProxyProtocolPlan::JuicityQuicTcp {
                uuid,
                password,
                allow_insecure,
                pinned_certchain_sha256,
            } => Self::Juicity(JuicityQuicStreamPacketSession::new(
                uuid.clone(),
                password.clone(),
                *allow_insecure,
                pinned_certchain_sha256.clone(),
            )),
            ResidentProxyProtocolPlan::VlessMuxTcpTls { .. } => Self::fail_closed(
                "resident VLESS mux handler does not admit UDP packets; mux row is TCP stream scoped",
            ),
            ResidentProxyProtocolPlan::ShadowsocksSimpleObfsHttpTcp { .. }
            | ResidentProxyProtocolPlan::ShadowsocksSimpleObfsTlsTcp { .. }
            | ResidentProxyProtocolPlan::ShadowsocksV2rayPluginTlsWsTcp { .. }
            | ResidentProxyProtocolPlan::Shadowsocks2022SimpleObfsHttpTcp { .. } => {
                Self::fail_closed(
                    "SIP003 plugin UDP is not part of the required plugin contract; resident UDP keeps plugin UDP policy-closed without alternate execution",
                )
            }
            ResidentProxyProtocolPlan::ShadowsocksRHttpSimpleTcp { .. } => Self::fail_closed(
                "ShadowsocksR legacy UDP requires an SSR protocol and obfs packet executor before resident UDP can admit this shape",
            ),
            ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. } => Self::fail_closed(
                "Trojan inner-encryption UDP requires inner-encrypted packet semantics before resident UDP can admit this shape",
            ),
            ResidentProxyProtocolPlan::HttpProxyTcp { .. } => {
                Self::fail_closed("HTTP CONNECT has no UDP relay semantics in resident dataplane")
            }
        }
    }

    fn fail_closed(reason: &str) -> Self {
        Self::FailClosed {
            reason: reason.to_owned(),
        }
    }

    pub(super) async fn execute(
        &mut self,
        dns: &ResidentDnsPlan,
        proxy: &ResidentProxyPlan,
        original_dst: SocketAddr,
        payload: &[u8],
    ) -> Result<(&'static str, UdpExchangeResult), String> {
        match self {
            Self::Dns => handle_resident_dns_udp_async(dns, original_dst, payload)
                .await
                .map(|response| {
                    (
                        "udp_dns_packet_finished",
                        UdpExchangeResult::new(response, "resident-dns-udp")
                            .with_session_executor("tokio-dns-datagram")
                            .with_underlay_reuse("not-required-independent-datagram"),
                    )
                }),
            Self::ShadowsocksAead(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Shadowsocks2022(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Socks5(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::VlessVision(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Trojan(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::VmessAead(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::AnyTls(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Hysteria2(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Tuic(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::Juicity(session) => session
                .exchange(proxy, original_dst, payload)
                .await
                .map(|response| ("udp_packet_finished", response)),
            Self::FailClosed { reason } => Err(format!(
                "unsupported_udp_handler: {reason}; handler={}; protocol={}; policy-closed without alternate execution",
                resident_udp_handler_name(&proxy.handler),
                proxy.protocol,
            )),
        }
    }

    pub(super) async fn shutdown(&mut self) {
        match self {
            Self::Hysteria2(session) => session.shutdown().await,
            Self::Tuic(session) => session.shutdown().await,
            Self::Juicity(session) => session.shutdown().await,
            Self::VmessAead(session) => session.shutdown().await,
            Self::Trojan(session) => session.shutdown().await,
            Self::AnyTls(session) => session.shutdown().await,
            Self::VlessVision(session) => session.shutdown().await,
            Self::Dns
            | Self::ShadowsocksAead(_)
            | Self::Shadowsocks2022(_)
            | Self::Socks5(_)
            | Self::FailClosed { .. } => {}
        }
    }
}

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
        let response = self.relay.exchange(proxy, &request, "Shadowsocks").await?;
        let decoded = decode_shadowsocks_udp_packet(&self.cipher, &self.password, &response)
            .map_err(|err| format!("decode Shadowsocks UDP packet: {err}"))?;
        Ok(UdpExchangeResult::new(decoded.payload, "udp-datagram-aead")
            .with_session_executor("tokio-datagram-relay")
            .with_underlay_reuse("udp-socket-reused"))
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
        let response = self
            .relay
            .exchange(proxy, &request.wire, "Shadowsocks 2022")
            .await?;
        let decoded = codec
            .decode_server_packet(&response, ss2022_udp_unix_timestamp_now())
            .map_err(|err| format!("decode Shadowsocks 2022 UDP packet: {err}"))?;
        Ok(UdpExchangeResult::new(
            decoded.payload,
            "udp-datagram-aead-2022",
        ))
        .map(|response| {
            response
                .with_session_executor("tokio-datagram-relay")
                .with_underlay_reuse("udp-socket-and-codec-session-reused")
        })
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
        let mut response = vec![0_u8; 64 * 1024];
        let (read, _) = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            relay.recv_from(&mut response),
        )
        .await
        .map_err(|_| "receive SOCKS5 UDP datagram timeout".to_owned())?
        .map_err(|err| format!("receive SOCKS5 UDP datagram: {err}"))?;
        response.truncate(read);
        let decoded = udp_packet::unwrap(&response)
            .map_err(|err| format!("unwrap SOCKS5 UDP packet: {err}"))?;
        Ok(UdpExchangeResult::new(
            decoded.payload,
            "socks5-udp-associate",
        ))
        .map(|response| {
            response
                .with_session_executor("tokio-socks5-udp-associate")
                .with_underlay_reuse("tcp-control-and-udp-relay-reused")
        })
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.control.is_some() && self.relay.is_some() && self.relay_addr.is_some() {
            return Ok(());
        }
        let ResidentProxyProtocolPlan::Socks5Tcp { username, password } = &proxy.handler else {
            return Err("SOCKS5 UDP associate executor received a non-SOCKS handler".to_owned());
        };
        let mut control = open_proxy_tcp_stream_async(proxy.clone()).await?;
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
        let frame = xudp_frame(original_dst, payload)?;
        if self.client.is_none() {
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
        }
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| "VLESS XUDP client is not initialized".to_owned())?;
        let payload = if self.response_header_seen {
            read_vless_xudp_session_response(client, key).await?
        } else {
            let payload = read_vless_udp_response_async(client, &proxy.flow, key).await?;
            self.response_header_seen = true;
            payload
        };
        Ok(UdpExchangeResult::new(payload, "vless-xudp")
            .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
            .with_session_executor("tokio-stream-session")
            .with_underlay_reuse("tls-stream-reused"))
    }

    async fn shutdown(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.client.take();
    }
}

async fn read_vless_xudp_session_response(
    client: &mut AsyncResidentTlsClient,
    user_uuid: [u8; 16],
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let mut plaintext = Vec::new();
    let mut buf = [0_u8; 2048];
    loop {
        let mut unpadder = VisionUnpadder::new(user_uuid);
        let payload = unpadder.consume(&plaintext)?;
        if !payload.is_empty() || matches!(unpadder.state, VisionUnpadState::Raw) {
            if let Some(packet) = parse_xudp_response_payload(&payload)? {
                return Ok(packet);
            }
        }
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err("VLESS XUDP session response timeout".to_owned());
        }
        match time::timeout(RESIDENT_IDLE_SLEEP, client.read_plain(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(read)) => plaintext.extend_from_slice(&buf[..read]),
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Ok(Err(err)) => return Err(format!("read VLESS XUDP session plaintext: {err}")),
            Err(_) => {}
        }
    }
}

async fn read_vless_udp_response_async(
    client: &mut AsyncResidentTlsClient,
    flow: &str,
    user_uuid: [u8; 16],
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let mut plaintext = Vec::new();
    let mut buf = [0_u8; 2048];
    loop {
        if let Some(payload) = parse_vless_udp_response(&plaintext, flow, user_uuid)? {
            return Ok(payload);
        }
        if started.elapsed() > RESIDENT_UDP_RESPONSE_TIMEOUT {
            return Err("VLESS UDP response timeout".to_owned());
        }
        match time::timeout(RESIDENT_IDLE_SLEEP, client.read_plain(&mut buf)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(read)) => plaintext.extend_from_slice(&buf[..read]),
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Ok(Err(err)) => return Err(format!("read VLESS UDP plaintext: {err}")),
            Err(_) => {}
        }
    }
}

pub(super) struct TrojanUdpStreamSession {
    password: String,
    client: Option<AsyncResidentTlsClient>,
    opened: bool,
    tls_underlay: Option<&'static str>,
}

impl TrojanUdpStreamSession {
    fn new(password: String) -> Self {
        Self {
            password,
            client: None,
            opened: false,
            tls_underlay: None,
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
        read_async_tls_plain_until(client, "read Trojan UDP session response", |buffer| {
            decode_trojan_udp_packet(buffer).map(|packet| packet.payload)
        })
        .await
        .map(|payload| {
            UdpExchangeResult::new(payload, "tls-udp-over-tcp")
                .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
                .with_session_executor("tokio-stream-session")
                .with_underlay_reuse("tls-stream-reused")
        })
    }

    async fn shutdown(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.shutdown().await;
        }
        self.client.take();
    }
}

pub(super) struct AnyTlsPacketStreamSession {
    auth: String,
    client: Option<AsyncResidentTlsClient>,
    opened: bool,
    tls_underlay: Option<&'static str>,
}

impl AnyTlsPacketStreamSession {
    fn new(auth: String) -> Self {
        Self {
            auth,
            client: None,
            opened: false,
            tls_underlay: None,
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
        let response = read_anytls_udp_payload_async(client).await?;
        Ok(
            UdpExchangeResult::new(response, "frame-tls-udp-packet-stream")
                .with_tls_underlay(self.tls_underlay.unwrap_or("standard-tls"))
                .with_session_executor("tokio-stream-session")
                .with_underlay_reuse("tls-frame-stream-reused"),
        )
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
        let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| "read Hysteria2 UDP datagram timeout".to_owned())?
            .map_err(|err| format!("read Hysteria2 UDP datagram: {err}"))?;
        let parsed = parse_hysteria2_udp_message(&response)?;
        Ok(UdpExchangeResult::new(parsed.payload, "quic-udp-datagram")
            .with_quic_underlay("quinn-h3")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused"))
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
        let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| "read TUIC UDP datagram timeout".to_owned())?
            .map_err(|err| format!("read TUIC UDP datagram: {err}"))?;
        let parsed = parse_tuic_packet_frame(&response)?;
        Ok(UdpExchangeResult::new(parsed.payload, "quic-udp-datagram")
            .with_quic_underlay("quinn")
            .with_session_executor("tokio-quic-datagram-session")
            .with_underlay_reuse("quic-endpoint-and-connection-reused"))
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

#[derive(Default)]
struct DatagramRelay {
    socket: Option<tokio::net::UdpSocket>,
    remote: Option<SocketAddr>,
}

impl DatagramRelay {
    async fn exchange(
        &mut self,
        proxy: &ResidentProxyPlan,
        request: &[u8],
        label: &str,
    ) -> Result<Vec<u8>, String> {
        self.ensure_open(proxy).await?;
        let remote = self
            .remote
            .ok_or_else(|| format!("{label} UDP relay remote is not initialized"))?;
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| format!("{label} UDP relay socket is not initialized"))?;
        socket
            .send_to(request, remote)
            .await
            .map_err(|err| format!("send {label} UDP datagram: {err}"))?;
        let mut response = vec![0_u8; 64 * 1024];
        let (read, _) = time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            socket.recv_from(&mut response),
        )
        .await
        .map_err(|_| format!("receive {label} UDP datagram timeout"))?
        .map_err(|err| format!("receive {label} UDP datagram: {err}"))?;
        response.truncate(read);
        Ok(response)
    }

    async fn ensure_open(&mut self, proxy: &ResidentProxyPlan) -> Result<(), String> {
        if self.socket.is_some() && self.remote.is_some() {
            return Ok(());
        }
        let remote = resolve_proxy_udp_socket_addr_async(proxy).await?;
        self.socket = Some(open_marked_tokio_udp_socket(remote, proxy.mark).await?);
        self.remote = Some(remote);
        Ok(())
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

async fn open_marked_tokio_udp_socket(
    remote: SocketAddr,
    mark: u32,
) -> Result<tokio::net::UdpSocket, String> {
    let bind = match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).map_err(|err| format!("bind UDP relay socket: {err}"))?;
    if mark != 0 {
        set_socket_mark(socket.as_raw_fd(), mark)
            .map_err(|err| format!("set UDP relay SO_MARK {mark}: {err}"))?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("set UDP relay socket nonblocking: {err}"))?;
    tokio::net::UdpSocket::from_std(socket)
        .map_err(|err| format!("adopt UDP relay socket into tokio: {err}"))
}
