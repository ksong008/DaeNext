use super::*;
pub(super) fn exchange_vless_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
) -> Result<UdpExchangeResult, String> {
    let key = proxy.vless_key()?;
    let mut client = open_vless_tls_client(proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    let request = build_vless_udp_request(proxy, original_dst, payload)?;
    client.queue_plain(&request, "queue VLESS UDP request")?;
    flush_tls_writes_for_udp(&mut client)?;
    read_vless_udp_response(&mut client, &proxy.flow, key).map(|payload| {
        UdpExchangeResult::new(payload, "vless-xudp").with_tls_underlay(tls_underlay)
    })
}

pub(super) fn exchange_shadowsocks_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    cipher: &str,
    password: &str,
    salt_len: usize,
) -> Result<UdpExchangeResult, String> {
    let mut salt = vec![0_u8; salt_len];
    fastrand::fill(&mut salt);
    let request = encode_udp_packet(cipher, password, &salt, &original_dst.to_string(), payload)
        .map_err(|err| format!("encode Shadowsocks UDP packet: {err}"))?;
    let response = exchange_udp_datagram_with_proxy(proxy, &request, "Shadowsocks")?;
    let decoded = decode_shadowsocks_udp_packet(cipher, password, &response)
        .map_err(|err| format!("decode Shadowsocks UDP packet: {err}"))?;
    Ok(UdpExchangeResult::new(decoded.payload, "udp-datagram-aead"))
}

pub(super) fn exchange_shadowsocks_2022_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    cipher: &str,
    password: &str,
    packet_nonce_len: usize,
) -> Result<UdpExchangeResult, String> {
    let mut session_id = [0_u8; 8];
    fastrand::fill(&mut session_id);
    let mut codec = Ss2022UdpCodec::new(cipher, password, session_id)
        .map_err(|err| format!("create Shadowsocks 2022 UDP codec: {err}"))?;
    let mut packet_nonce = vec![0_u8; packet_nonce_len];
    if packet_nonce_len > 0 {
        fastrand::fill(&mut packet_nonce);
    }
    let request = codec
        .encode_client_packet(
            &original_dst.to_string(),
            payload,
            ss2022_udp_unix_timestamp_now(),
            if packet_nonce_len > 0 {
                Some(packet_nonce.as_slice())
            } else {
                None
            },
        )
        .map_err(|err| format!("encode Shadowsocks 2022 UDP packet: {err}"))?;
    let response = exchange_udp_datagram_with_proxy(proxy, &request.wire, "Shadowsocks 2022")?;
    let decoded = codec
        .decode_server_packet(&response, ss2022_udp_unix_timestamp_now())
        .map_err(|err| format!("decode Shadowsocks 2022 UDP packet: {err}"))?;
    Ok(UdpExchangeResult::new(
        decoded.payload,
        "udp-datagram-aead-2022",
    ))
}

pub(super) fn exchange_socks5_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    username: &str,
    password: &str,
) -> Result<UdpExchangeResult, String> {
    let mut control = open_plain_proxy_tcp_stream(proxy, "SOCKS5 UDP associate")?;
    let report = udp_associate_control_over_stream(
        &mut control,
        &proxy_server_authority(proxy),
        "0.0.0.0:0",
        username,
        password,
    )
    .map_err(|err| format!("SOCKS5 UDP associate control: {err}"))?;
    let relay = socks5_udp_relay_addr(proxy, &report.bind)?;
    let request = udp_packet::wrap_target(&original_dst.to_string(), payload)
        .map_err(|err| format!("wrap SOCKS5 UDP packet: {err}"))?;
    let response = exchange_udp_datagram_to_addr(proxy, relay, &request, "SOCKS5")?;
    let decoded =
        udp_packet::unwrap(&response).map_err(|err| format!("unwrap SOCKS5 UDP packet: {err}"))?;
    Ok(UdpExchangeResult::new(
        decoded.payload,
        "socks5-udp-associate",
    ))
}

pub(super) fn exchange_trojan_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    password: &str,
) -> Result<UdpExchangeResult, String> {
    let mut client = open_vless_tls_client(proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    let packet = trojan_packet::udp_packet(&original_dst.to_string(), payload)
        .map_err(|err| format!("build Trojan UDP packet: {err}"))?;
    let request =
        trojan_packet::tcp_request_header(password, "udp", &original_dst.to_string(), &packet)
            .map_err(|err| format!("build Trojan UDP-over-TCP request: {err}"))?;
    write_tls_plain_all(&mut client, &request, "write Trojan UDP-over-TCP request")?;
    read_tls_plain_until(&mut client, "read Trojan UDP-over-TCP response", |buffer| {
        decode_trojan_udp_packet(buffer).map(|packet| packet.payload)
    })
    .map(|payload| {
        UdpExchangeResult::new(payload, "tls-udp-over-tcp").with_tls_underlay(tls_underlay)
    })
}

pub(super) fn exchange_vmess_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    id: &str,
) -> Result<UdpExchangeResult, String> {
    let mut stream = open_plain_proxy_tcp_stream(proxy, "VMess UDP-over-TCP")?;
    let report = vmess::aead_udp_over_tcp_exchange_over_stream(
        &mut stream,
        &proxy_server_authority(proxy),
        id,
        &original_dst.to_string(),
        payload,
    )
    .map_err(|err| format!("VMess AEAD UDP-over-TCP exchange: {err}"))?;
    Ok(UdpExchangeResult::new(
        report.echoed_payload,
        "aead-udp-over-tcp",
    ))
}

pub(super) fn exchange_anytls_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    auth: &str,
) -> Result<UdpExchangeResult, String> {
    let mut client = open_vless_tls_client(proxy)?;
    let tls_underlay = tls_underlay_name(&client);
    write_tls_plain_all(
        &mut client,
        &anytls_link::handshake_auth_bytes(auth),
        "write AnyTLS auth handshake",
    )?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(
            anytls_contract::CMD_SETTINGS,
            1,
            &anytls_link::settings_bytes(),
        ),
        "write AnyTLS settings",
    )?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(anytls_contract::CMD_SYN, 1, &[]),
        "write AnyTLS SYN",
    )?;
    let stream_target = anytls_link::udp_stream_target(&original_dst.to_string())
        .map_err(|err| format!("build AnyTLS UDP stream target: {err}"))?;
    let stream_target_addr = anytls_link::socks_addr(&stream_target)
        .map_err(|err| format!("build AnyTLS UDP stream address: {err}"))?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(anytls_contract::CMD_PSH, 1, &stream_target_addr),
        "write AnyTLS UDP stream target",
    )?;
    let packet = anytls_link::packet_first_write(&original_dst.to_string(), payload)
        .map_err(|err| format!("build AnyTLS UDP packet write: {err}"))?;
    write_tls_plain_all(
        &mut client,
        &anytls_link::frame(anytls_contract::CMD_PSH, 1, &packet),
        "write AnyTLS UDP packet",
    )?;
    wait_anytls_udp_synack(&mut client)?;
    let response = read_anytls_udp_payload(&mut client)?;
    Ok(
        UdpExchangeResult::new(response, "frame-tls-udp-packet-stream")
            .with_tls_underlay(tls_underlay),
    )
}

pub(super) fn exchange_hysteria2_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    auth: &str,
    pin_sha256: &str,
    max_rx: u64,
    port_hop_ports: &[u16],
) -> Result<UdpExchangeResult, String> {
    run_quic_udp_exchange("Hysteria2 UDP", async move {
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_hysteria2_pinned_client_config(pin_sha256.to_owned())
                .map_err(|err| format!("build Hysteria2 QUIC client config: {err}"))?,
        );
        let remote = resolve_hysteria2_quic_remote(proxy, port_hop_ports)?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect Hysteria2 QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await Hysteria2 QUIC connect: {err}"))?;
        let auth_report = authenticate_hysteria2_connection(connection.clone(), auth, max_rx)
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
        let packet_id = fastrand::u16(1..=u16::MAX);
        let session_id = fastrand::u32(1..=u32::MAX);
        let request =
            build_hysteria2_udp_message(session_id, packet_id, &original_dst.to_string(), payload)?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send Hysteria2 UDP datagram: {err}"))?;
        let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| "read Hysteria2 UDP datagram timeout".to_owned())?
            .map_err(|err| format!("read Hysteria2 UDP datagram: {err}"))?;
        let parsed = parse_hysteria2_udp_message(&response)?;
        connection.close(0_u32.into(), b"resident hysteria2 udp done");
        endpoint.wait_idle().await;
        Ok(UdpExchangeResult::new(parsed.payload, "quic-udp-datagram")
            .with_quic_underlay("quinn-h3"))
    })
}

pub(super) fn exchange_tuic_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    uuid: &str,
    password: &str,
    alpn: &[String],
    allow_insecure: bool,
) -> Result<UdpExchangeResult, String> {
    run_quic_udp_exchange("TUIC UDP", async move {
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_tuic_runtime_client_config(alpn, allow_insecure)
                .map_err(|err| format!("build TUIC QUIC client config: {err}"))?,
        );
        let remote = resolve_proxy_udp_addr(proxy)?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect TUIC QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await TUIC QUIC connect: {err}"))?;
        authenticate_tuic_connection(&connection, uuid, password)
            .await
            .map_err(|err| format!("authenticate TUIC QUIC connection: {err}"))?;
        let packet_id = fastrand::u16(1..=u16::MAX);
        let request = build_tuic_packet_frame(1, packet_id, &original_dst.to_string(), payload)?;
        connection
            .send_datagram(Bytes::from(request))
            .map_err(|err| format!("send TUIC UDP datagram: {err}"))?;
        let response = time::timeout(RESIDENT_UDP_RESPONSE_TIMEOUT, connection.read_datagram())
            .await
            .map_err(|_| "read TUIC UDP datagram timeout".to_owned())?
            .map_err(|err| format!("read TUIC UDP datagram: {err}"))?;
        let parsed = parse_tuic_packet_frame(&response)?;
        connection.close(0_u32.into(), b"resident tuic udp done");
        endpoint.wait_idle().await;
        Ok(UdpExchangeResult::new(parsed.payload, "quic-udp-datagram").with_quic_underlay("quinn"))
    })
}

pub(super) fn exchange_juicity_udp(
    proxy: &ResidentProxyPlan,
    original_dst: SocketAddrV4,
    payload: &[u8],
    uuid: &str,
    password: &str,
    allow_insecure: bool,
    pinned_certchain_sha256: &str,
) -> Result<UdpExchangeResult, String> {
    run_quic_udp_exchange("Juicity UDP", async move {
        let mut endpoint = open_marked_quic_endpoint(proxy.mark)?;
        endpoint.set_default_client_config(
            build_juicity_runtime_client_config(allow_insecure, pinned_certchain_sha256)
                .map_err(|err| format!("build Juicity QUIC client config: {err}"))?,
        );
        let remote = resolve_proxy_udp_addr(proxy)?;
        let connection = endpoint
            .connect(remote, &proxy.server_name)
            .map_err(|err| format!("connect Juicity QUIC endpoint: {err}"))?
            .await
            .map_err(|err| format!("await Juicity QUIC connect: {err}"))?;
        let (_auth_report, mut auth_stream) =
            authenticate_juicity_connection(&connection, uuid, password)
                .await
                .map_err(|err| format!("authenticate Juicity QUIC connection: {err}"))?;
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
        let _ = auth_stream.finish().await;
        connection.close(0_u32.into(), b"resident juicity udp done");
        endpoint.wait_idle().await;
        Ok(
            UdpExchangeResult::new(parsed.payload, "quic-udp-stream-packet")
                .with_quic_underlay("quinn-h3"),
        )
    })
}

pub(super) async fn read_juicity_stream_packet_response(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        if let Ok(frame) = decode_stream_packet_frame(&response) {
            return Ok(frame.encoded);
        }
        if response.len() > 64 * 1024 {
            return Err(format!(
                "Juicity UDP stream response too large: {} bytes",
                response.len()
            ));
        }
        match recv
            .read(&mut buf)
            .await
            .map_err(|err| format!("read Juicity UDP stream response: {err}"))?
        {
            Some(0) => {}
            Some(read) => response.extend_from_slice(&buf[..read]),
            None => {
                return Err(
                    "Juicity UDP stream closed before a complete packet frame was decoded"
                        .to_owned(),
                );
            }
        }
    }
}
