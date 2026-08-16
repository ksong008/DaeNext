use super::*;
pub(super) fn bench_shadowsocks_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = ShadowsocksLink {
        name: "bench".to_owned(),
        server: "example.com".to_owned(),
        port: 443,
        password: format!("{SS2022_PSK_128}:{SS2022_PSK_128}"),
        cipher: "2022-blake3-aes-128-gcm".to_owned(),
        plugin: Default::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url();
    Ok(measure(
        || {
            let parsed = ShadowsocksLink::parse(black_box(&link)).expect("shadowsocks parse link");
            black_box(
                parsed.server.len() as u64 ^ parsed.port as u64 ^ parsed.password.len() as u64,
            )
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_shadowsocks_metadata_bytes(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let metadata = ShadowsocksMetadata::parse("example.com:443")
        .map_err(|err| format!("shadowsocks metadata parse failed: {err}"))?;
    Ok(measure(
        || {
            let encoded = metadata.encode().expect("shadowsocks metadata encode");
            black_box(encoded.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_shadowsocks_ss2022_psk_split(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let password = format!("{SS2022_PSK_128}:{SS2022_PSK_128}");
    Ok(measure(
        || {
            let info = dae_outbound::shadowsocks::ss2022::validate_psk_list(
                black_box("2022-blake3-aes-128-gcm"),
                black_box(&password),
            )
            .expect("ss2022 psk split");
            black_box(info.psk_count as u64 ^ info.expected_key_len as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_shadowsocks_ss2022_udp_encode(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let mut codec = dae_outbound::shadowsocks::Ss2022UdpCodec::new(
        "2022-blake3-aes-128-gcm",
        SS2022_PSK_128,
        [0x31; 8],
    )
    .map_err(|err| format!("SS2022 UDP codec setup failed: {err}"))?;
    let payload = [0x72_u8; 1_200];
    Ok(measure(
        || {
            let packet = codec
                .encode_client_packet(
                    black_box("192.0.2.1:443"),
                    black_box(&payload),
                    black_box(1_700_000_000),
                    None,
                )
                .expect("SS2022 UDP encode");
            black_box(packet.wire.len() as u64 ^ packet.packet_id)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_trojan_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = "trojan-go://password@example.com:443?type=ws&host=front.example&path=/ws&encryption=ss%3Baes-128-gcm%3Bsecret#ss";
    Ok(measure(
        || {
            let parsed = TrojanLink::parse(black_box(link)).expect("trojan parse link");
            black_box(parsed.address().len() as u64 ^ parsed.encryption.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_trojan_tcp_request_header(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let header = dae_outbound::trojan::packet::tcp_request_header(
                black_box("password"),
                black_box("tcp"),
                black_box("example.com:443"),
                black_box(b"ping"),
            )
            .expect("trojan tcp header");
            black_box(header.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_trojan_udp_packet(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let packet =
                dae_outbound::trojan::packet::udp_packet(black_box("example.com:443"), b"ping")
                    .expect("trojan udp packet");
            black_box(packet.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_http_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = "https://user:pass@proxy.example:443?sni=server.example&allowInsecure=1#node";
    Ok(measure(
        || {
            let parsed = HttpProxyLink::parse(black_box(link)).expect("http parse link");
            black_box(parsed.address().len() as u64 ^ parsed.username.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_http_connect_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let mut options = HttpConnectOptions::connect("example.com:443");
    options.username = "user".to_owned();
    options.password = "pass".to_owned();
    options.host_override = "front.example".to_owned();
    Ok(measure(
        || {
            let request = dae_outbound::http_proxy::request::connect_request(black_box(&options))
                .expect("bench fixture proxy authority is valid");
            black_box(request.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_http_forward_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let raw =
        b"GET /index.html HTTP/1.1\r\nHost: origin.example\r\nProxy-Connection: keep-alive\r\n\r\n";
    Ok(measure(
        || {
            let request = dae_outbound::http_proxy::request::forward_http_request(black_box(raw))
                .expect("http forward request");
            black_box(request.len() as u64)
        },
        iters,
        warmup,
    ))
}
