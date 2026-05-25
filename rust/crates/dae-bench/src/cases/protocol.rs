use std::hint::black_box;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use dae_outbound::{
    AnyTLSLink, HttpConnectOptions, HttpProxyLink, Hysteria2Link, JuicityLink, ShadowsocksLink,
    ShadowsocksMetadata, Socks5Address, TrojanLink, TuicLink, VLESSLink, VMessLink, VMessMetadata,
};

use crate::{BenchCase, Measurement, measure};

const UUID: &str = "7c12c745-63a5-433d-9e60-022e469b5bd4";
const SS2022_PSK_128: &str = "MTIzNDU2Nzg5MDEyMzQ1Ng==";

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "protocol/socks5_address_codec",
            default_iters: 100_000,
            run: bench_socks5_address_codec,
        },
        BenchCase {
            id: "protocol/socks5_handshake_bytes",
            default_iters: 100_000,
            run: bench_socks5_handshake_bytes,
        },
        BenchCase {
            id: "protocol/socks5_udp_packet_wrap",
            default_iters: 100_000,
            run: bench_socks5_udp_packet_wrap,
        },
        BenchCase {
            id: "protocol/vless_parse_link",
            default_iters: 10_000,
            run: bench_vless_parse_link,
        },
        BenchCase {
            id: "protocol/vless_password_to_key",
            default_iters: 100_000,
            run: bench_vless_password_to_key,
        },
        BenchCase {
            id: "protocol/vless_request_header",
            default_iters: 100_000,
            run: bench_vless_request_header,
        },
        BenchCase {
            id: "protocol/vmess_parse_link",
            default_iters: 10_000,
            run: bench_vmess_parse_link,
        },
        BenchCase {
            id: "protocol/vmess_metadata_bytes",
            default_iters: 100_000,
            run: bench_vmess_metadata_bytes,
        },
        BenchCase {
            id: "protocol/vmess_uuid5_compatibility",
            default_iters: 100_000,
            run: bench_vmess_uuid5_compatibility,
        },
        BenchCase {
            id: "protocol/shadowsocks_parse_link",
            default_iters: 10_000,
            run: bench_shadowsocks_parse_link,
        },
        BenchCase {
            id: "protocol/shadowsocks_metadata_bytes",
            default_iters: 100_000,
            run: bench_shadowsocks_metadata_bytes,
        },
        BenchCase {
            id: "protocol/shadowsocks_ss2022_psk_split",
            default_iters: 100_000,
            run: bench_shadowsocks_ss2022_psk_split,
        },
        BenchCase {
            id: "protocol/trojan_parse_link",
            default_iters: 10_000,
            run: bench_trojan_parse_link,
        },
        BenchCase {
            id: "protocol/trojan_tcp_request_header",
            default_iters: 100_000,
            run: bench_trojan_tcp_request_header,
        },
        BenchCase {
            id: "protocol/trojan_udp_packet",
            default_iters: 100_000,
            run: bench_trojan_udp_packet,
        },
        BenchCase {
            id: "protocol/http_parse_link",
            default_iters: 10_000,
            run: bench_http_parse_link,
        },
        BenchCase {
            id: "protocol/http_connect_request",
            default_iters: 100_000,
            run: bench_http_connect_request,
        },
        BenchCase {
            id: "protocol/http_forward_request",
            default_iters: 100_000,
            run: bench_http_forward_request,
        },
        BenchCase {
            id: "protocol/hysteria2_parse_link",
            default_iters: 10_000,
            run: bench_hysteria2_parse_link,
        },
        BenchCase {
            id: "protocol/hysteria2_export_link",
            default_iters: 100_000,
            run: bench_hysteria2_export_link,
        },
        BenchCase {
            id: "protocol/hysteria2_pin_normalize",
            default_iters: 100_000,
            run: bench_hysteria2_pin_normalize,
        },
        BenchCase {
            id: "protocol/tuic_parse_link",
            default_iters: 10_000,
            run: bench_tuic_parse_link,
        },
        BenchCase {
            id: "protocol/tuic_export_link",
            default_iters: 100_000,
            run: bench_tuic_export_link,
        },
        BenchCase {
            id: "protocol/tuic_alpn_split",
            default_iters: 100_000,
            run: bench_tuic_alpn_split,
        },
        BenchCase {
            id: "protocol/juicity_parse_link",
            default_iters: 10_000,
            run: bench_juicity_parse_link,
        },
        BenchCase {
            id: "protocol/juicity_export_link",
            default_iters: 100_000,
            run: bench_juicity_export_link,
        },
        BenchCase {
            id: "protocol/juicity_pinned_decode",
            default_iters: 100_000,
            run: bench_juicity_pinned_decode,
        },
        BenchCase {
            id: "protocol/anytls_parse_link",
            default_iters: 10_000,
            run: bench_anytls_parse_link,
        },
        BenchCase {
            id: "protocol/anytls_auth_key",
            default_iters: 100_000,
            run: bench_anytls_auth_key,
        },
        BenchCase {
            id: "protocol/anytls_frame",
            default_iters: 100_000,
            run: bench_anytls_frame,
        },
        BenchCase {
            id: "protocol/anytls_underlay",
            default_iters: 100_000,
            run: bench_anytls_underlay,
        },
        BenchCase {
            id: "protocol/shared_xhttp_mode",
            default_iters: 100_000,
            run: bench_shared_xhttp_mode,
        },
        BenchCase {
            id: "protocol/shared_grpc_cache_key",
            default_iters: 100_000,
            run: bench_shared_grpc_cache_key,
        },
        BenchCase {
            id: "protocol/shared_xhttp_path",
            default_iters: 100_000,
            run: bench_shared_xhttp_path,
        },
        BenchCase {
            id: "protocol/shared_canonical_json",
            default_iters: 10_000,
            run: bench_shared_canonical_json,
        },
        BenchCase {
            id: "protocol/shared_timer_constants",
            default_iters: 100_000,
            run: bench_shared_timer_constants,
        },
    ]
}

fn bench_socks5_address_codec(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let address =
                Socks5Address::parse(black_box("example.com:443")).expect("socks5 address parse");
            let mut out = Vec::new();
            address.write_to(&mut out).expect("socks5 address write");
            black_box(out.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_socks5_handshake_bytes(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let greeting = dae_outbound::socks5::handshake::greeting("user", "pass");
            let auth = dae_outbound::socks5::handshake::username_password_auth("user", "pass")
                .expect("socks5 auth");
            let request = dae_outbound::socks5::handshake::connect_request("example.com:443")
                .expect("socks5 connect request");
            black_box((greeting.len() ^ auth.len() ^ request.len()) as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_socks5_udp_packet_wrap(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let payload = b"ping";
    Ok(measure(
        || {
            let packet = dae_outbound::socks5::udp_packet::wrap_target(
                black_box("example.com:443"),
                payload,
            )
            .expect("socks5 udp packet");
            black_box(packet.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_vless_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = format!(
        "vless://{UUID}@example.com:443?type=tcp&security=tls&sni=server.example&fp=chrome&alpn=h2,http/1.1&flow=xtls-rprx-vision#tcp-vision"
    );
    Ok(measure(
        || {
            let parsed = VLESSLink::parse(black_box(&link)).expect("vless parse link");
            black_box(parsed.address().len() as u64 ^ parsed.flow.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_vless_password_to_key(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let key = dae_outbound::vless::password_to_key(black_box("short-id"))
                .expect("vless password to key");
            black_box(key[0] as u64 ^ key[15] as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_vless_request_header(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let key = dae_outbound::vless::password_to_key(UUID).map_err(|err| err.to_string())?;
    Ok(measure(
        || {
            let header = dae_outbound::vless::packet::request_header(
                black_box(&key),
                black_box(""),
                black_box("udp"),
                black_box("1.2.3.4:53"),
                black_box(false),
                black_box(b"ping"),
            )
            .expect("vless request header");
            black_box(header.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_vmess_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = VMessLink {
        ps: "json-aead".to_owned(),
        add: "example.com".to_owned(),
        port: "443".to_owned(),
        id: UUID.to_owned(),
        aid: "0".to_owned(),
        net: "ws".to_owned(),
        r#type: "none".to_owned(),
        host: "front.example".to_owned(),
        sni: String::new(),
        path: "/ws".to_owned(),
        tls: "tls".to_owned(),
        allow_insecure: false,
        fingerprint: String::new(),
        v: "2".to_owned(),
        protocol: "vmess".to_owned(),
    }
    .export_url();
    Ok(measure(
        || {
            let parsed = VMessLink::parse(black_box(&link)).expect("vmess parse link");
            black_box(parsed.address().len() as u64 ^ parsed.net.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_vmess_metadata_bytes(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let metadata = VMessMetadata::parse("tcp", "example.com:443")
        .map_err(|err| format!("vmess metadata parse failed: {err}"))?;
    Ok(measure(
        || {
            let encoded = metadata.encode_addr().expect("vmess metadata encode");
            black_box(encoded.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_vmess_uuid5_compatibility(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let uuid = dae_outbound::vmess::uuid::string_to_uuid5(black_box("short-id"));
            black_box(uuid.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_shadowsocks_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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
            black_box(parsed.address().len() as u64 ^ parsed.password.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_shadowsocks_metadata_bytes(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_shadowsocks_ss2022_psk_split(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_trojan_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_trojan_tcp_request_header(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_trojan_udp_packet(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_http_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_http_connect_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let mut options = HttpConnectOptions::connect("example.com:443");
    options.username = "user".to_owned();
    options.password = "pass".to_owned();
    options.host_override = "front.example".to_owned();
    Ok(measure(
        || {
            let request = dae_outbound::http_proxy::request::connect_request(black_box(&options));
            black_box(request.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_http_forward_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

fn bench_hysteria2_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = "hy2://user:pass@example.com:443,8443-8445?insecure=true&sni=hop.example&pinSHA256=AA-BB:CC&maxTx=4096&maxRx=8192#hop";
    Ok(measure(
        || {
            let parsed = Hysteria2Link::parse(black_box(link)).expect("hysteria2 parse link");
            black_box(parsed.property_address().len() as u64 ^ parsed.pin_sha256.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_hysteria2_export_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = Hysteria2Link::parse(
        "hy2://user:pass@example.com:443,8443-8445?insecure=true&sni=hop.example&pinSHA256=AA-BB:CC&maxTx=4096&maxRx=8192#hop",
    )
    .map_err(|err| format!("hysteria2 parse failed: {err}"))?;
    Ok(measure(
        || {
            let exported = link.export_url();
            black_box(exported.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_hysteria2_pin_normalize(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let pin = dae_outbound::hysteria2::link::normalize_pin_sha256(black_box("AA-BB:CC"));
            black_box(pin.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_tuic_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = format!(
        "tuic://{UUID}:pass@example.com:443?congestion_control=bbr&alpn=h3,h2&udp_relay_mode=quic#basic"
    );
    Ok(measure(
        || {
            let parsed = TuicLink::parse(black_box(&link)).expect("tuic parse link");
            black_box(parsed.address().len() as u64 ^ parsed.alpn.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_tuic_export_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = TuicLink::parse(&format!(
        "tuic://{UUID}:pass@example.com:443?congestion_control=bbr&alpn=h3,h2&udp_relay_mode=quic#basic"
    ))
    .map_err(|err| format!("tuic parse failed: {err}"))?;
    Ok(measure(
        || {
            let exported = link.export_url();
            black_box(exported.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_tuic_alpn_split(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let alpn = dae_outbound::tuic::link::split_alpn(black_box("h3,h2,http/1.1"));
            black_box(alpn.len() as u64 ^ alpn[0].len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_juicity_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let pin = juicity_pin();
    let link = format!(
        "juicity://{UUID}:pass@example.com:443?congestion_control=bbr&pinned_certchain_sha256={pin}#basic"
    );
    Ok(measure(
        || {
            let parsed = JuicityLink::parse(black_box(&link)).expect("juicity parse link");
            black_box(parsed.address().len() as u64 ^ parsed.pinned_certchain_sha256.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_juicity_export_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let pin = juicity_pin();
    let link = JuicityLink::parse(&format!(
        "juicity://{UUID}:pass@example.com:443?congestion_control=bbr&pinned_certchain_sha256={pin}#basic"
    ))
    .map_err(|err| format!("juicity parse failed: {err}"))?;
    Ok(measure(
        || {
            let exported = link.export_url();
            black_box(exported.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_juicity_pinned_decode(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let pin = juicity_pin();
    Ok(measure(
        || {
            let decoded = dae_outbound::juicity::link::decode_pinned_certchain(black_box(&pin))
                .expect("juicity pinned decode");
            black_box(decoded.decoded.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_anytls_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let link = "anytls://auth@example.com:443?insecure=1&sni=sni.example#basic";
    Ok(measure(
        || {
            let parsed = AnyTLSLink::parse(black_box(link)).expect("anytls parse link");
            black_box(parsed.address().len() as u64 ^ parsed.auth.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_anytls_auth_key(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let key = dae_outbound::anytls::link::auth_key(black_box("auth"));
            black_box(key[0] as u64 ^ key[31] as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_anytls_frame(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let settings = dae_outbound::anytls::link::settings_bytes();
    Ok(measure(
        || {
            let frame = dae_outbound::anytls::link::frame(black_box(4), black_box(1), &settings);
            black_box(frame.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_anytls_underlay(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let contract =
                dae_outbound::anytls::link::underlay_contract(black_box("udp"), 1234, true);
            black_box(contract.underlay_encoded.len() as u64 ^ contract.same_encoded_value as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_shared_xhttp_mode(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let mode = dae_outbound::shared_transport::ir::normalize_xhttp_mode(
                black_box("auto"),
                black_box("https"),
                black_box("reality"),
                black_box(true),
            );
            black_box(mode.normalized.len() as u64 ^ mode.ok as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_shared_grpc_cache_key(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let key = dae_outbound::shared_transport::ir::grpc_cache_key(
                black_box("addr:443"),
                black_box("sni.example"),
                black_box("dialer-1"),
                black_box(true),
                black_box(1234),
                black_box(true),
            );
            black_box(key.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_shared_xhttp_path(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let path = dae_outbound::shared_transport::ir::normalize_xhttp_path_and_query(
                black_box("xhttp?ed=2048&foo=bar"),
            );
            black_box(path.path.len() as u64 ^ path.query.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_shared_canonical_json(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let raw = r#"{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","security":"reality","xhttpSettings":{"host":"download.example","path":"/download","extra":"{\"xmux\":{\"maxConnections\":\"3\",\"cMaxReuseTimes\":\"9\"}}"}},"xmux":{"maxConnections":"1"},"xPaddingBytes":"100-200"}"#;
    Ok(measure(
        || {
            let canonical = dae_outbound::shared_transport::ir::canonical_json(black_box(raw))
                .expect("shared transport canonical json");
            black_box(canonical.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_shared_timer_constants(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let duration = Duration::from_millis(500)
                + Duration::from_secs(19)
                + Duration::from_secs(30)
                + Duration::from_secs(10)
                + Duration::from_secs(5);
            black_box(duration.as_millis() as u64)
        },
        iters,
        warmup,
    ))
}

fn juicity_pin() -> String {
    general_purpose::URL_SAFE.encode([
        0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0xfb, 0xff, 0xfe, 0xfa, 0xef, 0xee, 0xab, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ])
}
