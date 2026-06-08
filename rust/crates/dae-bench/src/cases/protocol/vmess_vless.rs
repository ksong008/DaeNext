use super::*;
pub(super) fn bench_vless_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_vless_password_to_key(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_vless_request_header(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_vmess_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_vmess_metadata_bytes(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let metadata = VMessMetadata::parse("tcp", "example.com:443")
        .map_err(|err| format!("vmess metadata parse failed: {err}"))?;
    let mut encoded = [0_u8; 256];
    Ok(measure(
        || {
            let len = metadata
                .write_addr_to_slice(black_box(&mut encoded))
                .expect("vmess metadata encode");
            black_box(len as u64 ^ encoded[0] as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_vmess_uuid5_compatibility(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let uuid = dae_outbound::vmess::uuid::string_to_uuid5(black_box("short-id"));
            black_box(uuid.len() as u64)
        },
        iters,
        warmup,
    ))
}
