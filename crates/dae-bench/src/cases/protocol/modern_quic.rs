use super::*;
pub(super) fn bench_hysteria2_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_hysteria2_export_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_hysteria2_pin_normalize(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let pin = dae_outbound::hysteria2::link::normalize_pin_sha256(black_box("AA-BB:CC"));
            black_box(pin.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_hysteria2_udp_encode(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let payload = [0x31_u8; 1_200];
    Ok(measure(
        || {
            let encoded = dae_outbound::hysteria2::encode_hysteria2_udp_payload(
                black_box(7),
                0,
                0,
                1,
                black_box("192.0.2.1:443"),
                black_box(&payload),
            )
            .expect("Hysteria2 UDP encode");
            black_box(encoded.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_tuic_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_tuic_export_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_tuic_alpn_split(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let mut alpn = dae_outbound::tuic::link::split_alpn_ref(black_box("h3,h2,http/1.1"));
            let first = alpn.next().unwrap_or_default();
            let count = 1 + alpn.count();
            black_box(count as u64 ^ first.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_tuic_udp_encode(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let payload = [0x72_u8; 1_200];
    Ok(measure(
        || {
            let encoded = dae_outbound::tuic::encode_tuic_udp_payload(
                black_box(7),
                black_box(11),
                1,
                0,
                Some(black_box("192.0.2.1:443")),
                black_box(&payload),
            )
            .expect("TUIC UDP encode");
            black_box(encoded.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_juicity_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_juicity_export_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_juicity_pinned_decode(iters: u64, warmup: u64) -> Result<Measurement, String> {
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
