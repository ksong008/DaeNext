use super::*;
pub(super) fn bench_anytls_parse_link(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_anytls_auth_key(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let key = dae_outbound::anytls::link::auth_key(black_box("auth"));
            black_box(key[0] as u64 ^ key[31] as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_anytls_frame(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let settings = dae_outbound::anytls::link::settings_bytes();
    Ok(measure(
        || {
            let frame = dae_outbound::anytls::link::frame(black_box(4), black_box(1), &settings);
            black_box(frame.map(|frame| frame.len() as u64).unwrap_or_default())
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_anytls_underlay(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let contract =
                dae_outbound::anytls::link::underlay_contract(black_box("udp"), 1234, true)
                    .expect("fixed AnyTLS network fits MagicNetwork framing");
            black_box(contract.underlay_encoded.len() as u64 ^ contract.same_encoded_value as u64)
        },
        iters,
        warmup,
    ))
}
