use super::*;
pub(super) fn bench_socks5_address_codec(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_socks5_handshake_bytes(iters: u64, warmup: u64) -> Result<Measurement, String> {
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

pub(super) fn bench_socks5_udp_packet_wrap(iters: u64, warmup: u64) -> Result<Measurement, String> {
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
