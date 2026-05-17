use std::time::Instant;

use dae_outbound::http_proxy::{HttpConnectOptions, request as http_request};
use dae_outbound::shadowsocks;
use dae_outbound::socks5::{Socks5Address, Socks5Command, handshake};

fn main() {
    let iters = std::env::var("DAE_STAGE18_FIRST_BATCH_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200_000);
    let payload = b"stage18-ping";

    let target = Socks5Address::parse("example.com:443").unwrap();
    bench("stage18_socks5_connect_payload_frame", iters, || {
        let mut frame = handshake::request(Socks5Command::Connect, &target).unwrap();
        frame.extend_from_slice(payload);
        frame.len()
    });

    let mut options = HttpConnectOptions::connect("example.com:443");
    options.username = "user".to_owned();
    options.password = "pass".to_owned();
    options.host_override = "front.example".to_owned();
    bench("stage18_http_connect_payload_frame", iters, || {
        let mut frame = http_request::connect_request(&options);
        frame.extend_from_slice(payload);
        frame.len()
    });

    let client_salt = hex_decode("000102030405060708090a0b0c0d0e0f");
    let target_payload = {
        let mut out = Socks5Address::parse("example.com:443")
            .unwrap()
            .encode()
            .unwrap();
        out.extend_from_slice(payload);
        out
    };
    bench("stage18_shadowsocks_aead_initial_roundtrip", iters, || {
        let frame = shadowsocks::encode_client_initial(
            "aes-128-gcm",
            "stage18-password",
            &client_salt,
            &target_payload,
        )
        .unwrap();
        let (_, decoded) =
            shadowsocks::decode_client_initial("aes-128-gcm", "stage18-password", &frame).unwrap();
        decoded.len()
    });
}

fn bench(name: &str, iters: usize, mut f: impl FnMut() -> usize) {
    let start = Instant::now();
    let mut checksum = 0usize;
    for _ in 0..iters {
        checksum ^= f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    println!("{name}\t{ns_per_op:.1} ns/op\t{iters} iters\tchecksum {checksum}");
}

fn hex_decode(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("bad hex byte: {byte}"),
    }
}
