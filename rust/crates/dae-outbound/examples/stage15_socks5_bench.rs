use std::hint::black_box;
use std::time::Instant;

use dae_outbound::socks5::{Socks5Address, handshake, udp_packet};

fn main() {
    let iters = std::env::var("DAE_STAGE15_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let address = Socks5Address::parse("example.com:443").unwrap();

    bench("socks5_address_codec", iters, || {
        let encoded = black_box(&address).encode().unwrap();
        let _ = Socks5Address::decode(black_box(&encoded)).unwrap();
    });
    bench("socks5_handshake_bytes", iters, || {
        let _ = handshake::greeting(black_box("user"), black_box("pass"));
        let _ = handshake::username_password_auth(black_box("user"), black_box("pass")).unwrap();
        let _ = handshake::request(handshake::Socks5Command::Connect, black_box(&address)).unwrap();
    });
    bench("socks5_udp_packet_wrap", iters, || {
        let wrapped = udp_packet::wrap(black_box(&address), black_box(b"ping")).unwrap();
        let _ = udp_packet::unwrap(black_box(&wrapped)).unwrap();
    });
}

fn bench(name: &str, iters: u64, mut f: impl FnMut()) {
    for _ in 0..100 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    println!("{name}\t{ns_per_op:.1} ns/op\t{iters} iters");
}
