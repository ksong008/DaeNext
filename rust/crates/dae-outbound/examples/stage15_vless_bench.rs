use std::hint::black_box;
use std::time::Instant;

use dae_outbound::vless::{VLESSLink, packet, password_to_key};

fn main() {
    let iters = std::env::var("DAE_STAGE15_VLESS_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let link = "vless://7c12c745-63a5-433d-9e60-022e469b5bd4@example.com:443?allowInsecure=0&alpn=h2%2Chttp%2F1.1&flow=xtls-rprx-vision&fp=chrome&headerType=none&security=tls&sni=server.example&type=tcp#tcp-vision";
    bench("vless_parse_link", iters, || {
        let _ = VLESSLink::parse(black_box(link)).unwrap();
    });
    bench("vless_password_to_key", iters, || {
        let _ = password_to_key(black_box("short-id")).unwrap();
    });
    let key = password_to_key("7c12c745-63a5-433d-9e60-022e469b5bd4").unwrap();
    bench("vless_request_header", iters, || {
        let _ = packet::first_write_bytes(
            black_box(&key),
            black_box(""),
            black_box("udp"),
            black_box("1.2.3.4:53"),
            black_box(false),
            black_box(b"ping"),
        )
        .unwrap();
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
