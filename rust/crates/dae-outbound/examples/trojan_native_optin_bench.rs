use std::hint::black_box;
use std::time::Instant;

use dae_outbound::trojan::{TrojanLink, packet};

fn main() {
    let iters = std::env::var("DAE_TROJAN_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let link = "trojan-go://password@example.com:443?type=ws&host=front.example&path=/ws&encryption=ss%3Baes-128-gcm%3Bsecret#ss";
    bench("trojan_parse_link", iters, || {
        let _ = TrojanLink::parse(black_box(link)).unwrap();
    });
    bench("trojan_tcp_request_header", iters, || {
        let _ = packet::tcp_request_header(
            black_box("password"),
            black_box("tcp"),
            black_box("example.com:443"),
            black_box(b"ping"),
        )
        .unwrap();
    });
    bench("trojan_udp_packet", iters, || {
        let _ = packet::udp_packet(black_box("example.com:443"), black_box(b"ping")).unwrap();
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
