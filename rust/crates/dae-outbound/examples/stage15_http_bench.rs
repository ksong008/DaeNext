use std::hint::black_box;
use std::time::Instant;

use dae_outbound::http_proxy::{HttpConnectOptions, HttpProxyLink, request};

fn main() {
    let iters = std::env::var("DAE_STAGE15_HTTP_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    bench("http_proxy_parse_link", iters, || {
        let _ = HttpProxyLink::parse(black_box(
            "https://user:pass@proxy.example:443?sni=server.example&allowInsecure=1#node",
        ))
        .unwrap();
    });
    let mut connect = HttpConnectOptions::connect("example.com:443");
    connect.username = "user".to_owned();
    connect.password = "pass".to_owned();
    connect.host_override = "front.example".to_owned();
    bench("http_proxy_connect_request", iters, || {
        let _ = request::connect_request(black_box(&connect));
    });
    let raw =
        b"GET /index.html HTTP/1.1\r\nHost: origin.example\r\nProxy-Connection: keep-alive\r\n\r\n";
    bench("http_proxy_forward_request", iters, || {
        let _ = request::forward_http_request(black_box(raw)).unwrap();
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
