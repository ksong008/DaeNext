use std::time::Instant;

use dae_outbound::shared_transport::{
    HttpUpgradeOptions, SimpleObfsHttpOptions, http_upgrade_request, simpleobfs_http_request,
    websocket_client_binary_frame, websocket_handshake_request,
};

fn main() {
    let iters = std::env::var("DAE_SHARED_TRANSPORT_FOUNDATION_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200_000);
    let payload = b"shared-transport-ping";
    let upgrade = HttpUpgradeOptions::new("upgrade.example", "/upgrade");
    let websocket = HttpUpgradeOptions::new("ws.example", "/ws");
    let simpleobfs = SimpleObfsHttpOptions::new("obfs.example", "/");

    bench("shared_transport_httpupgrade_request", iters, || {
        http_upgrade_request(&upgrade).len()
    });
    bench("shared_transport_websocket_handshake", iters, || {
        websocket_handshake_request(&websocket, "dGhlIHNhbXBsZSBub25jZQ==").len()
    });
    bench("shared_transport_websocket_binary_frame", iters, || {
        websocket_client_binary_frame(payload, [0x11, 0x22, 0x33, 0x44])
            .unwrap()
            .len()
    });
    bench("shared_transport_simpleobfs_http_request", iters, || {
        simpleobfs_http_request(&simpleobfs).len()
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
