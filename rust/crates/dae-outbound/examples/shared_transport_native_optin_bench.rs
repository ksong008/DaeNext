use std::hint::black_box;
use std::time::Instant;

use dae_outbound::shared_transport::{contract, ir};

fn main() {
    let iters = std::env::var("DAE_SHARED_TRANSPORT_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let extra = r#"{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","security":"reality","xhttpSettings":{"host":"download.example","path":"/download","extra":"{\"xmux\":{\"maxConnections\":\"3\",\"cMaxReuseTimes\":\"9\"}}"}},"xmux":{"maxConnections":"1"},"xPaddingBytes":"100-200"}"#;

    bench("shared_transport_xhttp_mode", iters, || {
        let _ = ir::normalize_xhttp_mode(
            black_box("auto"),
            black_box("https"),
            black_box("reality"),
            black_box(true),
        );
    });
    bench("shared_transport_grpc_cache_key", iters, || {
        let _ = ir::grpc_cache_key(
            black_box("addr:443"),
            black_box("sni.example"),
            black_box("dialer-1"),
            black_box(true),
            black_box(1234),
            black_box(true),
        );
    });
    bench("shared_transport_xhttp_path", iters, || {
        let _ = ir::normalize_xhttp_path_and_query(black_box("xhttp?ed=2048&foo=bar"));
    });
    bench("shared_transport_canonical_json", iters, || {
        let _ = ir::canonical_json(black_box(extra)).unwrap();
    });
    bench("shared_transport_timer_constants", iters, || {
        let _ = black_box(
            contract::GRPC_BACKOFF_BASE_MS
                + contract::GRPC_KEEPALIVE_SECONDS
                + contract::GRPC_KEEPALIVE_TIMEOUT_SECONDS
                + contract::GRPC_MIN_CONNECT_TIMEOUT_SECONDS
                + contract::MEEK_INITIAL_POLLING_MS
                + contract::MEEK_MAX_POLLING_MS
                + contract::MEEK_MIN_POLLING_MS
                + contract::XHTTP_PACKET_MIN_GAP_MS_DEFAULT,
        );
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
