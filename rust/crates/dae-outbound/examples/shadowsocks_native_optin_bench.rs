use std::hint::black_box;
use std::time::Instant;

use dae_outbound::shadowsocks::{ShadowsocksLink, ShadowsocksMetadata, ss2022};

fn main() {
    let iters = std::env::var("DAE_SHADOWSOCKS_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let link = "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==%3AMTIzNDU2Nzg5MDEyMzQ1Ng==@example.com:443#multi";
    bench("shadowsocks_parse_link", iters, || {
        let _ = ShadowsocksLink::parse(black_box(link)).unwrap();
    });
    let metadata = ShadowsocksMetadata::parse("example.com:443").unwrap();
    bench("shadowsocks_metadata_bytes", iters, || {
        let _ = black_box(&metadata).encode().unwrap();
    });
    let password = "MTIzNDU2Nzg5MDEyMzQ1Ng==:MTIzNDU2Nzg5MDEyMzQ1Ng==";
    bench("shadowsocks_ss2022_psk_split", iters, || {
        let _ =
            ss2022::validate_psk_list(black_box("2022-blake3-aes-128-gcm"), black_box(password))
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
