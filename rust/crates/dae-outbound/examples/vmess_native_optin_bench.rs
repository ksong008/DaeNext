use std::hint::black_box;
use std::time::Instant;

use dae_outbound::vmess::{VMessLink, VMessMetadata, uuid};

fn main() {
    let iters = std::env::var("DAE_VMESS_NATIVE_OPTIN_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(200_000);
    let link = "vmess://eyJwcyI6Impzb24tYWVhZCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiN2MxMmM3NDUtNjNhNS00MzNkLTllNjAtMDIyZTQ2OWI1YmQ0IiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZnJvbnQuZXhhbXBsZSIsInNuaSI6InNuaS5leGFtcGxlIiwicGF0aCI6Ii93cyIsInRscyI6InRscyIsImFsbG93SW5zZWN1cmUiOmZhbHNlLCJGaW5nZXJwcmludCI6IiIsInYiOiIyIiwicHJvdG9jb2wiOiJ2bWVzcyJ9";
    bench("vmess_parse_link", iters, || {
        let _ = VMessLink::parse(black_box(link)).unwrap();
    });
    let metadata = VMessMetadata::parse("tcp", "example.com:443").unwrap();
    bench("vmess_metadata_bytes", iters, || {
        let _ = black_box(&metadata).encode_addr().unwrap();
    });
    bench("vmess_uuid5_compatibility", iters, || {
        let _ = uuid::normalize_vmess_uuid(black_box("short-id"));
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
