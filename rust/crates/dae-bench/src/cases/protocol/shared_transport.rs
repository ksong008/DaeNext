use super::*;
pub(super) fn bench_shared_xhttp_mode(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let mode = dae_outbound::shared_transport::ir::normalize_xhttp_mode_ref(
                black_box("auto"),
                black_box("https"),
                black_box("reality"),
                black_box(true),
            );
            black_box(mode.normalized.len() as u64 ^ mode.ok as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_shared_grpc_cache_key(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let key = dae_outbound::shared_transport::ir::grpc_cache_key(
                black_box("addr:443"),
                black_box("sni.example"),
                black_box("dialer-1"),
                black_box(true),
                black_box(1234),
                black_box(true),
            );
            black_box(key.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_shared_xhttp_path(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let path = dae_outbound::shared_transport::ir::normalize_xhttp_path_and_query(
                black_box("xhttp?ed=2048&foo=bar"),
            );
            black_box(path.path.len() as u64 ^ path.query.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_shared_canonical_json(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let raw = r#"{"downloadSettings":{"address":"download.example","port":443,"network":"xhttp","security":"reality","xhttpSettings":{"host":"download.example","path":"/download","extra":"{\"xmux\":{\"maxConnections\":\"3\",\"cMaxReuseTimes\":\"9\"}}"}},"xmux":{"maxConnections":"1"},"xPaddingBytes":"100-200"}"#;
    Ok(measure(
        || {
            let canonical = dae_outbound::shared_transport::ir::canonical_json(black_box(raw))
                .expect("shared transport canonical json");
            black_box(canonical.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_shared_timer_constants(iters: u64, warmup: u64) -> Result<Measurement, String> {
    Ok(measure(
        || {
            let duration = Duration::from_millis(500)
                + Duration::from_secs(19)
                + Duration::from_secs(30)
                + Duration::from_secs(10)
                + Duration::from_secs(5);
            black_box(duration.as_millis() as u64)
        },
        iters,
        warmup,
    ))
}
