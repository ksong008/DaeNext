use super::*;
pub(super) fn bench_dns_doh_get_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let payload = [0x12, 0x34, 0x56, 0x78];
    Ok(measure(
        || {
            let req = build_doh_request(
                black_box("1.1.1.1:443"),
                black_box("dns.example.com"),
                black_box("/dns-query"),
                black_box(&payload),
            )
            .expect("build doh get request");
            black_box(req.url.len() as u64 ^ req.method.len() as u64 ^ req.body.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_doh_post_request(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let mut payload = vec![0x12, 0x34];
    payload.extend(std::iter::repeat_n(0xab, 1024));
    Ok(measure(
        || {
            let req = build_doh_request(
                black_box("1.1.1.1:443"),
                black_box("dns.example.com"),
                black_box("/dns-query"),
                black_box(&payload),
            )
            .expect("build doh post request");
            black_box(req.url.len() as u64 ^ req.method.len() as u64 ^ req.body.len() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_doh_validate_content_type(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let cases: [(u16, &str, &[u8]); 4] = [
        (200, "200 OK", b"application/dns-message"),
        (200, "200 OK", b"application/dns-message; charset=binary"),
        (502, "502 Bad Gateway", b"application/dns-message"),
        (200, "200 OK", b"text/html; charset=utf-8"),
    ];
    Ok(measure(
        || {
            let mut checksum = 0_u64;
            for (status_code, status, content_type) in black_box(cases) {
                match validate_doh_response(status_code, status, content_type) {
                    Ok(_) => checksum ^= 1,
                    Err(err) => checksum ^= err.to_string().len() as u64,
                }
            }
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}
