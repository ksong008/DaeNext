use std::hint::black_box;

use dae_geodata::decode_hex;
use dae_sniffing::{TcpSniffBuffer, sniff_tcp, sniff_tcp_cow};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "sniffing/http_host",
            default_iters: 100_000,
            run: bench_sniffing_http_host,
        },
        BenchCase {
            id: "sniffing/http_host_borrowed",
            default_iters: 100_000,
            run: bench_sniffing_http_host_borrowed,
        },
        BenchCase {
            id: "sniffing/tcp_buffer_preserve",
            default_iters: 100_000,
            run: bench_sniffing_tcp_buffer_preserve,
        },
    ]
}

fn bench_sniffing_http_host(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = dae_golden::load_json("sniffing/basic.json").map_err(|err| err.to_string())?;
    let http_hex = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "http-host-normalize-and-retain")
        .unwrap()["input_hex"]
        .as_str()
        .unwrap();
    let http = decode_hex(http_hex).map_err(|err| err.to_string())?;
    Ok(measure(
        || {
            let domain = sniff_tcp(black_box(&http)).expect("sniff http host");
            black_box(domain.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_sniffing_http_host_borrowed(iters: u64, warmup: u64) -> Result<Measurement, String> {
    const HTTP: &[u8] = b"GET / HTTP/1.1\r\nHost:example.com\r\n\r\n";
    Ok(measure(
        || {
            let domain = sniff_tcp_cow(black_box(HTTP)).expect("sniff borrowed http host");
            black_box(domain.len() as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_sniffing_tcp_buffer_preserve(iters: u64, warmup: u64) -> Result<Measurement, String> {
    const HTTP: &[u8] = b"GET / HTTP/1.1\r\nHost:example.com\r\n\r\n";
    Ok(measure(
        || {
            let mut buffer = TcpSniffBuffer::new(black_box(HTTP));
            let domain_len = buffer.sniff_tcp().expect("sniff buffered http host").len();
            black_box(domain_len as u64 ^ buffer.data_view()[0] as u64)
        },
        iters,
        warmup,
    ))
}
