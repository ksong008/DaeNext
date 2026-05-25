use std::hint::black_box;

use dae_geodata::decode_hex;
use dae_sniffing::sniff_tcp;

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![BenchCase {
        id: "sniffing/http_host",
        default_iters: 100_000,
        run: bench_sniffing_http_host,
    }]
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
