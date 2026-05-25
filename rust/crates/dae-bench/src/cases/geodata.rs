use std::hint::black_box;

use dae_geodata::{decode_entry_bytes, decode_hex};

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![BenchCase {
        id: "geodata/streaming_geoip_hit",
        default_iters: 100_000,
        run: bench_geodata_streaming_geoip_hit,
    }]
}

fn bench_geodata_streaming_geoip_hit(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture =
        dae_golden::load_json("geodata/streaming/basic.json").map_err(|err| err.to_string())?;
    let geoip =
        decode_hex(fixture["geoip_hex"].as_str().unwrap()).map_err(|err| err.to_string())?;
    Ok(measure(
        || {
            let entry =
                decode_entry_bytes(black_box(&geoip), black_box("cn")).expect("decode geoip entry");
            black_box(entry.len() as u64)
        },
        iters,
        warmup,
    ))
}
