use std::hint::black_box;

use dae_routing::{DomainKey, DomainMatcher, IpPrefix};
use serde_json::Value;

use crate::{BenchCase, Measurement, measure};

pub(crate) fn cases() -> Vec<BenchCase> {
    vec![
        BenchCase {
            id: "routing/prefix_parse",
            default_iters: 100_000,
            run: bench_routing_prefix_parse,
        },
        BenchCase {
            id: "routing/domain_matcher_bitmap",
            default_iters: 100_000,
            run: bench_routing_domain_matcher_bitmap,
        },
    ]
}

fn bench_routing_prefix_parse(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let inputs = ["192.0.2.1", "2001:db8::1", "2001:db8::/48"];
    Ok(measure(
        || {
            let mut checksum = 0_u64;
            for input in black_box(inputs) {
                let prefix = IpPrefix::parse(input).expect("parse prefix");
                checksum ^= prefix.bits() as u64;
            }
            black_box(checksum)
        },
        iters,
        warmup,
    ))
}

fn bench_routing_domain_matcher_bitmap(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let matcher = build_domain_matcher()?;
    Ok(measure(
        || {
            let bitmap = matcher.match_domain_bitmap(black_box("API12.EXAMPLE.NET"));
            black_box(bitmap.iter().fold(0_u64, |acc, value| acc ^ *value as u64))
        },
        iters,
        warmup,
    ))
}

fn build_domain_matcher() -> Result<DomainMatcher, String> {
    let fixture = dae_golden::load_json("routing/domain_matcher/basic_bitmap.json")
        .map_err(|err| err.to_string())?;
    let bit_length = fixture["bit_length"].as_u64().unwrap() as usize;
    let mut matcher = DomainMatcher::new(bit_length);
    for set in fixture["sets"].as_array().unwrap() {
        let bit = set["bit"].as_u64().unwrap() as usize;
        let key =
            DomainKey::try_from(set["key"].as_str().unwrap()).map_err(|err| err.to_string())?;
        matcher
            .add_set(bit, string_array(&set["patterns"]), key)
            .map_err(|err| err.to_string())?;
    }
    Ok(matcher)
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}
