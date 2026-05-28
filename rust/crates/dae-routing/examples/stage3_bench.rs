use std::hint::black_box;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use dae_geodata::{decode_entry_bytes, decode_hex};
use dae_routing::{DomainKey, DomainMatcher, Query, RoutingMatcher, parse_prefixes_to_strings};
use dae_sniffing::sniff_tcp;
use serde_json::Value;

fn main() {
    let iters = std::env::var("DAE_STAGE3_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(100_000);

    let prefix_fixture =
        dae_golden::load_json("routing/prefix/bare_ip_to_host_prefix.json").unwrap();
    let prefix_inputs: Vec<String> = prefix_fixture["cases"][0]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    bench("routing_prefix_parse", iters, || {
        black_box(parse_prefixes_to_strings(black_box(&prefix_inputs)).unwrap());
    });

    let domain_matcher = build_domain_matcher();
    bench("domain_matcher_bitmap", iters, || {
        black_box(domain_matcher.match_domain_bitmap(black_box("API12.EXAMPLE.NET")));
    });

    let userspace_fixture = dae_golden::load_json("routing/userspace/basic_matcher.json").unwrap();
    let userspace_case = userspace_fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "ip-and-port-or-direct-else-block")
        .unwrap();
    let userspace = RoutingMatcher::from_fixture_value(&userspace_case["matcher"]).unwrap();
    let userspace_query = Query {
        dest: IpAddr::from_str("203.0.113.42").unwrap(),
        dest_port: 443,
        domain: String::new(),
        ..Query::default()
    };
    bench("userspace_ip_port_match", iters, || {
        black_box(userspace.match_query(black_box(&userspace_query)).unwrap());
    });

    let geodata_fixture = dae_golden::load_json("geodata/streaming/basic.json").unwrap();
    let geoip = decode_hex(geodata_fixture["geoip_hex"].as_str().unwrap()).unwrap();
    bench("geodata_streaming_geoip_hit", iters, || {
        black_box(decode_entry_bytes(black_box(&geoip), black_box("cn")).unwrap());
    });

    let sniffing_fixture = dae_golden::load_json("sniffing/basic.json").unwrap();
    let http_hex = sniffing_fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "http-host-normalize-and-retain")
        .unwrap()["input_hex"]
        .as_str()
        .unwrap();
    let http = decode_hex(http_hex).unwrap();
    bench("sniffing_http_host", iters, || {
        black_box(sniff_tcp(black_box(&http)).unwrap());
    });
}

fn build_domain_matcher() -> DomainMatcher {
    let fixture = dae_golden::load_json("routing/domain_matcher/basic_bitmap.json").unwrap();
    let bit_length = fixture["bit_length"].as_u64().unwrap() as usize;
    let mut matcher = DomainMatcher::new(bit_length);
    for set in fixture["sets"].as_array().unwrap() {
        let bit = set["bit"].as_u64().unwrap() as usize;
        let key = DomainKey::try_from(set["key"].as_str().unwrap()).unwrap();
        matcher
            .add_set(bit, string_array(&set["patterns"]), key)
            .unwrap();
    }
    matcher
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
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
