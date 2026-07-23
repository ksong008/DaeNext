use std::hint::black_box;

use dae_core_types::OutboundIndex;
use dae_routing::{DomainKey, DomainMatcher, IpPrefix, Query, RoutingMatcher};
use dae_runtime_control::{
    LpmMapTemplate, RoutingNativeFallback, RoutingNativeMatch, RoutingNativeRule,
    build_routing_native_plan,
};
use serde_json::Value;

use crate::{BenchCase, Measurement, measure};

#[path = "routing/prefix_lookup.rs"]
mod prefix_lookup;

pub(crate) fn cases() -> Vec<BenchCase> {
    let mut cases = vec![
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
        BenchCase {
            id: "routing/domain_matcher_bitmap_reuse",
            default_iters: 100_000,
            run: bench_routing_domain_matcher_bitmap_reuse,
        },
        BenchCase {
            id: "routing/userspace_ip_port_match",
            default_iters: 100_000,
            run: bench_routing_userspace_ip_port_match,
        },
        BenchCase {
            id: "routing/userspace_domain_match_reuse",
            default_iters: 100_000,
            run: bench_routing_userspace_domain_match_reuse,
        },
        BenchCase {
            id: "routing/lpm_native_plan_build",
            default_iters: 100_000,
            run: bench_routing_lpm_native_plan_build,
        },
    ];
    cases.extend(prefix_lookup::cases());
    cases
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
            let bitmap = matcher.match_domain_bitmap(black_box("api12.example.net"));
            black_box(bitmap.iter().fold(0_u64, |acc, value| acc ^ *value as u64))
        },
        iters,
        warmup,
    ))
}

fn bench_routing_domain_matcher_bitmap_reuse(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let matcher = build_domain_matcher()?;
    let mut bitmap = vec![0_u32; matcher.bitmap_words()];
    let domain = String::from("api12.example.net");
    Ok(measure(
        || {
            let words = matcher
                .fill_domain_bitmap(black_box(domain.as_str()), black_box(&mut bitmap))
                .expect("domain bitmap");
            black_box(
                bitmap[..words]
                    .iter()
                    .fold(0_u64, |acc, value| acc ^ *value as u64),
            )
        },
        iters,
        warmup,
    ))
}

fn bench_routing_userspace_ip_port_match(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let fixture = dae_golden::load_json("routing/userspace/basic_matcher.json")
        .map_err(|err| err.to_string())?;
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"].as_str() == Some("ip-and-port-or-direct-else-block"))
        })
        .ok_or_else(|| "missing userspace ip/port matcher case".to_owned())?;
    let matcher =
        RoutingMatcher::from_fixture_value(&case["matcher"]).map_err(|err| err.to_string())?;
    let query = Query::tcp("203.0.113.42".parse().expect("benchmark ip"), 443, "");
    Ok(measure(
        || {
            let outcome = matcher
                .match_query_detail(black_box(&query))
                .expect("userspace route match");
            black_box(outcome.outbound.value() as u64 ^ outcome.mark as u64 ^ outcome.must as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_routing_userspace_domain_match_reuse(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let fixture = dae_golden::load_json("routing/userspace/basic_matcher.json")
        .map_err(|err| err.to_string())?;
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"].as_str() == Some("domain-suffix-direct-else-block"))
        })
        .ok_or_else(|| "missing userspace domain matcher case".to_owned())?;
    let matcher =
        RoutingMatcher::from_fixture_value(&case["matcher"]).map_err(|err| err.to_string())?;
    let query = Query::tcp(
        "203.0.113.42".parse().expect("benchmark ip"),
        443,
        "www.example.com",
    );
    let mut bitmap = vec![0_u32; matcher.domain_bitmap_words()];
    Ok(measure(
        || {
            let outcome = matcher
                .match_query_detail_with_bitmap(black_box(&query), black_box(&mut bitmap))
                .expect("userspace domain route match");
            black_box(outcome.outbound.value() as u64 ^ outcome.mark as u64 ^ outcome.must as u64)
        },
        iters,
        warmup,
    ))
}

fn bench_routing_lpm_native_plan_build(iters: u64, warmup: u64) -> Result<Measurement, String> {
    let rules = benchmark_native_plan_rules()?;
    let fallback = RoutingNativeFallback::new(OutboundIndex::DIRECT);
    let template = LpmMapTemplate::default();
    Ok(measure(
        || {
            let plan = build_routing_native_plan(
                black_box(rules.as_slice()),
                black_box(fallback),
                black_box(template),
            )
            .expect("routing native plan");
            black_box(plan.checksum())
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

fn benchmark_native_plan_rules() -> Result<Vec<RoutingNativeRule>, String> {
    Ok(vec![
        RoutingNativeRule::new(
            RoutingNativeMatch::IpSet(vec![
                IpPrefix::parse("203.0.113.0/24").map_err(|err| err.to_string())?,
                IpPrefix::parse("2001:db8::/48").map_err(|err| err.to_string())?,
            ]),
            OutboundIndex::BLOCK,
        ),
        RoutingNativeRule::new(
            RoutingNativeMatch::SourceIpSet(vec![
                IpPrefix::parse("198.51.100.0/24").map_err(|err| err.to_string())?,
                IpPrefix::parse("2001:db8:1::/48").map_err(|err| err.to_string())?,
            ]),
            OutboundIndex::LOGICAL_AND,
        ),
        RoutingNativeRule::new(
            RoutingNativeMatch::Port(vec![(80, 80), (443, 443), (8443, 8443)]),
            OutboundIndex::DIRECT,
        ),
        RoutingNativeRule::new(RoutingNativeMatch::L4Proto(1), OutboundIndex::DIRECT),
        RoutingNativeRule::new(RoutingNativeMatch::IpVersion(1), OutboundIndex::DIRECT),
        RoutingNativeRule::new(
            RoutingNativeMatch::Mac(vec![[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]]),
            OutboundIndex(2),
        )
        .with_flags(false, 0x0800_0000, true),
    ])
}
