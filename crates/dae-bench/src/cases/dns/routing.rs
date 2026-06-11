use super::*;
pub(super) fn bench_dns_request_routing_match(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let matcher = RequestMatcher::from_fixture_value(&json!({
        "domain_sets": [
            {"bit": 0, "key": "suffix", "patterns": ["example.com"]}
        ],
        "matches": [
            {"type": "domain_set", "upstream": "logical_and"},
            {"type": "qtype", "value": 1, "upstream": "upstream:2"},
            {"type": "fallback", "upstream": "asis"}
        ]
    }))
    .map_err(|err| err.to_string())?;
    Ok(measure(
        || {
            let upstream = matcher
                .match_request(black_box("www.example.com."), black_box(1))
                .expect("dns request routing match");
            black_box(upstream.value() as u64)
        },
        iters,
        warmup,
    ))
}

pub(super) fn bench_dns_response_routing_match(
    iters: u64,
    warmup: u64,
) -> Result<Measurement, String> {
    let matcher = ResponseMatcher::from_fixture_value(&json!({
        "domain_sets": [
            {"bit": 0, "key": "suffix", "patterns": ["example.com"]}
        ],
        "lpm_sets": [
            {"index": 0, "prefixes": ["203.0.113.0/24"]}
        ],
        "matches": [
            {"type": "domain_set", "upstream": "logical_and"},
            {"type": "qtype", "value": 1, "upstream": "logical_and"},
            {"type": "ip_set", "lpm_index": 0, "upstream": "logical_and"},
            {"type": "upstream", "value": 2, "upstream": "accept"},
            {"type": "fallback", "upstream": "reject"}
        ]
    }))
    .map_err(|err| err.to_string())?;
    let ips = ["203.0.113.42".parse().expect("benchmark response ip")];
    Ok(measure(
        || {
            let upstream = matcher
                .match_response(
                    black_box("www.example.com."),
                    black_box(1),
                    black_box(&ips),
                    black_box(DnsRequestOutboundIndex(2)),
                )
                .expect("dns response routing match");
            black_box(upstream.value() as u64 ^ DnsResponseOutboundIndex::ACCEPT.value() as u64)
        },
        iters,
        warmup,
    ))
}
