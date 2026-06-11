use std::collections::BTreeSet;

const REQUIRED_HOT_PATH_CASES: &[&str] = &[
    "protocol/shadowsocks_metadata_bytes",
    "protocol/shadowsocks_ss2022_psk_split",
    "protocol/vmess_metadata_bytes",
    "protocol/vmess_packet_addr_payload",
    "protocol/vless_request_header",
    "protocol/vless_xudp_first_write",
    "protocol/socks5_udp_packet_wrap",
    "protocol/trojan_udp_packet",
    "protocol/anytls_frame",
    "dns/request_cache_hit_packet_view",
    "dns/response_cache_plan_packet_view",
    "dns/request_routing_match",
    "dns/response_routing_match",
    "routing/domain_matcher_bitmap_reuse",
    "routing/userspace_domain_match_reuse",
    "routing/lpm_native_plan_build",
];

#[test]
fn required_hot_path_bench_cases_are_registered() {
    let ids: BTreeSet<_> = super::bench_cases()
        .into_iter()
        .map(|case| case.id)
        .collect();
    let missing: Vec<_> = REQUIRED_HOT_PATH_CASES
        .iter()
        .copied()
        .filter(|id| !ids.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "missing required hot-path benchmark cases: {missing:?}"
    );
}

#[test]
fn bench_case_ids_are_unique() {
    let mut ids = BTreeSet::new();
    let mut duplicates = Vec::new();
    for case in super::bench_cases() {
        if !ids.insert(case.id) {
            duplicates.push(case.id);
        }
    }
    assert!(
        duplicates.is_empty(),
        "duplicate benchmark case ids: {duplicates:?}"
    );
}
