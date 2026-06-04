use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use dae_config::parser::parse_config;
use dae_config::schema::build_config;
use dae_core_types::OutboundIndex;

use super::maps::{
    resident_outbound_connectivity_entries, resident_user_outbound_ids, runtime_map_name_matches,
};
use super::plan::build_routing_plan_with_asset_dirs;
use super::types::OutboundConnectivityEntry;
use super::*;

static TEST_ASSET_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[test]
fn resident_routing_plan_compiles_lan_proxy_rules() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    dip(156.246.90.2) -> must_direct
    l4proto(tcp) && dport(443) -> proxy
    l4proto(udp) && dport(53) -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    assert!(plan.skipped_rules.is_empty());
    assert_eq!(plan.lpm_sets.len(), 1);
    assert!(
        plan.matches
            .iter()
            .any(|set| set.kind == "IpSet" && set.must)
    );
    assert!(plan.matches.iter().any(|set| set.kind == "L4Proto"));
    assert!(plan.matches.iter().any(|set| set.kind == "Port"));
    assert_eq!(plan.matches.last().unwrap().kind, "Fallback");
    assert_eq!(
        plan.matches.last().unwrap().outbound,
        OutboundIndex::DIRECT.value()
    );
    assert_eq!(
        resident_user_outbound_ids(&config),
        vec![OutboundIndex::USER_DEFINED_MIN.value()]
    );
    assert!(runtime_map_name_matches(
        "outbound_connec",
        OUTBOUND_CONNECTIVITY_MAP_NAME
    ));
}

#[test]
fn resident_routing_plan_compiles_geoip_from_asset() {
    let root = test_asset_root("geoip");
    write_asset(
        &root,
        "test-geoip.dat",
        geoip_list(&[geoip_entry(
            "private",
            &[
                (&[10, 0, 0, 0][..], 8),
                (&[192, 168, 0, 0][..], 16),
                (&[0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..], 7),
            ],
            false,
        )]),
    );
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    dip(ext:'test-geoip:private') -> must_direct
    fallback: proxy
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan_with_asset_dirs(&config, [&root]).unwrap();

    assert!(plan.skipped_rules.is_empty());
    assert_eq!(plan.lpm_sets.len(), 1);
    assert!(
        plan.lpm_sets[0]
            .iter()
            .any(|prefix| { prefix.addr.to_string() == "10.0.0.0" && prefix.bits == 8 })
    );
    assert!(
        plan.lpm_sets[0]
            .iter()
            .any(|prefix| { prefix.addr.to_string() == "192.168.0.0" && prefix.bits == 16 })
    );
    let ip_set = plan
        .matches
        .iter()
        .find(|set| set.kind == "IpSet")
        .expect("geoip private must compile to an IpSet match");
    assert_eq!(ip_set.outbound, OutboundIndex::DIRECT.value());
    assert!(ip_set.must);
    assert_eq!(plan.geodata_report.lookups.len(), 1);
    assert_eq!(plan.geodata_report.lookups[0].kind, "geoip");
    assert_eq!(plan.geodata_report.lookups[0].filename, "test-geoip.dat");
    assert_eq!(plan.geodata_report.lookups[0].code, "private");
    assert_eq!(plan.geodata_report.lookups[0].output_count, 3);
}

#[test]
fn resident_routing_plan_compiles_geosite_attr_from_asset() {
    let root = test_asset_root("geosite");
    write_asset(
        &root,
        "test-geosite.dat",
        geosite_list(&[geosite_entry(
            "sample",
            &[
                (3, "full.example.test", &[][..]),
                (2, "suffix.example.test", &["cn"][..]),
                (0, "keyword-test", &["other"][..]),
                (1, r"^api[0-9]+\.example\.test$", &["cn"][..]),
            ],
        )]),
    );
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    domain(ext:'test-geosite:sample@cn') -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan_with_asset_dirs(&config, [&root]).unwrap();

    assert!(plan.skipped_rules.is_empty());
    assert_eq!(plan.geodata_report.lookups.len(), 1);
    assert_eq!(plan.geodata_report.lookups[0].kind, "geosite");
    assert_eq!(plan.geodata_report.lookups[0].filename, "test-geosite.dat");
    assert_eq!(plan.geodata_report.lookups[0].code, "sample");
    assert_eq!(plan.geodata_report.lookups[0].attr.as_deref(), Some("cn"));
    assert_eq!(plan.geodata_report.lookups[0].output_count, 2);
    assert_eq!(plan.domain_sets.len(), 2);
    assert!(plan.domain_sets.iter().any(|set| {
        set.key == "suffix" && set.values == vec!["suffix.example.test".to_owned()]
    }));
    assert!(plan.domain_sets.iter().any(|set| {
        set.key == "regex" && set.values == vec![r"^api[0-9]+\.example\.test$".to_owned()]
    }));
    assert!(
        !plan
            .domain_sets
            .iter()
            .any(|set| set.values.iter().any(|value| value == "keyword-test"))
    );
}

#[test]
fn resident_routing_geodata_report_records_asset_cache_and_bytes() {
    let root = test_asset_root("geosite-cache");
    write_asset(
        &root,
        "test-geosite.dat",
        geosite_list(&[geosite_entry(
            "sample",
            &[
                (3, "full.example.test", &[][..]),
                (2, "suffix.example.test", &["cn"][..]),
            ],
        )]),
    );
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    domain(ext:'test-geosite:sample') -> proxy
    domain(ext:'test-geosite:sample') -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan_with_asset_dirs(&config, [&root]).unwrap();

    assert_eq!(plan.geodata_report.lookups.len(), 2);
    assert!(!plan.geodata_report.lookups[0].asset_cache_hit);
    assert!(plan.geodata_report.lookups[1].asset_cache_hit);
    assert!(!plan.geodata_report.lookups[0].decoded_entry_cache_hit);
    assert!(plan.geodata_report.lookups[1].decoded_entry_cache_hit);
    assert!(plan.geodata_report.lookups[0].raw_file_bytes > 0);
    assert!(plan.geodata_report.lookups[0].decoded_entry_bytes > 0);
    assert!(plan.geodata_report.lookups[0].expanded_string_bytes > 0);

    let report = super::geodata::geodata_report_json(&plan.geodata_report);
    assert_eq!(report["lookup_count"].as_u64().unwrap(), 2);
    assert_eq!(report["asset_read_count"].as_u64().unwrap(), 1);
    assert_eq!(report["asset_cache_hit_count"].as_u64().unwrap(), 1);
    assert_eq!(report["decoded_entry_cache_hit_count"].as_u64().unwrap(), 1);
    assert!(report["raw_file_bytes_read"].as_u64().unwrap() > 0);
    assert!(report["decoded_entry_bytes_sum"].as_u64().unwrap() > 0);
    assert!(report["expanded_string_bytes_sum"].as_u64().unwrap() > 0);
}

#[test]
fn resident_routing_plan_groups_domain_values_like_go_builder() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    domain(suffix: example.com, suffix: example.org, full: exact.example.net) -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    assert_eq!(plan.domain_sets.len(), 2);
    assert!(plan.domain_sets.iter().any(|set| {
        set.key == "suffix"
            && set.values == vec!["example.com".to_owned(), "example.org".to_owned()]
    }));
    assert!(
        plan.domain_sets
            .iter()
            .any(|set| { set.key == "full" && set.values == vec!["exact.example.net".to_owned()] })
    );
    assert_eq!(
        plan.matches
            .iter()
            .filter(|set| set.kind == "DomainSet")
            .count(),
        plan.domain_sets.len()
    );
}

#[test]
fn resident_userspace_routing_matcher_preserves_group_outbound_indices() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
    openai {
        policy: fixed(0)
    }
}
routing {
    domain(suffix: googleapis.com) -> openai
    fallback: proxy
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let matcher = build_resident_userspace_routing_matcher(&config).unwrap();

    let outcome = matcher
        .match_query_detail(&dae_routing::Query::tcp(
            "142.250.191.170".parse().unwrap(),
            443,
            "www.googleapis.com",
        ))
        .unwrap();
    assert_eq!(outcome.outbound, OutboundIndex(3));
    assert_eq!(outcome.mark, 0);
    assert!(!outcome.must);

    let fallback = matcher
        .match_query(&dae_routing::Query::tcp(
            "93.184.216.34".parse().unwrap(),
            443,
            "example.org",
        ))
        .unwrap();
    assert_eq!(fallback, OutboundIndex(2));
}

#[test]
fn resident_routing_plan_rejects_inverse_geoip_from_asset() {
    let root = test_asset_root("inverse-geoip");
    write_asset(
        &root,
        "inverse-geoip.dat",
        geoip_list(&[geoip_entry("private", &[(&[10, 0, 0, 0][..], 8)], true)]),
    );
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    dip(ext:'inverse-geoip:private') -> direct
    fallback: proxy
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let err = build_routing_plan_with_asset_dirs(&config, [&root]).unwrap_err();

    assert!(err.contains("not support inverse match yet"), "{err}");
}

#[test]
fn resident_routing_plan_compiles_full_function_matrix() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
}
routing {
    sip(198.51.100.0/24) && sport(40000-50000) -> direct
    ip(203.0.113.0/24) && port(443) -> proxy
    l4proto(tcp, udp) -> proxy
    ipversion(4, 6) -> proxy
    mac('aa:bb:cc:dd:ee:ff') -> proxy
    pname(curl) -> proxy
    dscp(46) -> must_rules
    domain(suffix: example.com) -> proxy(mark: 7)
    fallback: block
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan(&config).unwrap();

    assert!(plan.skipped_rules.is_empty());
    for kind in [
        "SourceIpSet",
        "SourcePort",
        "IpSet",
        "Port",
        "L4Proto",
        "IpVersion",
        "Mac",
        "ProcessName",
        "Dscp",
        "DomainSet",
        "Fallback",
    ] {
        assert!(
            plan.matches.iter().any(|set| set.kind == kind),
            "missing resident routing match kind {kind}"
        );
    }
    assert!(plan.lpm_sets.len() >= 3);
    assert!(
        plan.matches
            .iter()
            .any(|set| set.kind == "Dscp" && set.outbound == OutboundIndex::MUST_RULES.value())
    );
    assert!(
        plan.matches
            .iter()
            .any(|set| set.kind == "DomainSet" && set.mark == 7)
    );
    assert_eq!(
        plan.matches.last().unwrap().outbound,
        OutboundIndex::BLOCK.value()
    );
}

#[test]
fn resident_outbound_connectivity_entries_cover_user_groups() {
    let sections = parse_config(
        r#"
global {
    lan_interface: daerust0
}
group {
    proxy {
        policy: fixed(0)
    }
    backup {
        policy: fixed(1)
    }
}
routing {
    l4proto(udp) && dport(19090) -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let entries = resident_outbound_connectivity_entries(&config);
    let first = OutboundIndex::USER_DEFINED_MIN.value();
    let second = first + 1;

    assert_eq!(entries.len(), 12);
    assert!(!entries.iter().any(|entry| {
        entry.outbound == OutboundIndex::DIRECT.value()
            || entry.outbound == OutboundIndex::BLOCK.value()
    }));
    for outbound in [first, second] {
        for l4proto in [
            CONNECTIVITY_L4_TCP,
            CONNECTIVITY_L4_UDP,
            CONNECTIVITY_L4_UDP_GO_LEGACY,
        ] {
            for ipversion in [CONNECTIVITY_IP_VERSION_4, CONNECTIVITY_IP_VERSION_6] {
                assert!(entries.contains(&OutboundConnectivityEntry {
                    outbound,
                    l4proto,
                    ipversion,
                }));
            }
        }
    }
}

fn test_asset_root(name: &str) -> PathBuf {
    let sequence = TEST_ASSET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "dae-resident-routing-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn write_asset(root: &Path, filename: &str, data: Vec<u8>) {
    fs::write(root.join(filename), data).unwrap();
}

fn geoip_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        push_field_bytes(&mut out, 1, entry);
    }
    out
}

fn geoip_entry(code: &str, cidrs: &[(&[u8], u64)], inverse_match: bool) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_string(&mut out, 1, code);
    for (ip, prefix) in cidrs {
        let mut cidr = Vec::new();
        push_field_bytes(&mut cidr, 1, ip);
        push_field_varint(&mut cidr, 2, *prefix);
        push_field_bytes(&mut out, 2, &cidr);
    }
    if inverse_match {
        push_field_varint(&mut out, 3, 1);
    }
    out
}

fn geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        push_field_bytes(&mut out, 1, entry);
    }
    out
}

fn geosite_entry(code: &str, domains: &[(u64, &str, &[&str])]) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_string(&mut out, 1, code);
    for (domain_type, value, attrs) in domains {
        push_field_bytes(&mut out, 2, &domain_entry(*domain_type, value, attrs));
    }
    out
}

fn domain_entry(domain_type: u64, value: &str, attrs: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    push_field_varint(&mut out, 1, domain_type);
    push_field_string(&mut out, 2, value);
    for attr in attrs {
        let mut attribute = Vec::new();
        push_field_string(&mut attribute, 1, attr);
        push_field_bytes(&mut out, 3, &attribute);
    }
    out
}

fn push_field_string(out: &mut Vec<u8>, field: u64, value: &str) {
    push_field_bytes(out, field, value.as_bytes());
}

fn push_field_bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
    push_varint(out, (field << 3) | 2);
    push_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn push_field_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    push_varint(out, field << 3);
    push_varint(out, value);
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
