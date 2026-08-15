use super::super::plan::{
    build_routing_plan_with_asset_dirs, build_routing_plan_with_geodata_resolver,
};
use super::super::{ResidentGeodataStore, build_resident_userspace_routing_matcher_with_geodata};
use super::*;
use dae_resident_dataplane::facade::geodata_report_json;
use dae_routing::DomainKey;
#[test]
pub(super) fn resident_routing_plan_compiles_geoip_from_asset() {
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
            .any(|prefix| prefix.addr().to_string() == "10.0.0.0" && prefix.bits() == 8)
    );
    assert!(
        plan.lpm_sets[0]
            .iter()
            .any(|prefix| prefix.addr().to_string() == "192.168.0.0" && prefix.bits() == 16)
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
pub(super) fn resident_routing_plan_compiles_geoip_and_ext_as_plain_ip_sets() {
    let root = test_asset_root("geoip-and-ext");
    write_asset(
        &root,
        "geoip.dat",
        geoip_list(&[geoip_entry(
            "private",
            &[(&[10, 0, 0, 0][..], 8), (&[172, 16, 0, 0][..], 12)],
            false,
        )]),
    );
    write_asset(
        &root,
        "custom-geoip.dat",
        geoip_list(&[geoip_entry(
            "regional",
            &[(&[203, 0, 113, 0][..], 24)],
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
    ip(geoip:private) -> proxy
    dip(ext:'custom-geoip:regional') -> direct
    fallback: block
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let plan = build_routing_plan_with_asset_dirs(&config, [&root]).unwrap();

    assert!(plan.skipped_rules.is_empty());
    assert_eq!(plan.geodata_report.lookups.len(), 2);
    assert_eq!(plan.geodata_report.lookups[0].kind, "geoip");
    assert_eq!(plan.geodata_report.lookups[0].filename, "geoip.dat");
    assert_eq!(plan.geodata_report.lookups[0].code, "private");
    assert_eq!(plan.geodata_report.lookups[0].output_count, 2);
    assert_eq!(plan.geodata_report.lookups[1].kind, "geoip");
    assert_eq!(plan.geodata_report.lookups[1].filename, "custom-geoip.dat");
    assert_eq!(plan.geodata_report.lookups[1].code, "regional");
    assert_eq!(plan.geodata_report.lookups[1].output_count, 1);
    assert_eq!(plan.lpm_sets.len(), 2);
    assert!(plan.lpm_sets.iter().any(|set| {
        set.iter()
            .any(|prefix| prefix.addr().to_string() == "10.0.0.0" && prefix.bits() == 8)
            && set
                .iter()
                .any(|prefix| prefix.addr().to_string() == "172.16.0.0" && prefix.bits() == 12)
    }));
    assert!(plan.lpm_sets.iter().any(|set| {
        set.iter()
            .any(|prefix| prefix.addr().to_string() == "203.0.113.0" && prefix.bits() == 24)
    }));
}

#[test]
pub(super) fn resident_routing_plan_compiles_geosite_attr_from_asset() {
    let root = test_asset_root("geosite");
    write_asset(
        &root,
        "test-geosite.dat",
        geosite_list(&[geosite_entry(
            "sample",
            &[
                (3, "full.fixture.invalid.test", &[][..]),
                (2, "suffix.fixture.invalid.test", &["cn"][..]),
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
        domain_set_matches(set, DomainKey::Suffix, &["suffix.fixture.invalid.test"])
    }));
    assert!(plan.domain_sets.iter().any(|set| {
        domain_set_matches(set, DomainKey::Regex, &[r"^api[0-9]+\.example\.test$"])
    }));
    assert!(!plan.domain_sets.iter().any(|set| {
        set.values
            .patterns()
            .iter()
            .any(|value| value == "keyword-test")
    }));
}

#[test]
pub(super) fn resident_routing_plan_compiles_geosite_types_and_attr_case() {
    let root = test_asset_root("geosite-types-attr");
    write_asset(
        &root,
        "geosite.dat",
        geosite_list(&[geosite_entry(
            "Regional",
            &[
                (3, "full.fixture.invalid.test", &["CN"][..]),
                (2, "suffix.fixture.invalid.test", &["cn"][..]),
                (0, "keyword-test", &["Cn"][..]),
                (1, r"^api[0-9]+\.fixture\.invalid\.test$", &["cN"][..]),
                (3, "other.fixture.invalid.test", &["other"][..]),
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
    domain(geosite:regional@cn) -> proxy
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
    assert_eq!(plan.geodata_report.lookups[0].filename, "geosite.dat");
    assert_eq!(plan.geodata_report.lookups[0].code, "regional");
    assert_eq!(plan.geodata_report.lookups[0].attr.as_deref(), Some("cn"));
    assert_eq!(plan.geodata_report.lookups[0].output_count, 4);
    assert_eq!(plan.domain_sets.len(), 4);
    assert!(
        plan.domain_sets.iter().any(|set| {
            domain_set_matches(set, DomainKey::Full, &["full.fixture.invalid.test"])
        })
    );
    assert!(plan.domain_sets.iter().any(|set| {
        domain_set_matches(set, DomainKey::Suffix, &["suffix.fixture.invalid.test"])
    }));
    assert!(
        plan.domain_sets
            .iter()
            .any(|set| { domain_set_matches(set, DomainKey::Keyword, &["keyword-test"]) })
    );
    assert!(plan.domain_sets.iter().any(|set| {
        domain_set_matches(
            set,
            DomainKey::Regex,
            &[r"^api[0-9]+\.fixture\.invalid\.test$"],
        )
    }));
    assert!(!plan.domain_sets.iter().any(|set| {
        set.values
            .patterns()
            .iter()
            .any(|value| value == "other.fixture.invalid.test")
    }));
}

fn domain_set_matches(
    set: &super::super::types::ResidentDomainSet,
    key: DomainKey,
    values: &[&str],
) -> bool {
    set.values.key() == key
        && set
            .values
            .patterns()
            .iter()
            .map(String::as_str)
            .eq(values.iter().copied())
}

#[test]
pub(super) fn resident_routing_geodata_report_records_asset_cache_and_bytes() {
    let root = test_asset_root("geosite-cache");
    write_asset(
        &root,
        "test-geosite.dat",
        geosite_list(&[geosite_entry(
            "sample",
            &[
                (3, "full.fixture.invalid.test", &[][..]),
                (2, "suffix.fixture.invalid.test", &["cn"][..]),
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

    let report = geodata_report_json(&plan.geodata_report);
    assert_eq!(report["lookup_count"].as_u64().unwrap(), 2);
    assert_eq!(report["asset_read_count"].as_u64().unwrap(), 1);
    assert_eq!(report["asset_cache_hit_count"].as_u64().unwrap(), 1);
    assert_eq!(report["decoded_entry_cache_hit_count"].as_u64().unwrap(), 1);
    assert!(report["raw_file_bytes_read"].as_u64().unwrap() > 0);
    assert!(report["decoded_entry_bytes_sum"].as_u64().unwrap() > 0);
    assert!(report["expanded_string_bytes_sum"].as_u64().unwrap() > 0);
}

#[test]
pub(super) fn resident_routing_geosite_shared_sets_are_generic_across_consumers() {
    let root = test_asset_root("shared-geosite-generic");
    write_asset(
        &root,
        "test-geosite.dat",
        geosite_list(&[geosite_entry(
            "streaming",
            &[(2, "media.example.test", &[][..])],
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
    domain(ext:'test-geosite:streaming') -> proxy
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let geodata = ResidentGeodataStore::new([root.clone()]);

    let plan = build_routing_plan_with_geodata_resolver(&config, &geodata).unwrap();
    assert_eq!(plan.domain_sets.len(), 1);
    assert_eq!(geodata.shared_domain_set_count(), 1);

    let next_geodata = ResidentGeodataStore::new([root]);
    let next_plan = build_routing_plan_with_geodata_resolver(&config, &next_geodata).unwrap();
    assert!(
        plan.domain_sets[0]
            .values
            .ptr_eq(&next_plan.domain_sets[0].values)
    );

    let matcher = build_resident_userspace_routing_matcher_with_geodata(&config, &geodata).unwrap();
    assert_eq!(geodata.shared_domain_set_count(), 1);
    assert_eq!(
        matcher
            .match_query(&dae_routing::Query::tcp(
                "203.0.113.1".parse().unwrap(),
                443,
                "www.media.example.test",
            ))
            .unwrap(),
        OutboundIndex(2),
    );
}

#[test]
pub(super) fn resident_routing_regex_sets_scope_thread_caches_to_one_generation() {
    let patterns = (0..40)
        .map(|index| format!(r"^service-{index}\.example\.test$"))
        .collect::<Vec<_>>();
    let first_generation = ResidentGeodataStore::new(Vec::<std::path::PathBuf>::new());
    let first = first_generation
        .shared_domain_set_for_test("regex", patterns.clone())
        .unwrap();
    let first_again = first_generation
        .shared_domain_set_for_test("regex", patterns.clone())
        .unwrap();
    assert!(first.ptr_eq(&first_again));

    let next_generation = ResidentGeodataStore::new(Vec::<std::path::PathBuf>::new());
    let next = next_generation
        .shared_domain_set_for_test("regex", patterns)
        .unwrap();
    assert!(!first.ptr_eq(&next));
}

#[test]
pub(super) fn resident_routing_geoip_shared_prefix_sets_are_generic() {
    let root = test_asset_root("shared-geoip-generic");
    write_asset(
        &root,
        "test-geoip.dat",
        geoip_list(&[geoip_entry(
            "streaming",
            &[(&[203, 0, 113, 0][..], 24)],
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
    dip(ext:'test-geoip:streaming') -> proxy
    ip(ext:'test-geoip:streaming') -> direct
    fallback: direct
}
"#,
    )
    .unwrap();
    let config = build_config(&sections).unwrap();
    let geodata = ResidentGeodataStore::new([root.clone()]);
    let plan = build_routing_plan_with_geodata_resolver(&config, &geodata).unwrap();

    assert_eq!(plan.lpm_sets.len(), 2);
    assert_eq!(geodata.shared_prefix_set_count(), 1);

    let next_geodata = ResidentGeodataStore::new([root]);
    let next_plan = build_routing_plan_with_geodata_resolver(&config, &next_geodata).unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &plan.lpm_sets[0],
        &next_plan.lpm_sets[0]
    ));
}

#[test]
pub(super) fn resident_routing_plan_rejects_inverse_geoip_from_asset() {
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
