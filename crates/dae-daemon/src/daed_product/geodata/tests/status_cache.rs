use super::*;

#[test]
fn geodata_status_cache_detects_external_file_deletion() {
    let dir = test_dir("delete");
    write_geosite(&dir, "cached", &["cached.example"]);
    write_geoip(&dir, "cached", &[(&[10, 0, 0, 0], 8)]);
    let app = test_app(&dir);

    let first = geodata_status(&app).unwrap();
    assert_eq!(first["geosite"]["ruleCount"], json!(1));
    assert_eq!(first["geoip"]["cidrCount"], json!(1));

    fs::remove_file(dir.join(GEOSITE_FILE)).unwrap();
    fs::remove_file(dir.join(GEOIP_FILE)).unwrap();

    let refreshed = geodata_status(&app).unwrap();
    assert_eq!(refreshed["geosite"]["available"], json!(false));
    assert_eq!(refreshed["geoip"]["available"], json!(false));

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn geodata_status_cache_reuses_unchanged_parsed_values() {
    let dir = test_dir("reuse");
    write_geosite(&dir, "cached", &["cached.example"]);
    write_geoip(&dir, "cached", &[(&[10, 0, 0, 0], 8)]);
    let app = test_app(&dir);

    reset_geodata_status_parse_count();
    let first = geodata_status(&app).unwrap();
    assert_eq!(first["geosite"]["available"], json!(true));
    assert_eq!(first["geoip"]["available"], json!(true));
    assert_eq!(geodata_status_parse_count(), 2);

    let second = geodata_status(&app).unwrap();
    assert_eq!(second, first);
    assert_eq!(geodata_status_parse_count(), 2);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn geodata_status_cache_detects_external_data_and_version_replacement() {
    let dir = test_dir("replace");
    write_geosite(&dir, "initial", &["one.example"]);
    fs::write(
        dir.join(GeodataKind::Geosite.version_file_name()),
        "initial-tag\n",
    )
    .unwrap();
    let app = test_app(&dir);

    let first = geodata_status(&app).unwrap();
    let first_sha = first["geosite"]["sha256"].clone();
    assert_eq!(first["geosite"]["version"], json!("initial-tag"));
    assert_eq!(first["geosite"]["ruleCount"], json!(1));

    fs::write(
        dir.join(GeodataKind::Geosite.version_file_name()),
        "updated-tag\n",
    )
    .unwrap();
    let version_refreshed = geodata_status(&app).unwrap();
    assert_eq!(
        version_refreshed["geosite"]["version"],
        json!("updated-tag")
    );
    assert_eq!(version_refreshed["geosite"]["ruleCount"], json!(1));
    assert_eq!(version_refreshed["geosite"]["sha256"], first_sha);

    let replacement = dir.join("replacement-geosite.dat");
    fs::write(
        &replacement,
        geosite_payload("replacement", &["one.example", "two.example"]),
    )
    .unwrap();
    fs::rename(&replacement, dir.join(GEOSITE_FILE)).unwrap();
    fs::write(
        dir.join(GeodataKind::Geosite.version_file_name()),
        "replacement-tag\n",
    )
    .unwrap();

    let refreshed = geodata_status(&app).unwrap();
    assert_eq!(refreshed["geosite"]["version"], json!("replacement-tag"));
    assert_eq!(refreshed["geosite"]["ruleCount"], json!(2));
    assert_ne!(refreshed["geosite"]["sha256"], first_sha);

    fs::remove_dir_all(dir).unwrap();
}

fn test_dir(suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "daed-product-geodata-status-cache-{suffix}-{}",
        fastrand::u64(..)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_app(dir: &Path) -> AppState {
    AppState {
        config_dir: dir.to_path_buf(),
        state: dir.join("daed.db"),
        web_root: dir.join("web"),
        api_only: true,
        control_socket: dir.join("control.sock"),
        runtime: Arc::new(ProductRuntimeManager::new()),
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        auth_runtime: product_test_auth_runtime(),
        geodata_updates: Arc::new(ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
    }
}

fn write_geosite(dir: &Path, category: &str, domains: &[&str]) {
    fs::write(dir.join(GEOSITE_FILE), geosite_payload(category, domains)).unwrap();
}

fn geosite_payload(category: &str, domains: &[&str]) -> Vec<u8> {
    let mut entry = vec![field_string(1, &format!("geosite:{category}"))];
    entry.extend(
        domains
            .iter()
            .map(|domain| field_message(2, message([field_string(2, domain)]))),
    );
    message([field_message(1, message(entry))])
}

fn write_geoip(dir: &Path, category: &str, cidrs: &[(&[u8], u64)]) {
    let mut entry = vec![field_string(1, &format!("geoip:{category}"))];
    entry.extend(cidrs.iter().map(|(ip, prefix)| {
        field_message(2, message([field_bytes(1, ip), field_varint(2, *prefix)]))
    }));
    fs::write(
        dir.join(GEOIP_FILE),
        message([field_message(1, message(entry))]),
    )
    .unwrap();
}
