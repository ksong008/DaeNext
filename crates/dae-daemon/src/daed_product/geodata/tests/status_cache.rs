use super::*;

#[test]
fn geodata_status_follows_per_file_fallback_independently_of_web_root() {
    let root = test_dir("paths");
    let preferred = root.join("override");
    let fallback = root.join("fallback");
    fs::create_dir_all(&preferred).unwrap();
    fs::create_dir_all(&fallback).unwrap();
    write_geoip(&preferred, "override", &[(&[10, 0, 0, 0], 8)]);
    write_geosite(&fallback, "fallback", &["fallback.example"]);
    let mut app = test_app(&root);
    app.web_root = root.join("unrelated/web");
    app.geodata_paths = Arc::new(geodata::ProductGeodataPaths::for_search_directories(
        vec![preferred.clone(), fallback.clone()],
        Some(preferred.clone()),
    ));
    let status = geodata_status(&app).unwrap();
    assert_eq!(status["geoip"]["available"], true);
    assert_eq!(status["geosite"]["available"], true);
    assert_eq!(status["geosite"]["ruleCount"], 1);
    let context = ProductGeodataUpdateContext::from_app(&app);
    use dae_product_control::geodata::GeodataUpdateRuntimeContext;
    assert_eq!(context.directory(GeodataKind::Geosite).unwrap(), preferred);
    write_geosite(&preferred, "override", &["one.example", "two.example"]);
    assert_eq!(geodata_status(&app).unwrap()["geosite"]["ruleCount"], 2);
    fs::remove_file(preferred.join(GEOSITE_FILE)).unwrap();
    assert_eq!(geodata_status(&app).unwrap()["geosite"]["ruleCount"], 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn geodata_environment_override_is_used_by_web_and_runtime_search() {
    const CHILD: &str = "DAED_TEST_GEODATA_PATH_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let dir = PathBuf::from(std::env::var_os("DAE_LOCATION_ASSET").unwrap());
        let mut app = test_app(&dir);
        app.web_root = dir.join("other/web");
        app.geodata_paths = Arc::new(geodata::ProductGeodataPaths::from_environment());
        assert_eq!(app.geodata_paths.read_directory(GeodataKind::Geoip), dir);
        assert_eq!(app.geodata_paths.read_directory(GeodataKind::Geosite), dir);
        assert_eq!(geodata_status(&app).unwrap()["geosite"]["ruleCount"], 2);
        assert_eq!(
            dae_geodata::paths::geodata_asset_dirs("daed", Vec::<PathBuf>::new())[0],
            dir
        );
        return;
    }
    let dir = test_dir("environment");
    write_geoip(&dir, "override", &[(&[10, 0, 0, 0], 8)]);
    write_geosite(&dir, "override", &["one.example", "two.example"]);
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "daed_product::geodata::tests::status_cache::geodata_environment_override_is_used_by_web_and_runtime_search", "--nocapture"])
        .env(CHILD, "1").env("DAE_LOCATION_ASSET", &dir).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
    fs::remove_dir_all(dir).unwrap();
}

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
        shutdown: Arc::new(ProductShutdown::default()),
        runtime: Arc::new(ProductRuntimeManager::new()),
        runtime_sampler: None,
        latency_jobs: Arc::new(LatencyJobManager::default()),
        http_metrics: Arc::new(ProductHttpMetrics::default()),
        ui_runtime: product_ui_runtime(),
        auth_runtime: product_test_auth_runtime(),
        geodata_paths: Arc::new(geodata::ProductGeodataPaths::for_directory(
            dir.to_path_buf(),
        )),
        geodata_updates: Arc::new(ProductGeodataUpdateCoordinator::default()),
        geodata_status_cache: Arc::new(Mutex::new(GeodataStatusCache::default())),
        geodata_update_runtime: None,
        control_runtime: product_test_control_runtime(),
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
