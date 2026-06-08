fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_daed")
}

fn assert_protocol_matrix_source_uses_generic_semantics(source: &str) {
    let forbidden = [
        ["matrix", "-", "socks"].concat(),
        ["matrix", "-", "http"].concat(),
        ["matrix", "-", "ss"].concat(),
        ["matrix", "-", "shadowsocks"].concat(),
        ["matrix", "-", "trojan"].concat(),
        ["matrix", "-", "vmess"].concat(),
        ["matrix", "-", "vless"].concat(),
        ["matrix", "-", "anytls"].concat(),
        ["matrix", "-", "hy2"].concat(),
        ["matrix", "-", "hysteria"].concat(),
        ["matrix", "-", "tuic"].concat(),
        ["matrix", "-", "juicity"].concat(),
        ["matrix", "-", "socks", "-", "pass"].concat(),
        ["matrix", "-", "http", "-", "pass"].concat(),
        ["matrix", "-", "ss", "-", "pass"].concat(),
        ["matrix", "-", "trojan", "-", "pass"].concat(),
        ["matrix", "-", "anytls", "-", "pass"].concat(),
        ["matrix", "-", "hy2", "-", "auth"].concat(),
        ["matrix", "-", "tuic", "-", "pass"].concat(),
        ["matrix", "-", "juicity", "-", "pass"].concat(),
        ["socks5://", "matrix"].concat(),
        ["http://", "matrix"].concat(),
        ["trojan-go://", "matrix"].concat(),
        ["anytls://", "matrix"].concat(),
        ["/", "matrix", "-"].concat(),
        ["#", "matrix", "-"].concat(),
        ["tag=", "matrix", "-"].concat(),
        ["name=", "matrix", "-"].concat(),
    ];
    for needle in forbidden {
        assert!(
            !source.contains(&needle),
            "protocol matrix source fixtures must use protocol-generic semantics, found {needle}"
        );
    }
    for digit in '0'..='9' {
        let needle = format!("{}{}", "stage", digit);
        assert!(
            !source.contains(&needle),
            "protocol matrix source fixtures must not use staged semantics, found {needle}"
        );
    }
    for needle in [["#", "stage"].concat(), ["stage", "-"].concat()] {
        assert!(
            !source.contains(&needle),
            "protocol matrix source fixtures must not use staged semantics, found {needle}"
        );
    }
}

#[test]
fn daed_product_protocol_matrix_source_fixtures_use_generic_semantics() {
    for source in [
        include_str!("../daed_product.rs"),
        include_str!("helpers.rs"),
        include_str!("matrix.rs"),
        include_str!("contract_cli.rs"),
        include_str!("api_runtime.rs"),
        include_str!("export_reset.rs"),
        include_str!("support.rs"),
    ] {
        assert_protocol_matrix_source_uses_generic_semantics(source);
    }
}

fn vmess_fixture_url(ps: &str, add: &str, port: u16, net: &str) -> String {
    VMessLink {
        ps: ps.to_owned(),
        add: add.to_owned(),
        port: port.to_string(),
        id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        aid: "0".to_owned(),
        net: net.to_owned(),
        r#type: "none".to_owned(),
        host: String::new(),
        sni: String::new(),
        path: String::new(),
        tls: String::new(),
        allow_insecure: false,
        fingerprint: String::new(),
        v: "2".to_owned(),
        protocol: "vmess".to_owned(),
    }
    .export_url()
}

fn shadowsocks_fixture_url(ps: &str, add: &str, port: u16) -> String {
    ShadowsocksLink {
        name: ps.to_owned(),
        server: add.to_owned(),
        port,
        password: "ss-password".to_owned(),
        cipher: "aes-128-gcm".to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

fn vless_fixture_url(ps: &str, add: &str, port: u16) -> String {
    VLESSLink {
        ps: ps.to_owned(),
        add: add.to_owned(),
        port: port.to_string(),
        id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        net: "tcp".to_owned(),
        r#type: "none".to_owned(),
        host: String::new(),
        sni: "office.example".to_owned(),
        path: String::new(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        tls: "tls".to_owned(),
        flow: "xtls-rprx-vision".to_owned(),
        alpn: "h2,http/1.1".to_owned(),
        allow_insecure: false,
        fingerprint: "chrome".to_owned(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        protocol: "vless".to_owned(),
    }
    .export_url()
}

fn trojan_fixture_url(ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: ps.to_owned(),
        server: add.to_owned(),
        port,
        password: "trojan-password".to_owned(),
        sni: "office.example".to_owned(),
        transport_type: String::new(),
        encryption: String::new(),
        host: String::new(),
        path: String::new(),
        service_name: String::new(),
        allow_insecure: false,
        protocol: "trojan".to_owned(),
    }
    .export_url()
}

fn hysteria2_fixture_url(ps: &str, add: &str, port: u16) -> String {
    Hysteria2Link {
        name: ps.to_owned(),
        user: "hy2-auth".to_owned(),
        password: String::new(),
        server: format!("{add}:{port}"),
        insecure: false,
        sni: "office.example".to_owned(),
        pin_sha256: "AA-BB-CC".to_owned(),
        max_tx: 0,
        max_rx: 0,
    }
    .export_url()
}

fn tuic_fixture_url(ps: &str, add: &str, port: u16) -> String {
    TuicLink {
        name: ps.to_owned(),
        user: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        password: "tuic-password".to_owned(),
        server: add.to_owned(),
        port,
        sni: "office.example".to_owned(),
        allow_insecure: true,
        disable_sni: false,
        congestion_control: String::new(),
        alpn: vec!["h3".to_owned()],
        udp_relay_mode: String::new(),
        protocol: "tuic".to_owned(),
    }
    .export_url()
}

fn juicity_fixture_url(ps: &str, add: &str, port: u16) -> String {
    JuicityLink {
        name: ps.to_owned(),
        user: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        password: "juicity-password".to_owned(),
        server: add.to_owned(),
        port,
        sni: "office.example".to_owned(),
        allow_insecure: true,
        congestion_control: String::new(),
        pinned_certchain_sha256: String::new(),
        protocol: "juicity".to_owned(),
    }
    .export_url()
}

fn assert_current_config_matrix_scope_contract(report: &Value) {
    assert_eq!(
        report["matrix_scope"].as_str().unwrap(),
        "current-config-formal-handler-matrix"
    );
    assert!(report["current_config_matrix_open"].as_bool().unwrap());
    assert!(report["current_admitted_baseline_open"].as_bool().unwrap());
    assert!(report["source_shape_registry_open"].as_bool().unwrap());
    assert!(report["expanded_source_matrix_open"].as_bool().unwrap());
    assert!(!report["expanded_source_matrix_complete"].as_bool().unwrap());
    assert_eq!(
        report["full_matrix_scope"].as_str().unwrap(),
        "current-config-formal-handler-matrix"
    );
    assert!(
        !report["full_matrix_is_expanded_source_matrix"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["full_matrix_release_gate_source_ready"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !report["full_matrix_c10_expanded_source_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        report["source_matrix_completion_blocker"].as_str().unwrap(),
        "expanded source matrix has fail-closed rows and requires live host, benchmark, and rollback evidence"
    );
    assert!(
        report["source_shape_registry_row_count"].as_u64().unwrap() >= 20,
        "{report}"
    );
    assert!(
        report["expanded_source_matrix_row_count"].as_u64().unwrap() >= 20,
        "{report}"
    );

    let contract = &report["matrix_scope_contract"];
    assert_eq!(contract["schemaVersion"].as_u64().unwrap(), 1);
    assert_eq!(
        contract["scope"].as_str().unwrap(),
        "current-config-formal-handler-matrix"
    );
    assert!(contract["currentConfigMatrixOpen"].as_bool().unwrap());
    assert!(contract["currentAdmittedBaselineOpen"].as_bool().unwrap());
    assert!(contract["sourceShapeRegistryOpen"].as_bool().unwrap());
    assert!(contract["expandedSourceMatrixOpen"].as_bool().unwrap());
    assert!(!contract["expandedSourceMatrixComplete"].as_bool().unwrap());
    assert!(
        !contract["releaseGateMayUseAsSourceMatrix"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !contract["c10MayUseAsExpandedSourceMatrix"]
            .as_bool()
            .unwrap()
    );
    let status_counts = &report["expanded_source_matrix_status_counts"];
    assert!(status_counts["blocked"].as_u64().unwrap() >= 1);
    assert!(status_counts["not-source-supported"].as_u64().unwrap() >= 1);
    assert!(
        status_counts["admitted"].as_u64().unwrap_or(0) >= 1
            || status_counts["not-present"].as_u64().unwrap_or(0) >= 1
    );
}
