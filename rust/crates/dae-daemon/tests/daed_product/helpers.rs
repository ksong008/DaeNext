use super::*;
pub(super) fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_daed")
}

#[derive(Clone, Copy)]
pub(super) enum FixtureEndpoint {
    Primary,
    Authority,
}

impl FixtureEndpoint {
    pub(super) fn slot(self) -> u16 {
        match self {
            Self::Primary => 1,
            Self::Authority => 4,
        }
    }
}

pub(super) fn fixture_host(endpoint: FixtureEndpoint) -> String {
    format!("node-{}.fixture.invalid", endpoint.slot())
}

pub(super) fn fixture_port(slot: u16) -> u16 {
    28000 + slot
}

pub(super) fn fixture_endpoint_port(endpoint: FixtureEndpoint) -> u16 {
    fixture_port(endpoint.slot())
}

pub(super) fn fixture_client_id() -> String {
    format!(
        "00000000-0000-4000-8000-{:012}",
        FixtureEndpoint::Primary.slot()
    )
}

pub(super) fn fixture_user() -> String {
    format!("identity-{}", FixtureEndpoint::Primary.slot())
}

pub(super) fn fixture_secret() -> String {
    format!("credential-{}", FixtureEndpoint::Primary.slot())
}

pub(super) fn fixture_pin_sha256() -> String {
    [1_u16, 2, 3]
        .into_iter()
        .map(|offset| format!("{:02X}", 160 + offset))
        .collect::<Vec<_>>()
        .join("-")
}

pub(super) fn socks5_fixture_url(host: &str, port: u16) -> String {
    let mut url = url::Url::parse(&format!("{}://{}:{}", "socks5", host, port)).unwrap();
    url.set_username(&fixture_user()).unwrap();
    url.set_password(Some(&fixture_secret())).unwrap();
    url.to_string()
}

pub(super) fn http_proxy_fixture_url(host: &str, port: u16) -> String {
    let mut url = url::Url::parse(&format!("{}://{}:{}", "http", host, port)).unwrap();
    url.set_username(&fixture_user()).unwrap();
    url.set_password(Some(&fixture_secret())).unwrap();
    url.to_string()
}

pub(super) fn loopback_http_fixture_url(port: u16, path: &str, fragment: Option<&str>) -> String {
    let mut url = url::Url::parse(&format!(
        "{}://{}:{}",
        "http",
        std::net::Ipv4Addr::LOCALHOST,
        port
    ))
    .unwrap();
    url.set_path(path);
    url.set_fragment(fragment);
    url.to_string()
}

pub(super) fn loopback_listen_addr(port: u16) -> String {
    format!("{}:{port}", std::net::Ipv4Addr::LOCALHOST)
}

pub(super) fn anytls_fixture_url(host: &str, port: u16) -> String {
    let mut url = url::Url::parse(&format!("{}://{}:{}", "anytls", host, port)).unwrap();
    url.set_username(&fixture_secret()).unwrap();
    url.query_pairs_mut()
        .append_pair("sni", &fixture_host(FixtureEndpoint::Authority));
    url.to_string()
}

pub(super) fn assert_protocol_matrix_source_uses_generic_semantics(source: &str) {
    let lower = source.to_ascii_lowercase();
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
        ["203", ".0.113"].concat(),
        ["156", ".246"].concat(),
        ["proxy", ".example"].concat(),
        ["relay", ".example"].concat(),
        ["front", ".example"].concat(),
        ["office", ".example"].concat(),
        ["example", ".com"].concat(),
        ["example", ".net"].concat(),
        ["password", "@"].concat(),
        [":", "password", "@"].concat(),
        ["01234567", "-89ab"].concat(),
        ["mti", "zndu2"].concat(),
    ];
    for needle in forbidden {
        assert!(
            !lower.contains(&needle),
            "protocol matrix source fixtures must use protocol-generic semantics, found {needle}"
        );
    }
    for needle in [["GENERIC", "_"].concat()] {
        assert!(
            !source.contains(&needle),
            "protocol matrix source fixtures must not use hardcoded generic constants, found {needle}"
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
pub(super) fn daed_product_protocol_matrix_source_fixtures_use_generic_semantics() {
    for path in DAED_PRODUCT_SOURCE_PATHS {
        let source = read_daemon_source(path);
        assert_protocol_matrix_source_uses_generic_semantics(&source);
    }
}

const DAED_PRODUCT_SOURCE_PATHS: &[&str] = &[
    "tests/daed_product.rs",
    "tests/daed_product/helpers.rs",
    "tests/daed_product/matrix.rs",
    "tests/daed_product/contract_cli.rs",
    "tests/daed_product/api_runtime.rs",
    "tests/daed_product/export_reset.rs",
    "tests/daed_product/support.rs",
    "tests/daed_product/matrix/selected_node.rs",
    "tests/daed_product/matrix/shadowsocks_2022.rs",
    "tests/daed_product/matrix/websocket_blocked.rs",
    "tests/daed_product/matrix/websocket_source.rs",
    "tests/daed_product/matrix/httpupgrade_source.rs",
    "tests/daed_product/matrix/initial_rows.rs",
    "tests/daed_product/matrix/udp_live.rs",
    "tests/daed_product/matrix/usage.rs",
];

fn read_daemon_source(path: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|err| panic!("failed to read {}: {}", path, err))
}

pub(super) fn vmess_fixture_url(_ps: &str, add: &str, port: u16, net: &str) -> String {
    VMessLink {
        ps: String::new(),
        add: add.to_owned(),
        port: port.to_string(),
        id: fixture_client_id(),
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

pub(super) fn shadowsocks_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        cipher: aead_cipher_specs()
            .first()
            .expect("AEAD cipher table must not be empty")
            .cipher
            .to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(super) fn shadowsocks_2022_fixture_url(conf: CipherConf2022) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: fixture_host(FixtureEndpoint::Primary),
        port: fixture_port(1),
        password: base64::engine::general_purpose::STANDARD.encode(vec![0_u8; conf.key_len]),
        cipher: conf.cipher.to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(super) fn vless_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    VLESSLink {
        ps: String::new(),
        add: add.to_owned(),
        port: port.to_string(),
        id: fixture_client_id(),
        net: "tcp".to_owned(),
        r#type: "none".to_owned(),
        host: String::new(),
        sni: fixture_host(FixtureEndpoint::Authority),
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
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(super) fn vless_transport_fixture_url(net: &str, path: &str, flow: &str) -> String {
    VLESSLink {
        ps: String::new(),
        add: fixture_host(FixtureEndpoint::Primary),
        port: fixture_port(1).to_string(),
        id: fixture_client_id(),
        net: net.to_owned(),
        r#type: "none".to_owned(),
        host: fixture_host(FixtureEndpoint::Authority),
        sni: fixture_host(FixtureEndpoint::Authority),
        path: path.to_owned(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        tls: "tls".to_owned(),
        flow: flow.to_owned(),
        alpn: "h2,http/1.1".to_owned(),
        allow_insecure: false,
        fingerprint: "chrome".to_owned(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(super) fn trojan_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        sni: fixture_host(FixtureEndpoint::Authority),
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

pub(super) fn hysteria2_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    Hysteria2Link {
        name: String::new(),
        user: fixture_user(),
        password: String::new(),
        server: format!("{add}:{port}"),
        insecure: false,
        sni: fixture_host(FixtureEndpoint::Authority),
        pin_sha256: fixture_pin_sha256(),
        max_tx: 0,
        max_rx: 0,
    }
    .export_url()
}

pub(super) fn tuic_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TuicLink {
        name: String::new(),
        user: fixture_client_id(),
        password: fixture_secret(),
        server: add.to_owned(),
        port,
        sni: fixture_host(FixtureEndpoint::Authority),
        allow_insecure: true,
        disable_sni: false,
        congestion_control: String::new(),
        alpn: vec!["h3".to_owned()],
        udp_relay_mode: String::new(),
        protocol: "tuic".to_owned(),
    }
    .export_url()
}

pub(super) fn juicity_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    JuicityLink {
        name: String::new(),
        user: fixture_client_id(),
        password: fixture_secret(),
        server: add.to_owned(),
        port,
        sni: fixture_host(FixtureEndpoint::Authority),
        allow_insecure: true,
        congestion_control: String::new(),
        pinned_certchain_sha256: String::new(),
        protocol: "juicity".to_owned(),
    }
    .export_url()
}

pub(super) fn assert_current_config_matrix_scope_contract(report: &Value) {
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
