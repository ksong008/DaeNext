use super::*;
#[allow(clippy::too_many_arguments)]
pub(crate) fn vless_fixture_url(
    _ps: &str,
    add: &str,
    port: u16,
    net: &str,
    host: &str,
    path: &str,
    sni: &str,
    flow: &str,
    fingerprint: &str,
) -> String {
    VLESSLink {
        ps: String::new(),
        add: add.to_owned(),
        port: port.to_string(),
        id: fixture_client_id(),
        net: net.to_owned(),
        r#type: "none".to_owned(),
        host: host.to_owned(),
        sni: sni.to_owned(),
        path: path.to_owned(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        tls: "tls".to_owned(),
        flow: flow.to_owned(),
        alpn: String::new(),
        allow_insecure: false,
        fingerprint: fingerprint.to_owned(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(crate) fn vless_vision_fixture_url(fingerprint: &str) -> String {
    vless_vision_fixture_url_with_allow_insecure(fingerprint, false)
}

pub(crate) fn vless_vision_insecure_fixture_url(fingerprint: &str) -> String {
    vless_vision_fixture_url_with_allow_insecure(fingerprint, true)
}

fn vless_vision_fixture_url_with_allow_insecure(fingerprint: &str, allow_insecure: bool) -> String {
    VLESSLink {
        ps: String::new(),
        add: fixture_host(FixtureEndpoint::Primary),
        port: fixture_authority_port().to_string(),
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
        allow_insecure,
        fingerprint: fingerprint.to_owned(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(crate) fn vless_vision_without_flow_fixture_url(fingerprint: &str) -> String {
    vless_fixture_url(
        "",
        &fixture_host(FixtureEndpoint::Primary),
        fixture_authority_port(),
        "tcp",
        "",
        "",
        &fixture_host(FixtureEndpoint::Authority),
        "",
        fingerprint,
    )
}

pub(crate) fn vless_plain_tcp_none_fixture_url() -> String {
    VLESSLink {
        ps: String::new(),
        add: fixture_host(FixtureEndpoint::Primary),
        port: fixture_authority_port().to_string(),
        id: fixture_client_id(),
        net: "tcp".to_owned(),
        r#type: "none".to_owned(),
        host: String::new(),
        sni: String::new(),
        path: String::new(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        tls: "none".to_owned(),
        flow: String::new(),
        alpn: String::new(),
        allow_insecure: false,
        fingerprint: String::new(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(crate) fn vless_vision_empty_fingerprint_fixture_url() -> String {
    let mut url = Url::parse(&vless_vision_fixture_url("")).unwrap();
    url.query_pairs_mut().append_pair("fp", "");
    url.to_string()
}

pub(crate) fn vless_reality_fixture_url() -> String {
    vless_reality_fixture_url_with_allow_insecure(false)
}

pub(crate) fn vless_reality_insecure_fixture_url() -> String {
    vless_reality_fixture_url_with_allow_insecure(true)
}

fn vless_reality_fixture_url_with_allow_insecure(allow_insecure: bool) -> String {
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode([FixtureEndpoint::Authority.slot() as u8; 32]);
    let short_id = [FixtureEndpoint::Primary.slot() as u8; 4]
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    VLESSLink {
        ps: String::new(),
        add: fixture_host(FixtureEndpoint::Primary),
        port: fixture_authority_port().to_string(),
        id: fixture_client_id(),
        net: "tcp".to_owned(),
        r#type: "none".to_owned(),
        host: String::new(),
        sni: fixture_host(FixtureEndpoint::Authority),
        path: String::new(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        tls: "reality".to_owned(),
        flow: "xtls-rprx-vision".to_owned(),
        alpn: "h2,http/1.1".to_owned(),
        allow_insecure,
        fingerprint: String::new(),
        public_key,
        short_id,
        spider_x: "/".to_owned(),
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(crate) fn vless_mux_fixture_url() -> String {
    VLESSLink {
        ps: String::new(),
        add: fixture_host(FixtureEndpoint::Primary),
        port: fixture_authority_port().to_string(),
        id: fixture_client_id(),
        net: "tcp".to_owned(),
        r#type: "none".to_owned(),
        host: String::new(),
        sni: fixture_host(FixtureEndpoint::Authority),
        path: String::new(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        tls: "tls".to_owned(),
        flow: String::new(),
        alpn: "h2,http/1.1".to_owned(),
        allow_insecure: false,
        fingerprint: String::new(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        mux: true,
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(crate) fn vless_xhttp_parser_fixture_url(mode: &str, alpn: &str, extra: &str) -> String {
    VLESSLink {
        ps: String::new(),
        add: fixture_host(FixtureEndpoint::Primary),
        port: fixture_authority_port().to_string(),
        id: fixture_client_id(),
        net: "xhttp".to_owned(),
        r#type: "none".to_owned(),
        host: fixture_host(FixtureEndpoint::Authority),
        sni: fixture_host(FixtureEndpoint::Authority),
        path: "/resource?ed=2048".to_owned(),
        xhttp_mode: mode.to_owned(),
        xhttp_extra: extra.to_owned(),
        tls: "tls".to_owned(),
        flow: String::new(),
        alpn: alpn.to_owned(),
        allow_insecure: false,
        fingerprint: String::new(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        mux: false,
        protocol: "vless".to_owned(),
    }
    .export_url()
}
