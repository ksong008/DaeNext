use super::*;
pub(crate) fn hysteria2_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    hysteria2_fixture_url_with_pin("", &format!("{add}:{port}"), &fixture_pin_sha256())
}

pub(crate) fn hysteria2_fixture_url_with_pin(_ps: &str, server: &str, pin_sha256: &str) -> String {
    Hysteria2Link {
        name: String::new(),
        user: fixture_user(),
        password: String::new(),
        server: server.to_owned(),
        insecure: false,
        sni: fixture_host(FixtureEndpoint::Authority),
        pin_sha256: pin_sha256.to_owned(),
        max_tx: 0,
        max_rx: 0,
    }
    .export_url()
}

pub(crate) fn tuic_fixture_url(_ps: &str, add: &str, port: u16, allow_insecure: bool) -> String {
    TuicLink {
        name: String::new(),
        user: fixture_client_id(),
        password: fixture_secret(),
        server: add.to_owned(),
        port,
        sni: fixture_host(FixtureEndpoint::Authority),
        allow_insecure,
        disable_sni: false,
        congestion_control: String::new(),
        alpn: vec!["h3".to_owned()],
        udp_relay_mode: String::new(),
        protocol: "tuic".to_owned(),
    }
    .export_url()
}

pub(crate) fn juicity_fixture_url(_ps: &str, add: &str, port: u16, allow_insecure: bool) -> String {
    JuicityLink {
        name: String::new(),
        user: fixture_client_id(),
        password: fixture_secret(),
        server: add.to_owned(),
        port,
        sni: fixture_host(FixtureEndpoint::Authority),
        allow_insecure,
        congestion_control: String::new(),
        pinned_certchain_sha256: String::new(),
        protocol: "juicity".to_owned(),
    }
    .export_url()
}
