use super::*;
pub(crate) fn trojan_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        sni: fixture_host(FixtureEndpoint::Authority),
        alpn: String::new(),
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

pub(crate) fn trojan_insecure_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        sni: fixture_host(FixtureEndpoint::Authority),
        alpn: String::new(),
        transport_type: String::new(),
        encryption: String::new(),
        host: String::new(),
        path: String::new(),
        service_name: String::new(),
        allow_insecure: true,
        protocol: "trojan".to_owned(),
    }
    .export_url()
}

pub(crate) fn trojan_tcp_type_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    format!(
        "trojan://{}@{}:{}?security=tls&sni={}&alpn=h3,h2,http/1.1&type=tcp",
        fixture_secret(),
        add,
        port,
        fixture_host(FixtureEndpoint::Authority)
    )
}

pub(crate) fn trojan_websocket_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        sni: fixture_host(FixtureEndpoint::Authority),
        alpn: String::new(),
        transport_type: "ws".to_owned(),
        encryption: String::new(),
        host: fixture_host(FixtureEndpoint::Authority),
        path: "/resource".to_owned(),
        service_name: String::new(),
        allow_insecure: false,
        protocol: "trojan-go".to_owned(),
    }
    .export_url()
}

pub(crate) fn trojan_httpupgrade_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        sni: fixture_host(FixtureEndpoint::Authority),
        alpn: String::new(),
        transport_type: "httpupgrade".to_owned(),
        encryption: String::new(),
        host: fixture_host(FixtureEndpoint::Authority),
        path: "/resource".to_owned(),
        service_name: String::new(),
        allow_insecure: false,
        protocol: "trojan-go".to_owned(),
    }
    .export_url()
}

pub(crate) fn trojan_grpc_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        sni: fixture_host(FixtureEndpoint::Authority),
        alpn: String::new(),
        transport_type: "grpc".to_owned(),
        encryption: String::new(),
        host: fixture_host(FixtureEndpoint::Authority),
        path: String::new(),
        service_name: "ServiceEndpoint".to_owned(),
        allow_insecure: false,
        protocol: "trojan-go".to_owned(),
    }
    .export_url()
}

pub(crate) fn trojan_inner_shadowsocks_fixture_url(cipher: &str) -> String {
    TrojanLink {
        name: String::new(),
        server: fixture_host(FixtureEndpoint::Primary),
        port: fixture_authority_port(),
        password: fixture_secret(),
        sni: fixture_host(FixtureEndpoint::Authority),
        alpn: String::new(),
        transport_type: "ws".to_owned(),
        encryption: format!("ss;{}:{}", cipher, fixture_secret()),
        host: String::new(),
        path: String::new(),
        service_name: String::new(),
        allow_insecure: false,
        protocol: "trojan-go".to_owned(),
    }
    .export_url()
}
