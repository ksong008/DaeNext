use super::*;
pub(crate) fn trojan_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: "password".to_owned(),
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

pub(crate) fn trojan_websocket_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    TrojanLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: "password".to_owned(),
        sni: "office.example".to_owned(),
        transport_type: "ws".to_owned(),
        encryption: String::new(),
        host: "front.example".to_owned(),
        path: "/trojan".to_owned(),
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
        password: "password".to_owned(),
        sni: "office.example".to_owned(),
        transport_type: "httpupgrade".to_owned(),
        encryption: String::new(),
        host: "front.example".to_owned(),
        path: "/trojan-upgrade".to_owned(),
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
        password: "password".to_owned(),
        sni: "office.example".to_owned(),
        transport_type: "grpc".to_owned(),
        encryption: String::new(),
        host: "front.example".to_owned(),
        path: String::new(),
        service_name: "TrojanGunService".to_owned(),
        allow_insecure: false,
        protocol: "trojan-go".to_owned(),
    }
    .export_url()
}
