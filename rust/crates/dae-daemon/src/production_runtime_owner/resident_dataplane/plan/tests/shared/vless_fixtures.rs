use super::*;
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
        id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
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
        protocol: "vless".to_owned(),
    }
    .export_url()
}

pub(crate) fn vless_xhttp_parser_fixture_url(mode: &str, alpn: &str, extra: &str) -> String {
    VLESSLink {
        ps: String::new(),
        add: "198.51.100.10".to_owned(),
        port: "443".to_owned(),
        id: "7c12c745-63a5-433d-9e60-022e469b5bd4".to_owned(),
        net: "xhttp".to_owned(),
        r#type: "none".to_owned(),
        host: "edge.transport.invalid".to_owned(),
        sni: "edge.transport.invalid".to_owned(),
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
        protocol: "vless".to_owned(),
    }
    .export_url()
}
