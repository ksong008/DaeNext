use super::*;
pub(crate) fn vmess_fixture_url(
    _ps: &str,
    add: &str,
    port: u16,
    net: &str,
    host: &str,
    path: &str,
    tls: &str,
) -> String {
    vmess_fixture_url_with_sni(add, port, net, host, path, tls, "")
}

pub(crate) fn vmess_fixture_url_with_sni(
    add: &str,
    port: u16,
    net: &str,
    host: &str,
    path: &str,
    tls: &str,
    sni: &str,
) -> String {
    VMessLink {
        ps: String::new(),
        add: add.to_owned(),
        port: port.to_string(),
        id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
        aid: "0".to_owned(),
        net: net.to_owned(),
        r#type: "none".to_owned(),
        host: host.to_owned(),
        sni: sni.to_owned(),
        path: path.to_owned(),
        tls: tls.to_owned(),
        allow_insecure: false,
        fingerprint: String::new(),
        v: "2".to_owned(),
        protocol: "vmess".to_owned(),
    }
    .export_url()
}

pub(crate) fn vmess_legacy_fixture_url() -> String {
    "vmess://YXV0bzowMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWZAMjAzLjAuMTEzLjEwOjI4NDUy?alterId=0&obfs=tcp"
        .to_owned()
}
