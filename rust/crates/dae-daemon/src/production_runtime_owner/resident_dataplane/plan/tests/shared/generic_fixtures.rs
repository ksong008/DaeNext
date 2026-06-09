use super::*;

#[derive(Clone, Copy)]
pub(crate) enum FixtureEndpoint {
    Primary,
    Secondary,
    Tertiary,
    Authority,
}

impl FixtureEndpoint {
    pub(crate) fn slot(self) -> u16 {
        match self {
            Self::Primary => 1,
            Self::Secondary => 2,
            Self::Tertiary => 3,
            Self::Authority => 4,
        }
    }
}

pub(crate) fn fixture_host(endpoint: FixtureEndpoint) -> String {
    format!("node-{}.fixture.invalid", endpoint.slot())
}

pub(crate) fn fixture_port(slot: u16) -> u16 {
    28000 + slot
}

pub(crate) fn fixture_endpoint_port(endpoint: FixtureEndpoint) -> u16 {
    fixture_port(endpoint.slot())
}

pub(crate) fn fixture_authority_port() -> u16 {
    fixture_endpoint_port(FixtureEndpoint::Authority)
}

pub(crate) fn fixture_client_id() -> String {
    format!(
        "00000000-0000-4000-8000-{:012}",
        FixtureEndpoint::Primary.slot()
    )
}

pub(crate) fn fixture_user() -> String {
    format!("identity-{}", FixtureEndpoint::Primary.slot())
}

pub(crate) fn fixture_secret() -> String {
    format!("credential-{}", FixtureEndpoint::Primary.slot())
}

pub(crate) fn fixture_pin_sha256() -> String {
    // Resident Hysteria2 live admission verifies raw certificate SHA256 as
    // normalized hex, not the base64 pin shape some clients display.
    (0_u8..32)
        .map(|offset| format!("{:02x}", 0xa0_u8.wrapping_add(offset)))
        .collect::<String>()
}

pub(crate) fn socks5_fixture_url(host: &str, port: u16) -> String {
    let mut url = Url::parse(&format!("{}://{}:{}", "socks5", host, port)).unwrap();
    url.set_username(&fixture_user()).unwrap();
    url.set_password(Some(&fixture_secret())).unwrap();
    url.to_string()
}

pub(crate) fn socks5_endpoint_fixture_url(endpoint: FixtureEndpoint) -> String {
    socks5_fixture_url(&fixture_host(endpoint), fixture_endpoint_port(endpoint))
}

pub(crate) fn unsupported_endpoint_fixture_url(endpoint: FixtureEndpoint) -> String {
    Url::parse(&format!(
        "{}://{}:{}",
        "wireguard",
        fixture_host(endpoint),
        fixture_endpoint_port(endpoint)
    ))
    .unwrap()
    .to_string()
}

pub(crate) fn tcp_check_fixture_url(
    scheme: HttpScheme,
    endpoint: FixtureEndpoint,
    path: &str,
    dial_target: Option<&str>,
) -> String {
    let scheme = match scheme {
        HttpScheme::Http => "http",
        HttpScheme::Https => "https",
    };
    let mut url = Url::parse(&format!("{}://{}", scheme, fixture_host(endpoint))).unwrap();
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    url.set_path(path);
    if !query.is_empty() {
        url.set_query(Some(query));
    }
    let url = url.to_string();
    match dial_target {
        Some(target) => format!("{url},{target}"),
        None => url,
    }
}

pub(crate) fn http_proxy_fixture_url(host: &str, port: u16) -> String {
    http_proxy_url(HttpScheme::Http, host, port, false, "")
}

pub(crate) fn https_proxy_fixture_url(host: &str, port: u16) -> String {
    http_proxy_url(HttpScheme::Https, host, port, false, "")
}

pub(crate) fn https_proxy_insecure_fixture_url(host: &str, port: u16) -> String {
    http_proxy_url(HttpScheme::Https, host, port, true, "")
}

pub(crate) fn https_proxy_utls_fixture_url(host: &str, port: u16) -> String {
    http_proxy_url(HttpScheme::Https, host, port, false, "chrome")
}

pub(crate) fn http_transport_fixture_url(host: &str, port: u16) -> String {
    let mut url = Url::parse(&format!("{}://{}:{}/{}", "http", host, port, "resource")).unwrap();
    url.set_username(&fixture_user()).unwrap();
    url.set_password(Some(&fixture_secret())).unwrap();
    url.query_pairs_mut()
        .append_pair("transport", "1")
        .append_pair("host", &fixture_host(FixtureEndpoint::Authority));
    url.to_string()
}

pub(crate) fn anytls_fixture_url(host: &str, port: u16) -> String {
    anytls_url(host, port, false)
}

pub(crate) fn anytls_insecure_fixture_url(host: &str, port: u16) -> String {
    anytls_url(host, port, true)
}

pub(crate) fn two_node_chain_fixture_url() -> String {
    format!(
        "{} -> {}",
        socks5_fixture_url(
            &fixture_host(FixtureEndpoint::Primary),
            fixture_port(FixtureEndpoint::Primary.slot())
        ),
        http_proxy_fixture_url(
            &fixture_host(FixtureEndpoint::Secondary),
            fixture_port(FixtureEndpoint::Secondary.slot())
        )
    )
}

pub(crate) fn too_deep_chain_fixture_url() -> String {
    format!(
        "{} -> {} -> {}",
        socks5_fixture_url(
            &fixture_host(FixtureEndpoint::Primary),
            fixture_port(FixtureEndpoint::Primary.slot())
        ),
        http_proxy_fixture_url(
            &fixture_host(FixtureEndpoint::Secondary),
            fixture_port(FixtureEndpoint::Secondary.slot())
        ),
        http_proxy_fixture_url(
            &fixture_host(FixtureEndpoint::Tertiary),
            fixture_port(FixtureEndpoint::Tertiary.slot())
        )
    )
}

pub(crate) fn fixture_hop_server(port: u16, extra_ports: &str) -> String {
    format!(
        "{}:{port}{extra_ports}",
        fixture_host(FixtureEndpoint::Primary)
    )
}

fn http_proxy_url(
    protocol: HttpScheme,
    host: &str,
    port: u16,
    allow_insecure: bool,
    utls_imitate: &str,
) -> String {
    let mut link = HttpProxyLink {
        name: String::new(),
        server: host.to_owned(),
        port,
        username: fixture_user(),
        password: fixture_secret(),
        sni: String::new(),
        protocol,
        allow_insecure,
        host: String::new(),
        path: "/".to_owned(),
        transport: false,
        tls_implementation: "tls".to_owned(),
        alpn: "h2,http/1.1".to_owned(),
        utls_imitate: utls_imitate.to_owned(),
    }
    .export_url();
    if !utls_imitate.is_empty() {
        let separator = if link.contains('?') { '&' } else { '?' };
        link.push(separator);
        link.push_str("utlsImitate=");
        link.push_str(utls_imitate);
    }
    link
}

fn anytls_url(host: &str, port: u16, insecure: bool) -> String {
    let mut url = Url::parse(&format!("{}://{}:{}", "anytls", host, port)).unwrap();
    url.set_username(&fixture_secret()).unwrap();
    {
        let mut query = url.query_pairs_mut();
        if insecure {
            query.append_pair("insecure", "1");
        }
        query.append_pair("sni", host);
    }
    url.to_string()
}
