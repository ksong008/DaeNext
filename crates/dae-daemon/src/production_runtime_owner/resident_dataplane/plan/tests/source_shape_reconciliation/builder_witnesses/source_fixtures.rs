use super::*;

pub(super) fn shadowsocks_2022_source(host: &str, port: u16) -> String {
    let conf = default_shadowsocks_2022_conf();
    ShadowsocksLink {
        name: String::new(),
        server: host.to_owned(),
        port,
        password: psk_for_conf(conf),
        cipher: conf.cipher.to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(super) fn connect_udp_source(
    transport: &str,
    host: &str,
    port: u16,
    authority: &str,
) -> String {
    format!(
        "masque://identity:credential@{host}:{port}?transport={transport}&auth=basic&template=%2F.well-known%2Fmasque%2Fudp%2F%7Btarget_host%7D%2F%7Btarget_port%7D%2F&sni={authority}"
    )
}

pub(super) fn https_transport_source(primary: &str, authority: &str) -> String {
    let mut source = url::Url::parse(&https_proxy_fixture_url(primary, fixture_port(3))).unwrap();
    source
        .query_pairs_mut()
        .append_pair("transport", "1")
        .append_pair("host", authority);
    source.to_string()
}

pub(super) fn native_reality_source() -> String {
    let mut source = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
    source.flow.clear();
    source.export_url()
}

pub(super) fn reality_meek_source() -> String {
    let mut source = VLESSLink::parse(&vless_reality_fixture_url()).unwrap();
    source.net = "meek".to_owned();
    source.flow.clear();
    source.host.clear();
    source.path = "https://meek.fixture.invalid/resource".to_owned();
    source.export_url()
}
