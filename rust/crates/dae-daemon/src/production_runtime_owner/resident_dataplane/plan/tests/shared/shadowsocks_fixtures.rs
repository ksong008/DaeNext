use super::*;
pub(crate) fn shadowsocks_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: "password".to_owned(),
        cipher: "aes-128-gcm".to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocks_plugin_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: "password".to_owned(),
        cipher: "aes-128-gcm".to_owned(),
        plugin: Sip003::parse("simple-obfs;obfs=http"),
        udp: false,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocks_simple_obfs_tls_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: "password".to_owned(),
        cipher: "aes-128-gcm".to_owned(),
        plugin: Sip003::parse("simple-obfs;obfs=tls"),
        udp: false,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocks_v2ray_plugin_tls_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    format!(
        "ss://aes-128-gcm:password@{add}:{port}?plugin=v2ray-plugin%3Btls%3Bobfs-host%3Dfront.example%3Bobfs-uri%3D%2Fss"
    )
}

pub(crate) fn shadowsocks_2022_simple_obfs_http_fixture_url(
    _ps: &str,
    add: &str,
    port: u16,
) -> String {
    format!(
        "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@{add}:{port}?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dfront.example%3Bobfs-uri%3D%2F"
    )
}

pub(crate) fn shadowsocks_unsupported_plugin_fixture_url(
    _ps: &str,
    add: &str,
    port: u16,
) -> String {
    format!("ss://aes-128-gcm:password@{add}:{port}?plugin=unknown-plugin")
}
