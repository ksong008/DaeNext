use super::*;

fn default_aead_cipher() -> &'static str {
    aead_cipher_specs()
        .first()
        .expect("AEAD cipher table must not be empty")
        .cipher
}

pub(crate) fn default_shadowsocks_2022_conf() -> CipherConf2022 {
    *cipher_confs()
        .first()
        .expect("Shadowsocks 2022 cipher table must not be empty")
}

pub(crate) fn psk_for_conf(conf: CipherConf2022) -> String {
    base64::engine::general_purpose::STANDARD.encode(vec![0_u8; conf.key_len])
}

pub(crate) fn shadowsocks_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        cipher: default_aead_cipher().to_owned(),
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
        password: fixture_secret(),
        cipher: default_aead_cipher().to_owned(),
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
        password: fixture_secret(),
        cipher: default_aead_cipher().to_owned(),
        plugin: Sip003::parse("simple-obfs;obfs=tls"),
        udp: false,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocks_v2ray_plugin_tls_fixture_url(_ps: &str, add: &str, port: u16) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        cipher: default_aead_cipher().to_owned(),
        plugin: Sip003::parse(&format!(
            "v2ray-plugin;tls;obfs-host={};obfs-uri=/resource",
            fixture_host(FixtureEndpoint::Authority)
        )),
        udp: false,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocks_2022_simple_obfs_http_fixture_url(
    _ps: &str,
    add: &str,
    port: u16,
) -> String {
    let conf = default_shadowsocks_2022_conf();
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: psk_for_conf(conf),
        cipher: conf.cipher.to_owned(),
        plugin: Sip003::parse(&format!(
            "simple-obfs;obfs=http;obfs-host={};obfs-uri=/",
            fixture_host(FixtureEndpoint::Authority)
        )),
        udp: false,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocks_unsupported_plugin_fixture_url(
    _ps: &str,
    add: &str,
    port: u16,
) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: add.to_owned(),
        port,
        password: fixture_secret(),
        cipher: default_aead_cipher().to_owned(),
        plugin: Sip003::parse("unknown-plugin"),
        udp: false,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocks_2022_fixture_url(conf: CipherConf2022) -> String {
    ShadowsocksLink {
        name: String::new(),
        server: fixture_host(FixtureEndpoint::Primary),
        port: fixture_port(1),
        password: psk_for_conf(conf),
        cipher: conf.cipher.to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

pub(crate) fn shadowsocksr_http_simple_fixture_url(cipher: &str) -> String {
    let password = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fixture_secret());
    format!(
        "{}://{}:{}:origin:{cipher}:http_simple:{password}/?remarks=&protoparam=&obfsparam={}",
        "ssr",
        fixture_host(FixtureEndpoint::Primary),
        fixture_port(1),
        fixture_host(FixtureEndpoint::Authority)
    )
}
