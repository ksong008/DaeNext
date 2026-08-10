use base64::Engine;
use dae_outbound::{
    FLOW_STREAM_ASSOCIATION_OWNERSHIP, FLOW_STREAM_PACKET_OWNERSHIP,
    FLOW_STREAM_POLICY_CLOSED_OWNERSHIP, GENERATION_OWNED_H2_PACKET_OWNERSHIP,
    GENERATION_OWNED_H2_POLICY_CLOSED_OWNERSHIP, GENERATION_OWNED_MEEK_OWNERSHIP,
    GENERATION_OWNED_VLESS_MUX_OWNERSHIP, GENERATION_OWNED_XHTTP_OWNERSHIP, ShadowsocksLink,
    Sip003, TrojanLink, VLESSLink, VMessLink,
};

use super::*;

const TEST_CLIENT_ID: &str = "00000000-0000-4000-8000-000000000001";

#[test]
fn admitted_policy_closed_plans_keep_their_explicit_tcp_owner() {
    for link in [
        vless_link("meek", "tls", "", "https://meek.example.test/resource").export_url(),
        vless_reality_link("meek", "", "https://meek.example.test/resource").export_url(),
    ] {
        let proxy = build_proxy(link).unwrap();
        assert!(proxy.execution_plan().udp.policy_closed());
        assert_eq!(
            materialized_runtime_ownership(proxy.execution_plan()),
            GENERATION_OWNED_MEEK_OWNERSHIP,
            "{}",
            proxy.protocol
        );
    }

    let mux = build_proxy(vless_mux_link().export_url()).unwrap();
    assert!(mux.execution_plan().udp.policy_closed());
    assert_eq!(
        materialized_runtime_ownership(mux.execution_plan()),
        GENERATION_OWNED_VLESS_MUX_OWNERSHIP
    );

    let vmess_h2 = build_proxy(vmess_link("h2", "tls").export_url()).unwrap();
    assert!(vmess_h2.execution_plan().udp.policy_closed());
    assert_eq!(
        materialized_runtime_ownership(vmess_h2.execution_plan()),
        GENERATION_OWNED_H2_POLICY_CLOSED_OWNERSHIP
    );

    for link in [
        trojan_inner_link().export_url(),
        shadowsocks_plugin_link(),
        shadowsocksr_link(),
        "http://user:password@127.0.0.1:8080/".to_owned(),
        "http://user:password@127.0.0.1:8080/resource?transport=1&host=transport.example.test"
            .to_owned(),
        "https://user:password@127.0.0.1:8443/".to_owned(),
        "https://user:password@127.0.0.1:8443/resource?transport=1&host=transport.example.test&alpn=http%2F1.1"
            .to_owned(),
    ] {
        let proxy = build_proxy(link).unwrap();
        assert!(proxy.execution_plan().udp.policy_closed());
        assert_eq!(
            materialized_runtime_ownership(proxy.execution_plan()),
            FLOW_STREAM_POLICY_CLOSED_OWNERSHIP,
            "{}",
            proxy.protocol
        );
    }
}

#[test]
fn admitted_vless_h2_and_xhttp_versions_map_to_their_real_profiles() {
    let h2 = build_proxy(vless_link("h2", "tls", "h2", "/h2").export_url()).unwrap();
    assert_eq!(
        materialized_runtime_ownership(h2.execution_plan()),
        GENERATION_OWNED_H2_PACKET_OWNERSHIP
    );

    for alpn in ["http/1.1", "h2", "h3"] {
        let proxy = build_proxy(vless_link("xhttp", "tls", alpn, "/xhttp").export_url())
            .unwrap_or_else(|error| panic!("admit xHTTP {alpn}: {error}"));
        assert_eq!(
            materialized_runtime_ownership(proxy.execution_plan()),
            GENERATION_OWNED_XHTTP_OWNERSHIP,
            "{alpn}"
        );
    }

    let reality_h2 = build_proxy(vless_xhttp_reality_h2_link().export_url()).unwrap();
    assert_eq!(
        materialized_runtime_ownership(reality_h2.execution_plan()),
        GENERATION_OWNED_XHTTP_OWNERSHIP
    );
}

#[test]
fn source_admission_rejects_factory_only_or_invalid_security_tuples() {
    for (link, expected) in [
        (
            vless_link("websocket", "none", "", "/ws").export_url(),
            "security=none currently admits native tcp",
        ),
        (
            vless_link("httpupgrade", "none", "", "/upgrade").export_url(),
            "security=none currently admits native tcp",
        ),
        (
            vless_link("h2", "reality", "h2", "/h2").export_url(),
            "h2 transport admits standard tls",
        ),
        (
            vmess_link("h2", "none").export_url(),
            "h2 handler admits TLS HTTP/2",
        ),
    ] {
        let error = build_proxy(link).unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn chain_admission_projects_effective_udp_ownership_without_rewriting_child_factories() {
    let standalone_socks = build_proxy("socks5://127.0.0.1:1080".to_owned()).unwrap();
    assert_eq!(
        effective_materialized_runtime_ownership(&standalone_socks),
        FLOW_STREAM_ASSOCIATION_OWNERSHIP
    );
    let chained_socks = build_proxy(chained("socks5://127.0.0.1:1081".to_owned())).unwrap();
    assert_eq!(
        effective_materialized_runtime_ownership(&chained_socks),
        FLOW_STREAM_POLICY_CLOSED_OWNERSHIP
    );

    let standalone_shadowsocks = build_proxy(shadowsocks_link()).unwrap();
    assert_eq!(
        effective_materialized_runtime_ownership(&standalone_shadowsocks),
        FLOW_STREAM_PACKET_OWNERSHIP
    );
    let chained_shadowsocks = build_proxy(chained(shadowsocks_link())).unwrap();
    assert_eq!(
        effective_materialized_runtime_ownership(&chained_shadowsocks),
        FLOW_STREAM_POLICY_CLOSED_OWNERSHIP
    );

    for net in ["tcp", "ws", "httpupgrade"] {
        let vmess = build_proxy(chained(vmess_link(net, "none").export_url())).unwrap();
        assert_eq!(
            effective_materialized_runtime_ownership(&vmess),
            FLOW_STREAM_PACKET_OWNERSHIP,
            "{net}"
        );
    }

    let http_transport = build_proxy(chained(
        "http://user:password@127.0.0.1:8080/resource?transport=1&host=transport.example.test"
            .to_owned(),
    ))
    .unwrap();
    assert_eq!(
        effective_materialized_runtime_ownership(&http_transport),
        FLOW_STREAM_POLICY_CLOSED_OWNERSHIP
    );
}

fn build_proxy(link: String) -> Result<plan::ResidentProxyPlan, String> {
    plan::build_resident_proxy_plan_for_node(
        &test_config(),
        "proxy".to_owned(),
        "ownership-fixture".to_owned(),
        link,
    )
}

fn chained(child: String) -> String {
    format!("socks5://127.0.0.1:1080 -> {child}")
}

fn test_config() -> Config {
    let sections = dae_config::parser::parse_config(
        r#"
        global {
          lan_interface: daerust0
          allow_insecure: false
          so_mark_from_dae: 1234
          mptcp: false
        }
        routing {
          fallback: direct
        }
        "#,
    )
    .unwrap();
    dae_config::schema::build_config(&sections).unwrap()
}

fn vless_link(net: &str, security: &str, alpn: &str, path: &str) -> VLESSLink {
    VLESSLink {
        ps: String::new(),
        add: "127.0.0.1".to_owned(),
        port: "443".to_owned(),
        id: TEST_CLIENT_ID.to_owned(),
        net: net.to_owned(),
        r#type: "none".to_owned(),
        host: "transport.example.test".to_owned(),
        sni: "server.example.test".to_owned(),
        path: path.to_owned(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        tls: security.to_owned(),
        flow: String::new(),
        alpn: alpn.to_owned(),
        allow_insecure: false,
        fingerprint: String::new(),
        public_key: String::new(),
        short_id: String::new(),
        spider_x: String::new(),
        mux: false,
        encryption: String::new(),
        protocol: "vless".to_owned(),
    }
}

fn vless_xhttp_reality_h2_link() -> VLESSLink {
    vless_reality_link("xhttp", "", "/xhttp-reality")
}

fn vless_reality_link(net: &str, alpn: &str, path: &str) -> VLESSLink {
    let mut link = vless_link(net, "reality", alpn, path);
    link.public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
    link.short_id = "01020304".to_owned();
    link.spider_x = "/".to_owned();
    link
}

fn vless_mux_link() -> VLESSLink {
    let mut link = vless_link("tcp", "tls", "", "");
    link.mux = true;
    link
}

fn vmess_link(net: &str, tls: &str) -> VMessLink {
    VMessLink {
        ps: String::new(),
        add: "127.0.0.1".to_owned(),
        port: "443".to_owned(),
        id: TEST_CLIENT_ID.to_owned(),
        aid: "0".to_owned(),
        net: net.to_owned(),
        r#type: "none".to_owned(),
        host: "vmess.example.test".to_owned(),
        sni: "vmess.example.test".to_owned(),
        path: "/vmess".to_owned(),
        tls: tls.to_owned(),
        security: String::new(),
        allow_insecure: false,
        fingerprint: String::new(),
        v: "2".to_owned(),
        protocol: "vmess".to_owned(),
    }
}

fn trojan_inner_link() -> TrojanLink {
    TrojanLink {
        name: String::new(),
        server: "127.0.0.1".to_owned(),
        port: 443,
        password: "outer-secret".to_owned(),
        sni: "trojan.example.test".to_owned(),
        alpn: String::new(),
        transport_type: "ws".to_owned(),
        encryption: "ss;aes-128-gcm:inner-secret".to_owned(),
        host: "trojan.example.test".to_owned(),
        path: "/trojan".to_owned(),
        service_name: String::new(),
        allow_insecure: false,
        protocol: "trojan-go".to_owned(),
    }
}

fn shadowsocks_plugin_link() -> String {
    ShadowsocksLink {
        name: String::new(),
        server: "127.0.0.1".to_owned(),
        port: 8388,
        password: "shadowsocks-secret".to_owned(),
        cipher: "aes-128-gcm".to_owned(),
        plugin: Sip003::parse(
            "simple-obfs;obfs=http;obfs-host=transport.example.test;obfs-uri=/resource",
        ),
        udp: false,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

fn shadowsocks_link() -> String {
    ShadowsocksLink {
        name: String::new(),
        server: "127.0.0.1".to_owned(),
        port: 8388,
        password: "shadowsocks-secret".to_owned(),
        cipher: "aes-128-gcm".to_owned(),
        plugin: Sip003::default(),
        udp: true,
        protocol: "shadowsocks".to_owned(),
    }
    .export_url()
}

fn shadowsocksr_link() -> String {
    let password = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("shadowsocksr-secret");
    format!(
        "ssr://127.0.0.1:8388:origin:aes-128-cfb:http_simple:{password}/?remarks=&protoparam=&obfsparam=transport.example.test"
    )
}
