use super::*;
mod basic_shadowsocks;
use self::basic_shadowsocks::*;
mod trojan;
use self::trojan::*;
mod vmess_vless;
use self::vmess_vless::*;
mod quic;
use self::quic::*;
mod graph_contract;
use self::graph_contract::*;

#[test]
pub(super) fn resident_dataplane_plan_admits_shadowsocks_2022_cipher_family() {
    let config = parse_config(
        r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868'
        }
        group {
        proxy {
            filter: name(ss_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
    );
    let plan = build_resident_dataplane_plan(&config).unwrap();
    let proxy = plan
        .default_proxy_group()
        .unwrap()
        .select_proxy_for_tcp()
        .unwrap();
    assert_eq!(proxy.node_tag, "ss_live");
    assert_eq!(proxy.protocol, "shadowsocks");
    assert_eq!(proxy.tls, "aead-2022");
    assert_eq!(
        proxy.executable_graph_value()["packetSemantics"],
        "datagram-aead-2022"
    );
    assert!(matches!(
        proxy.handler,
        ResidentProxyProtocolPlan::Shadowsocks2022Tcp {
            salt_len: 16,
            packet_nonce_len: 0,
            ..
        }
    ));
}

pub(super) fn resident_tcp_handler_config() -> Config {
    parse_config(
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
}

#[test]
pub(super) fn resident_dataplane_plan_admits_basic_and_shadowsocks_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_basic_and_shadowsocks_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}

#[test]
pub(super) fn resident_dataplane_plan_admits_trojan_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_trojan_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}

#[test]
pub(super) fn resident_dataplane_plan_admits_vmess_vless_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_vmess_vless_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}

#[test]
pub(super) fn resident_dataplane_plan_admits_quic_handlers() {
    let config = resident_tcp_handler_config();
    let proxies = assert_quic_handlers(&config);
    assert_common_resident_graph_contracts(&proxies);
}
