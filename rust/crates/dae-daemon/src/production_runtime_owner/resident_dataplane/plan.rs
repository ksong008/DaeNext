use std::collections::BTreeMap;
use std::time::Duration;

use dae_config::{Config, DynamicFunctionValue, Group};
use dae_core_types::OutboundIndex;
use dae_datapath::TcpDialMode;
use dae_outbound::{
    AnyTLSLink,
    http_proxy::{HttpProxyLink, HttpScheme},
    hysteria2::{Hysteria2Link, server_contract as hysteria2_server_contract},
    juicity::JuicityLink,
    shadowsocks::{ShadowsocksLink, cipher_spec},
    shared_transport::{UtlsFingerprint, resolve_utls_client_hello_id},
    trojan::{TrojanLink, TrojanTransportType},
    tuic::TuicLink,
    vless::{VLESSLink, password_to_key},
    vmess::VMessLink,
};
use url::Url;

use super::{
    XTLS_RPRX_VISION,
    dns::{ResidentDnsPlan, build_resident_dns_plan},
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedGroupNode {
    tag: String,
    link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentNodeLinkShape {
    pub(super) tag: String,
    pub(super) scheme: String,
    pub(super) link: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ResidentUtlsFingerprintPlan {
    pub(super) source: &'static str,
    pub(super) requested: String,
    pub(super) name: String,
    pub(super) canonical: String,
    pub(super) family: String,
    pub(super) client: String,
    pub(super) randomized: bool,
    pub(super) alpn_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GroupNodeSelection {
    Selected(SelectedGroupNode),
    NoCandidate {
        explicit_name_filter: bool,
        unresolved_names: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub(super) enum ResidentProxyProtocolPlan {
    VlessVisionTcpTls {
        key: [u8; 16],
    },
    Socks5Tcp {
        username: String,
        password: String,
    },
    HttpProxyTcp {
        username: String,
        password: String,
    },
    ShadowsocksAeadTcp {
        cipher: String,
        password: String,
        salt_len: usize,
    },
    TrojanTcpTls {
        password: String,
    },
    AnyTlsTcpTls {
        auth: String,
    },
    VmessAeadTcp {
        id: String,
    },
    Hysteria2QuicTcp {
        auth: String,
        pin_sha256: String,
        max_rx: u64,
    },
    TuicQuicTcp {
        uuid: String,
        password: String,
        alpn: Vec<String>,
    },
    JuicityQuicTcp {
        uuid: String,
        password: String,
        allow_insecure: bool,
        pinned_certchain_sha256: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct ResidentProxyPlan {
    pub(super) protocol: String,
    pub(super) group_name: String,
    pub(super) group_policy: String,
    pub(super) node_tag: String,
    pub(super) server_host: String,
    pub(super) server_port: u16,
    pub(super) server_name: String,
    pub(super) alpn: Vec<String>,
    pub(super) flow: String,
    pub(super) net: String,
    pub(super) tls: String,
    pub(super) allow_insecure: bool,
    pub(super) utls_fingerprint: Option<ResidentUtlsFingerprintPlan>,
    pub(super) handler: ResidentProxyProtocolPlan,
    pub(super) mark: u32,
    pub(super) mptcp: bool,
}

impl ResidentProxyPlan {
    pub(super) fn vless_key(&self) -> Result<[u8; 16], String> {
        match self.handler {
            ResidentProxyProtocolPlan::VlessVisionTcpTls { key } => Ok(key),
            _ => Err(format!(
                "resident proxy {} node {} is not a VLESS handler",
                self.protocol, self.node_tag
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResidentDataplanePlan {
    pub(super) enabled: bool,
    pub(super) unsupported_reason: Option<String>,
    pub(super) proxies: BTreeMap<u8, ResidentProxyPlan>,
    pub(super) default_proxy: Option<ResidentProxyPlan>,
    pub(super) tcp_dial_mode: TcpDialMode,
    pub(super) sniffing_timeout: Duration,
    pub(super) dns: ResidentDnsPlan,
}

pub(super) fn build_resident_dataplane_plan(
    config: &Config,
) -> Result<ResidentDataplanePlan, String> {
    let node_links = tagged_node_links(config);
    let (proxies, default_outbound) = resident_proxy_plans(config, &node_links)?;
    let Some(default_proxy) = default_outbound.and_then(|outbound| proxies.get(&outbound).cloned())
    else {
        return Ok(ResidentDataplanePlan {
            enabled: false,
            unsupported_reason: Some(
                "no user-defined routing outbound with a resolvable node link was found".to_owned(),
            ),
            proxies,
            default_proxy: None,
            tcp_dial_mode: parse_tcp_dial_mode(config)?,
            sniffing_timeout: Duration::ZERO,
            dns: ResidentDnsPlan::asis(config.global.so_mark_from_dae),
        });
    };
    let tcp_dial_mode = parse_tcp_dial_mode(config)?;
    let sniffing_timeout = tcp_sniffing_timeout(config, tcp_dial_mode);
    let dns = build_resident_dns_plan(config)?;
    Ok(ResidentDataplanePlan {
        enabled: true,
        unsupported_reason: None,
        proxies,
        default_proxy: Some(default_proxy),
        tcp_dial_mode,
        sniffing_timeout,
        dns,
    })
}

fn resident_proxy_plans(
    config: &Config,
    node_links: &BTreeMap<String, String>,
) -> Result<(BTreeMap<u8, ResidentProxyPlan>, Option<u8>), String> {
    let mut proxies = BTreeMap::new();
    let mut default_outbound = None;
    for outbound in referenced_user_outbounds(config) {
        if node_links.contains_key(&outbound) {
            return Err(format!(
                "resident dataplane cannot assign direct node outbound {outbound} to a stable Go-compatible outbound index; put the node behind a group before enabling Rust resident dataplane",
            ));
        }
        let Some((group_index, group)) = config
            .group
            .iter()
            .enumerate()
            .find(|(_, group)| group.name == outbound)
        else {
            continue;
        };
        let outbound_index = (OutboundIndex::USER_DEFINED_MIN.value() as usize + group_index) as u8;
        if proxies.contains_key(&outbound_index) {
            continue;
        }
        let node = match select_group_node(group, node_links)? {
            GroupNodeSelection::Selected(node) => node,
            GroupNodeSelection::NoCandidate {
                explicit_name_filter,
                unresolved_names,
            } => {
                let names = if unresolved_names.is_empty() {
                    "<empty>".to_owned()
                } else {
                    unresolved_names.join(", ")
                };
                let reason = if explicit_name_filter {
                    format!(
                        "resident dataplane cannot resolve group {} name filter node(s): {names}; subscription-backed groups must be materialized before Rust resident dataplane can own runtime",
                        group.name
                    )
                } else {
                    format!(
                        "resident dataplane cannot resolve any node for referenced group {}",
                        group.name
                    )
                };
                return Err(reason);
            }
        };
        let mut proxy = build_proxy_plan(config, group.name.clone(), node.tag, node.link)?;
        proxy.group_policy = group_policy_name(&group.policy);
        default_outbound.get_or_insert(outbound_index);
        proxies.insert(outbound_index, proxy);
    }
    Ok((proxies, default_outbound))
}

fn build_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let scheme = link_scheme(&link).unwrap_or_default();
    match scheme.as_str() {
        "vless" => build_vless_proxy_plan(config, group_name, node_tag, link),
        "socks" | "socks5" => build_socks5_proxy_plan(config, group_name, node_tag, link),
        "http" | "https" => build_http_proxy_plan(config, group_name, node_tag, link),
        "ss" | "shadowsocks" => build_shadowsocks_proxy_plan(config, group_name, node_tag, link),
        "trojan" | "trojan-go" => build_trojan_proxy_plan(config, group_name, node_tag, link),
        "anytls" => build_anytls_proxy_plan(config, group_name, node_tag, link),
        "vmess" => build_vmess_proxy_plan(config, group_name, node_tag, link),
        "hysteria2" | "hy2" => build_hysteria2_proxy_plan(config, group_name, node_tag, link),
        "tuic" => build_tuic_proxy_plan(config, group_name, node_tag, link),
        "juicity" => build_juicity_proxy_plan(config, group_name, node_tag, link),
        _ => Err(format!(
            "resident dataplane selected unsupported {scheme} node {node_tag}; no Rust protocol handler is admitted for this node yet, keep Go outbound for this config",
        )),
    }
}

fn build_vless_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let vless =
        VLESSLink::parse(&link).map_err(|err| format!("parse VLESS node {node_tag}: {err}"))?;
    vless
        .validate_flow_client(true)
        .map_err(|err| format!("validate VLESS flow for {node_tag}: {err}"))?;
    vless
        .validate_transport_contract()
        .map_err(|err| format!("validate VLESS transport for {node_tag}: {err}"))?;
    if vless.flow != XTLS_RPRX_VISION {
        return Err(format!(
            "resident dataplane vless native experiment admits only flow={XTLS_RPRX_VISION}, got '{}' for node {node_tag}; keep Go outbound for this config",
            vless.flow
        ));
    }
    if vless.net != "tcp" {
        return Err(format!(
            "resident dataplane vless handler currently supports tcp transport only, got {} for node {node_tag}",
            vless.net
        ));
    }
    if vless.tls != "tls" {
        return Err(format!(
            "resident dataplane vless handler currently supports security=tls only, got {} for node {node_tag}",
            vless.tls
        ));
    }
    if vless.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane vless TLS handler does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let utls_fingerprint = resident_utls_fingerprint_plan(config, Some(&vless.fingerprint))?;
    let server_port = vless.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VLESS port {} for node {node_tag}: {err}",
            vless.port
        )
    })?;
    let key = password_to_key(&vless.id)
        .map_err(|err| format!("parse VLESS key for {node_tag}: {err}"))?;
    let server_name = if vless.sni.is_empty() {
        vless.add.clone()
    } else {
        vless.sni.clone()
    };
    let alpn = split_alpn(&vless.alpn);
    Ok(ResidentProxyPlan {
        protocol: "vless".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: vless.add,
        server_port,
        server_name,
        alpn,
        flow: vless.flow,
        net: vless.net,
        tls: vless.tls,
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::VlessVisionTcpTls { key },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_socks5_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Url::parse(&link).map_err(|err| format!("parse SOCKS node {node_tag}: {err}"))?;
    if !matches!(parsed.scheme(), "socks" | "socks5") {
        return Err(format!(
            "resident dataplane socks5 handler got unsupported scheme {} for node {node_tag}",
            parsed.scheme()
        ));
    }
    let server_host = parsed
        .host_str()
        .ok_or_else(|| format!("parse SOCKS node {node_tag}: missing host"))?
        .to_owned();
    let server_port = parsed.port().unwrap_or(1080);
    Ok(ResidentProxyPlan {
        protocol: "socks5".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::Socks5Tcp {
            username: parsed.username().to_owned(),
            password: parsed.password().unwrap_or_default().to_owned(),
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_http_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = HttpProxyLink::parse(&link)
        .map_err(|err| format!("parse HTTP proxy node {node_tag}: {err}"))?;
    if parsed.protocol != HttpScheme::Http {
        return Err(format!(
            "resident dataplane first-batch HTTP proxy handler admits plain http proxy endpoints only for node {node_tag}"
        ));
    }
    if parsed.transport {
        return Err(format!(
            "resident dataplane first-batch HTTP proxy handler does not admit HTTP transport mode for node {node_tag}"
        ));
    }
    if parsed.allow_insecure {
        return Err(format!(
            "resident dataplane first-batch HTTP proxy handler does not admit allow_insecure for node {node_tag}"
        ));
    }
    Ok(ResidentProxyPlan {
        protocol: "http-proxy".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::HttpProxyTcp {
            username: parsed.username,
            password: parsed.password,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_shadowsocks_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = ShadowsocksLink::parse(&link)
        .map_err(|err| format!("parse Shadowsocks node {node_tag}: {err}"))?;
    if !parsed.plugin.name.is_empty() {
        return Err(format!(
            "resident dataplane first-batch Shadowsocks handler does not admit SIP003 plugin {} for node {node_tag}",
            parsed.plugin.name
        ));
    }
    let spec = cipher_spec(&parsed.cipher)
        .map_err(|err| format!("admit Shadowsocks cipher for node {node_tag}: {err}"))?;
    Ok(ResidentProxyPlan {
        protocol: "shadowsocks".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "aead".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::ShadowsocksAeadTcp {
            cipher: spec.cipher.to_owned(),
            password: parsed.password,
            salt_len: spec.salt_len,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_trojan_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TrojanLink::parse(&link).map_err(|err| format!("parse Trojan node {node_tag}: {err}"))?;
    if parsed.protocol != "trojan" || parsed.transport_kind() != TrojanTransportType::None {
        return Err(format!(
            "resident dataplane generic TLS/TCP handler admits only plain trojan endpoints for node {node_tag}; transport={} protocol={}",
            parsed.transport_type, parsed.protocol
        ));
    }
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic TLS/TCP handler does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    Ok(ResidentProxyPlan {
        protocol: "trojan".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name: parsed.sni,
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "tls".to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::TrojanTcpTls {
            password: parsed.password,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_anytls_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        AnyTLSLink::parse(&link).map_err(|err| format!("parse AnyTLS node {node_tag}: {err}"))?;
    if parsed.insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic TLS/TCP handler does not admit AnyTLS insecure mode; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let url =
        Url::parse(&link).map_err(|err| format!("parse AnyTLS endpoint {node_tag}: {err}"))?;
    let server_host = url
        .host_str()
        .ok_or_else(|| format!("parse AnyTLS endpoint {node_tag}: missing host"))?
        .to_owned();
    let server_port = url.port().unwrap_or(443);
    let utls_fingerprint = resident_utls_fingerprint_plan(config, None)?;
    Ok(ResidentProxyPlan {
        protocol: "anytls".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host,
        server_port,
        server_name: parsed.tls_server_name,
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "tls".to_owned(),
        allow_insecure: false,
        utls_fingerprint,
        handler: ResidentProxyProtocolPlan::AnyTlsTcpTls { auth: parsed.auth },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_tuic_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        TuicLink::parse(&link).map_err(|err| format!("parse TUIC node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate TUIC UUID for {node_tag}: {err}"))?;
    if !(parsed.allow_insecure || config.global.allow_insecure || parsed.disable_sni) {
        return Err(format!(
            "resident dataplane generic QUIC handler admits TUIC only when allow_insecure is explicit for node {node_tag}; keep Go fallback for this config"
        ));
    }
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires TUIC password for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    let alpn = if parsed.alpn.is_empty() {
        vec!["h3".to_owned()]
    } else {
        parsed.alpn.clone()
    };
    Ok(ResidentProxyPlan {
        protocol: "tuic".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: alpn.clone(),
        flow: String::new(),
        net: "udp".to_owned(),
        tls: "quic".to_owned(),
        allow_insecure: true,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::TuicQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            alpn,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_hysteria2_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed = Hysteria2Link::parse(&link)
        .map_err(|err| format!("parse Hysteria2 node {node_tag}: {err}"))?;
    if parsed.insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic QUIC handler does not admit Hysteria2 insecure mode; keep Go fallback for this config"
                .to_owned(),
        );
    }
    if parsed.pin_sha256.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Hysteria2 pinSHA256 for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let auth = if parsed.password.is_empty() {
        parsed.user.clone()
    } else {
        format!("{}:{}", parsed.user, parsed.password)
    };
    if auth.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Hysteria2 auth for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let server = hysteria2_server_contract(&parsed.server);
    if server.port_hopping {
        return Err(format!(
            "resident dataplane generic QUIC handler admits only single-port Hysteria2 endpoints for node {node_tag}; got {}",
            parsed.server
        ));
    }
    let server_port = server.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid Hysteria2 port {} for node {node_tag}: {err}",
            server.port
        )
    })?;
    let server_name = if parsed.sni.is_empty() {
        server.host.clone()
    } else {
        parsed.sni.clone()
    };
    Ok(ResidentProxyPlan {
        protocol: "hysteria2".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: server.host,
        server_port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        tls: "quic".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::Hysteria2QuicTcp {
            auth,
            pin_sha256: parsed.pin_sha256,
            max_rx: parsed.max_rx,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_juicity_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        JuicityLink::parse(&link).map_err(|err| format!("parse Juicity node {node_tag}: {err}"))?;
    parsed
        .validate_uuid()
        .map_err(|err| format!("validate Juicity UUID for {node_tag}: {err}"))?;
    if parsed.password.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Juicity password for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let allow_insecure = parsed.allow_insecure || config.global.allow_insecure;
    if !allow_insecure && parsed.pinned_certchain_sha256.is_empty() {
        return Err(format!(
            "resident dataplane generic QUIC handler requires Juicity allow_insecure or pinned_certchain_sha256 for node {node_tag}; keep Go fallback for this config"
        ));
    }
    let server_name = if parsed.sni.is_empty() {
        parsed.server.clone()
    } else {
        parsed.sni.clone()
    };
    Ok(ResidentProxyPlan {
        protocol: "juicity".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.server,
        server_port: parsed.port,
        server_name,
        alpn: vec!["h3".to_owned()],
        flow: String::new(),
        net: "udp".to_owned(),
        tls: "quic".to_owned(),
        allow_insecure,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::JuicityQuicTcp {
            uuid: parsed.user,
            password: parsed.password,
            allow_insecure,
            pinned_certchain_sha256: parsed.pinned_certchain_sha256,
        },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

fn build_vmess_proxy_plan(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    let parsed =
        VMessLink::parse(&link).map_err(|err| format!("parse VMess node {node_tag}: {err}"))?;
    parsed
        .validate_aead()
        .map_err(|err| format!("validate VMess AEAD for {node_tag}: {err}"))?;
    parsed
        .validate_transport()
        .map_err(|err| format!("validate VMess transport for {node_tag}: {err}"))?;
    if parsed.net != "tcp" {
        return Err(format!(
            "resident dataplane generic AEAD TCP handler admits only VMess net=tcp endpoints for node {node_tag}; got {}",
            parsed.net
        ));
    }
    if !parsed.tls.is_empty() && parsed.tls != "none" {
        return Err(format!(
            "resident dataplane generic AEAD TCP handler admits only plain VMess TCP endpoints for node {node_tag}; got tls={}",
            parsed.tls
        ));
    }
    if parsed.allow_insecure || config.global.allow_insecure {
        return Err(
            "resident dataplane generic AEAD TCP handler does not admit allow_insecure; keep Go fallback for this config"
                .to_owned(),
        );
    }
    let server_port = parsed.port.parse::<u16>().map_err(|err| {
        format!(
            "invalid VMess port {} for node {node_tag}: {err}",
            parsed.port
        )
    })?;
    Ok(ResidentProxyPlan {
        protocol: "vmess".to_owned(),
        group_name,
        group_policy: String::new(),
        node_tag,
        server_host: parsed.add,
        server_port,
        server_name: String::new(),
        alpn: Vec::new(),
        flow: String::new(),
        net: "tcp".to_owned(),
        tls: "none".to_owned(),
        allow_insecure: false,
        utls_fingerprint: None,
        handler: ResidentProxyProtocolPlan::VmessAeadTcp { id: parsed.id },
        mark: config.global.so_mark_from_dae,
        mptcp: config.global.mptcp,
    })
}

pub(super) fn build_resident_proxy_plan_for_node(
    config: &Config,
    group_name: String,
    node_tag: String,
    link: String,
) -> Result<ResidentProxyPlan, String> {
    build_proxy_plan(config, group_name, node_tag, link)
}

pub(super) fn resident_node_link_shapes(config: &Config) -> Vec<ResidentNodeLinkShape> {
    tagged_node_links(config)
        .into_iter()
        .map(|(tag, link)| ResidentNodeLinkShape {
            tag,
            scheme: link_scheme(&link).unwrap_or_default(),
            link,
        })
        .collect()
}

fn resident_utls_fingerprint_plan(
    config: &Config,
    link_fingerprint: Option<&str>,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    let link_fingerprint = link_fingerprint.unwrap_or_default().trim();
    if !link_fingerprint.is_empty() && !link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return resolve_optional_resident_utls_fingerprint("link fp", link_fingerprint);
    }
    if link_fingerprint.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }

    if config
        .global
        .tls_implementation
        .trim()
        .eq_ignore_ascii_case("utls")
    {
        let global_fingerprint = config.global.utls_imitate.trim();
        if global_fingerprint.is_empty() {
            return resolve_resident_utls_fingerprint("default fingerprint", "chrome").map(Some);
        }
        return resolve_optional_resident_utls_fingerprint(
            "global utls_imitate",
            global_fingerprint,
        );
    }

    Ok(None)
}

fn resolve_optional_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<Option<ResidentUtlsFingerprintPlan>, String> {
    if requested.eq_ignore_ascii_case("unsafe") {
        return Ok(None);
    }
    resolve_resident_utls_fingerprint(source, requested).map(Some)
}

fn resolve_resident_utls_fingerprint(
    source: &'static str,
    requested: &str,
) -> Result<ResidentUtlsFingerprintPlan, String> {
    let fingerprint = resolve_utls_client_hello_id(requested)
        .map_err(|err| format!("resident dataplane unsupported {source} {requested}: {err}"))?;
    Ok(resident_utls_fingerprint_plan_from(
        source,
        requested,
        fingerprint,
    ))
}

fn resident_utls_fingerprint_plan_from(
    source: &'static str,
    requested: &str,
    fingerprint: UtlsFingerprint,
) -> ResidentUtlsFingerprintPlan {
    ResidentUtlsFingerprintPlan {
        source,
        requested: requested.to_owned(),
        name: fingerprint.name.to_owned(),
        canonical: fingerprint.canonical.to_owned(),
        family: fingerprint.family.to_owned(),
        client: fingerprint.client.to_owned(),
        randomized: fingerprint.randomized,
        alpn_policy: fingerprint.alpn_policy.to_owned(),
    }
}

fn parse_tcp_dial_mode(config: &Config) -> Result<TcpDialMode, String> {
    config
        .global
        .dial_mode
        .parse::<TcpDialMode>()
        .map_err(|err| format!("resident dataplane dial_mode: {err}"))
}

fn tcp_sniffing_timeout(config: &Config, dial_mode: TcpDialMode) -> Duration {
    if dial_mode == TcpDialMode::Ip {
        return Duration::ZERO;
    }
    let nanos = config.global.sniffing_timeout.as_nanos();
    if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }
}

fn referenced_user_outbounds(config: &Config) -> Vec<String> {
    let mut outbounds = Vec::new();
    for rule in &config.routing.rules {
        push_user_outbound(&mut outbounds, &rule.outbound.name);
    }
    match &config.routing.fallback {
        DynamicFunctionValue::String(name) => push_user_outbound(&mut outbounds, name),
        DynamicFunctionValue::Function(function) => {
            push_user_outbound(&mut outbounds, &function.name)
        }
        DynamicFunctionValue::FunctionList(functions) => {
            for function in functions {
                push_user_outbound(&mut outbounds, &function.name);
            }
        }
        DynamicFunctionValue::Nil => {}
    }
    outbounds
}

fn push_user_outbound(outbounds: &mut Vec<String>, name: &str) {
    if matches!(
        name,
        "direct" | "block" | "must_rules" | "logical_or" | "logical_and"
    ) {
        return;
    }
    if !outbounds.iter().any(|seen| seen == name) {
        outbounds.push(name.to_owned());
    }
}

fn select_group_node(
    group: &Group,
    node_links: &BTreeMap<String, String>,
) -> Result<GroupNodeSelection, String> {
    let mut unresolved_names = Vec::<String>::new();
    let mut explicit_name_filter = false;
    let fixed_index = fixed_policy_index(&group.policy).unwrap_or(0);
    let mut matching_index = 0_usize;
    let mut first_match = None::<&str>;
    let mut fixed_match = None::<&str>;
    for filter in &group.filter {
        for function in filter {
            if function.name == "name" && !function.not {
                explicit_name_filter = true;
                for param in &function.params {
                    if param.key.is_empty() {
                        if node_links.contains_key(&param.val) {
                            first_match.get_or_insert(param.val.as_str());
                            if matching_index == fixed_index {
                                fixed_match = Some(param.val.as_str());
                            }
                            matching_index += 1;
                        } else {
                            unresolved_names.push(param.val.clone());
                        }
                    }
                }
            }
        }
    }
    let tag = if explicit_name_filter {
        fixed_match.or(first_match)
    } else {
        node_links
            .keys()
            .nth(fixed_index)
            .or_else(|| node_links.keys().next())
            .map(String::as_str)
    };
    let Some(tag) = tag else {
        return Ok(GroupNodeSelection::NoCandidate {
            explicit_name_filter,
            unresolved_names,
        });
    };
    let link = node_links
        .get(tag)
        .ok_or_else(|| format!("group {} selected missing node {tag}", group.name))?
        .clone();
    Ok(GroupNodeSelection::Selected(SelectedGroupNode {
        tag: tag.to_owned(),
        link,
    }))
}

fn fixed_policy_index(policy: &DynamicFunctionValue) -> Option<usize> {
    let function = match policy {
        DynamicFunctionValue::Function(function) => function,
        DynamicFunctionValue::FunctionList(functions) if functions.len() == 1 => &functions[0],
        _ => return None,
    };
    if function.name != "fixed" {
        return None;
    }
    function
        .params
        .first()
        .and_then(|param| param.val.parse::<usize>().ok())
}

fn group_policy_name(policy: &DynamicFunctionValue) -> String {
    match policy {
        DynamicFunctionValue::Function(function) => function.name.clone(),
        DynamicFunctionValue::FunctionList(functions) => functions
            .first()
            .map(|function| function.name.clone())
            .unwrap_or_default(),
        DynamicFunctionValue::String(value) => value.clone(),
        DynamicFunctionValue::Nil => String::new(),
    }
}

fn tagged_node_links(config: &Config) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in &config.node {
        let (tag, link) = split_keyable_link(raw);
        if link.contains("://") {
            let tag = tag.unwrap_or_else(|| link.clone());
            out.insert(tag, link);
        }
    }
    out
}

fn link_scheme(link: &str) -> Option<String> {
    link.split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
}

fn split_keyable_link(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return (None, unquote_config_value(trimmed));
    };
    let before_scheme = &trimmed[..scheme_pos];
    if let Some(colon) = before_scheme.rfind(':') {
        let tag = unquote_config_value(&trimmed[..colon]);
        let link = unquote_config_value(&trimmed[colon + 1..]);
        if !tag.is_empty() {
            return (Some(tag), link);
        }
    }
    (None, unquote_config_value(trimmed))
}

fn unquote_config_value(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

fn split_alpn(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(input: &str) -> Config {
        let sections = dae_config::parser::parse_config(input).unwrap();
        dae_config::schema::build_config(&sections).unwrap()
    }

    #[test]
    fn resident_dataplane_plan_selects_vless_group_node() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        pname(dae) -> must_direct
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        let proxy = plan.default_proxy.unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.proxies.len(), 1);
        assert_eq!(proxy.group_name, "proxy");
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.server_host, "156.246.90.2");
        assert_eq!(proxy.server_port, 443);
        assert_eq!(proxy.server_name, "office.example");
        assert_eq!(proxy.flow, "xtls-rprx-vision");
        assert_eq!(proxy.alpn, ["h2", "http/1.1"]);
        assert_eq!(proxy.mark, 1234);
    }

    #[test]
    fn group_node_selection_keeps_fixed_policy_order() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        }
        node {
        node_a: 'socks://127.0.0.1:1080'
        node_b: 'socks://127.0.0.1:1081'
        }
        group {
        proxy {
            filter: name(node_a, node_b)
            policy: fixed(1)
        }
        }
        routing {
        l4proto(tcp) -> proxy
        fallback: direct
        }
        "#,
        );
        let links = tagged_node_links(&config);
        let selected = select_group_node(&config.group[0], &links).unwrap();
        match selected {
            GroupNodeSelection::Selected(node) => {
                assert_eq!(node.tag, "node_b");
                assert_eq!(node.link, "socks://127.0.0.1:1081");
            }
            GroupNodeSelection::NoCandidate { .. } => panic!("expected selected node"),
        }
    }

    #[test]
    fn resident_dataplane_plan_does_not_fallback_unresolved_name_filter_to_static_ss_node() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        _022: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868#ss2022'
        xhttp: 'vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?security=tls&type=xhttp&sni=office.example&path=%2Fxhttp&mode=packet-up&alpn=h3'
        }
        group {
        proxy {
            filter: name(node_17)
            policy: fixed
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("cannot resolve group proxy name filter node(s): node_17"));
        assert!(!err.contains("parse VLESS node _022"));
    }

    #[test]
    fn resident_dataplane_plan_rejects_unwired_shadowsocks_variant() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        ss_live: 'ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@217.116.171.227:25868#ss2022'
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
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("admit Shadowsocks cipher for node ss_live"));
        assert!(err.contains("cipher is not stage18 AEAD TCP candidate"));
        assert!(!err.contains("parse VLESS node ss_live"));
    }

    #[test]
    fn resident_dataplane_plan_admits_first_batch_tcp_handlers() {
        let config = parse_config(
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
        );
        let socks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "socks_live".to_owned(),
            "socks5://matrix:matrix-socks-pass@203.0.113.10:28447#socks".to_owned(),
        )
        .unwrap();
        assert_eq!(socks.protocol, "socks5");
        assert_eq!(socks.server_host, "203.0.113.10");
        assert_eq!(socks.server_port, 28447);
        assert!(matches!(
            socks.handler,
            ResidentProxyProtocolPlan::Socks5Tcp { .. }
        ));

        let http = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "http_live".to_owned(),
            "http://matrix:matrix-http-pass@203.0.113.10:28448#http".to_owned(),
        )
        .unwrap();
        assert_eq!(http.protocol, "http-proxy");
        assert_eq!(http.tls, "none");
        assert!(matches!(
            http.handler,
            ResidentProxyProtocolPlan::HttpProxyTcp { .. }
        ));

        let shadowsocks = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_live".to_owned(),
            "ss://aes-128-gcm:matrix-ss-pass@203.0.113.10:28446#ss".to_owned(),
        )
        .unwrap();
        assert_eq!(shadowsocks.protocol, "shadowsocks");
        assert_eq!(shadowsocks.tls, "aead");
        assert!(matches!(
            shadowsocks.handler,
            ResidentProxyProtocolPlan::ShadowsocksAeadTcp { salt_len: 16, .. }
        ));

        let trojan = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_live".to_owned(),
            "trojan://matrix-trojan-pass@203.0.113.10:28444?sni=office.example#trojan".to_owned(),
        )
        .unwrap();
        assert_eq!(trojan.protocol, "trojan");
        assert_eq!(trojan.server_host, "203.0.113.10");
        assert_eq!(trojan.server_port, 28444);
        assert_eq!(trojan.server_name, "office.example");
        assert_eq!(trojan.tls, "tls");
        assert!(matches!(
            trojan.handler,
            ResidentProxyProtocolPlan::TrojanTcpTls { .. }
        ));

        let anytls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_live".to_owned(),
            "anytls://matrix-anytls-pass@203.0.113.10:28451?sni=office.example#anytls".to_owned(),
        )
        .unwrap();
        assert_eq!(anytls.protocol, "anytls");
        assert_eq!(anytls.server_host, "203.0.113.10");
        assert_eq!(anytls.server_port, 28451);
        assert_eq!(anytls.server_name, "office.example");
        assert_eq!(anytls.tls, "tls");
        assert!(matches!(
            anytls.handler,
            ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
        ));

        let vmess = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_live".to_owned(),
            "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MiLCJhZGQiOiIyMDMuMC4xMTMuMTAiLCJwb3J0IjoiMjg0NTIiLCJpZCI6IjAxMjM0NTY3LTg5YWItY2RlZi0wMTIzLTQ1Njc4OWFiY2RlZiIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoiIn0=".to_owned(),
        )
        .unwrap();
        assert_eq!(vmess.protocol, "vmess");
        assert_eq!(vmess.server_host, "203.0.113.10");
        assert_eq!(vmess.server_port, 28452);
        assert_eq!(vmess.tls, "none");
        assert!(matches!(
            vmess.handler,
            ResidentProxyProtocolPlan::VmessAeadTcp { .. }
        ));

        let hysteria2 = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_live".to_owned(),
            "hy2://matrix-hy2-auth@203.0.113.10:28453?sni=office.example&pinSHA256=AA-BB-CC#hy2"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(hysteria2.protocol, "hysteria2");
        assert_eq!(hysteria2.server_host, "203.0.113.10");
        assert_eq!(hysteria2.server_port, 28453);
        assert_eq!(hysteria2.server_name, "office.example");
        assert_eq!(hysteria2.net, "udp");
        assert_eq!(hysteria2.tls, "quic");
        assert!(matches!(
            hysteria2.handler,
            ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
        ));

        let tuic = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_live".to_owned(),
            "tuic://01234567-89ab-cdef-0123-456789abcdef:matrix-tuic-pass@203.0.113.10:28454?allow_insecure=1&sni=office.example&alpn=h3#tuic"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(tuic.protocol, "tuic");
        assert_eq!(tuic.server_host, "203.0.113.10");
        assert_eq!(tuic.server_port, 28454);
        assert_eq!(tuic.server_name, "office.example");
        assert_eq!(tuic.net, "udp");
        assert_eq!(tuic.tls, "quic");
        assert!(matches!(
            tuic.handler,
            ResidentProxyProtocolPlan::TuicQuicTcp { .. }
        ));

        let juicity = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_live".to_owned(),
            "juicity://01234567-89ab-cdef-0123-456789abcdef:matrix-juicity-pass@203.0.113.10:28455?allow_insecure=1&sni=office.example#juicity"
                .to_owned(),
        )
        .unwrap();
        assert_eq!(juicity.protocol, "juicity");
        assert_eq!(juicity.server_host, "203.0.113.10");
        assert_eq!(juicity.server_port, 28455);
        assert_eq!(juicity.server_name, "office.example");
        assert_eq!(juicity.net, "udp");
        assert_eq!(juicity.tls, "quic");
        assert!(matches!(
            juicity.handler,
            ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
        ));
    }

    #[test]
    fn resident_dataplane_plan_keeps_first_batch_unsupported_shapes_blocked() {
        let config = parse_config(
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
        );
        let https = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "https_live".to_owned(),
            "https://matrix:matrix-http-pass@203.0.113.10:28448#https".to_owned(),
        )
        .unwrap_err();
        assert!(https.contains("plain http proxy endpoints only"));

        let plugin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "ss_plugin".to_owned(),
            "ss://aes-128-gcm:matrix-ss-pass@203.0.113.10:28446?plugin=simple-obfs%3Bobfs%3Dhttp#ss-plugin".to_owned(),
        )
        .unwrap_err();
        assert!(plugin.contains("does not admit SIP003 plugin"));

        let trojan_go = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "trojan_go".to_owned(),
            "trojan-go://matrix-trojan-pass@203.0.113.10:28444?type=ws&sni=office.example#trojan-go".to_owned(),
        )
        .unwrap_err();
        assert!(trojan_go.contains("admits only plain trojan endpoints"));

        let anytls_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "anytls_insecure".to_owned(),
            "anytls://matrix-anytls-pass@203.0.113.10:28451?insecure=1&sni=office.example#anytls"
                .to_owned(),
        )
        .unwrap_err();
        assert!(anytls_insecure.contains("does not admit AnyTLS insecure mode"));

        let vmess_tls = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "vmess_tls".to_owned(),
            "vmess://eyJ2IjoiMiIsInBzIjoidm1lc3MtdGxzIiwiYWRkIjoiMjAzLjAuMTEzLjEwIiwicG9ydCI6IjI4NDUyIiwiaWQiOiIwMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWYiLCJhaWQiOiIwIiwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6InRscyJ9".to_owned(),
        )
        .unwrap_err();
        assert!(vmess_tls.contains("admits only plain VMess TCP endpoints"));

        let hy2_no_pin = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_no_pin".to_owned(),
            "hy2://matrix-hy2-auth@203.0.113.10:28453?sni=office.example#hy2".to_owned(),
        )
        .unwrap_err();
        assert!(hy2_no_pin.contains("requires Hysteria2 pinSHA256"));

        let hy2_hopping = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "hy2_hopping".to_owned(),
            "hy2://matrix-hy2-auth@example.com:443,8443-8445?sni=office.example&pinSHA256=AA-BB-CC#hy2"
                .to_owned(),
        )
        .unwrap_err();
        assert!(hy2_hopping.contains("single-port Hysteria2 endpoints"));

        let tuic_without_insecure = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "tuic_without_insecure".to_owned(),
            "tuic://01234567-89ab-cdef-0123-456789abcdef:matrix-tuic-pass@203.0.113.10:28454?sni=office.example&alpn=h3#tuic"
                .to_owned(),
        )
        .unwrap_err();
        assert!(tuic_without_insecure.contains("allow_insecure is explicit"));

        let juicity_without_verification = build_resident_proxy_plan_for_node(
            &config,
            "proxy".to_owned(),
            "juicity_without_verification".to_owned(),
            "juicity://01234567-89ab-cdef-0123-456789abcdef:matrix-juicity-pass@203.0.113.10:28455?sni=office.example#juicity"
                .to_owned(),
        )
        .unwrap_err();
        assert!(
            juicity_without_verification
                .contains("requires Juicity allow_insecure or pinned_certchain_sha256")
        );
    }

    #[test]
    fn resident_dataplane_plan_builds_proxy_by_outbound_index() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        dial_mode: domain++
        }
        node {
        hk: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=hk.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        us: 'vless://01234567-89ab-cdef-0123-456789abcdef@203.0.113.2:443?security=tls&type=tcp&sni=us.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(hk)
            policy: fixed(0)
        }
        openai {
            filter: name(us)
            policy: fixed(0)
        }
        }
        routing {
        domain(suffix: googleapis.com) -> openai
        fallback: proxy
        }
        "#,
        );
        let plan = build_resident_dataplane_plan(&config).unwrap();
        assert!(plan.enabled);
        assert_eq!(plan.tcp_dial_mode, TcpDialMode::DomainPlusPlus);
        assert_eq!(plan.proxies.get(&2).unwrap().group_name, "proxy");
        assert_eq!(plan.proxies.get(&2).unwrap().node_tag, "hk");
        assert_eq!(plan.proxies.get(&3).unwrap().group_name, "openai");
        assert_eq!(plan.proxies.get(&3).unwrap().node_tag, "us");
    }

    #[test]
    fn resident_dataplane_plan_rejects_vless_without_vision_flow() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("admits only flow=xtls-rprx-vision"));
        assert!(err.contains("keep Go outbound"));
    }

    #[test]
    fn resident_dataplane_plan_resolves_link_fingerprint_before_wire_gate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=firefox_105&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "firefox_105");
        assert_eq!(utls.name, "firefox_105");
        assert_eq!(utls.family, "firefox");
    }

    #[test]
    fn resident_dataplane_plan_carries_generic_link_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=safari_16_0&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        assert!(plan.enabled);
        assert_eq!(proxy.node_tag, "vless_live");
        assert_eq!(proxy.flow, XTLS_RPRX_VISION);
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "link fp");
        assert_eq!(utls.requested, "safari_16_0");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_omits_fp_and_global_tls() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_standard_tls_when_link_fp_is_empty_and_global_tls() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_keeps_document_unsafe_auxiliary_rustls_path() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=unsafe&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        assert!(proxy.utls_fingerprint.is_none());
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_does_not_set_fp() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: safari
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "safari");
        assert_eq!(utls.canonical, "safari_auto");
        assert_eq!(utls.family, "safari");
    }

    #[test]
    fn resident_dataplane_plan_uses_global_utls_when_link_fp_is_empty() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: edge
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "global utls_imitate");
        assert_eq!(utls.requested, "edge");
        assert_eq!(utls.canonical, "edge_auto");
        assert_eq!(utls.family, "edge");
    }

    #[test]
    fn resident_dataplane_plan_uses_document_default_when_global_utls_has_empty_imitate() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        tls_implementation: utls
        utls_imitate: ""
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
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
        let proxy = plan.default_proxy.unwrap();
        let utls = proxy.utls_fingerprint.unwrap();
        assert_eq!(utls.source, "default fingerprint");
        assert_eq!(utls.requested, "chrome");
        assert_eq!(utls.canonical, "chrome_auto");
        assert_eq!(utls.family, "chrome");
    }

    #[test]
    fn resident_dataplane_plan_rejects_unknown_utls_fingerprint() {
        let config = parse_config(
            r#"
        global {
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }
        node {
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp=Chrome&alpn=h2,http/1.1'
        }
        group {
        proxy {
            filter: name(vless_live)
            policy: fixed(0)
        }
        }
        routing {
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }
        "#,
        );
        let err = build_resident_dataplane_plan(&config).unwrap_err();
        assert!(err.contains("unsupported link fp Chrome"));
        assert!(err.contains("unknown uTLS Client Hello ID: Chrome"));
    }

    #[test]
    fn resident_dataplane_plan_rejects_non_document_no_fingerprint_aliases() {
        for value in ["no", "none", "off", "false", "0"] {
            let config = parse_config(&format!(
                r#"
        global {{
        lan_interface: daerust0
        allow_insecure: false
        so_mark_from_dae: 1234
        mptcp: false
        }}
        node {{
        vless_live: 'vless://01234567-89ab-cdef-0123-456789abcdef@156.246.90.2:443?security=tls&type=tcp&sni=office.example&flow=xtls-rprx-vision&fp={value}&alpn=h2,http/1.1'
        }}
        group {{
        proxy {{
            filter: name(vless_live)
            policy: fixed(0)
        }}
        }}
        routing {{
        l4proto(tcp) && dport(443) -> proxy
        fallback: direct
        }}
        "#
            ));
            let err = build_resident_dataplane_plan(&config).unwrap_err();
            assert!(err.contains(&format!("unsupported link fp {value}")));
            assert!(err.contains(&format!("unknown uTLS Client Hello ID: {value}")));
        }
    }

    #[test]
    fn resident_utls_fingerprint_resolution_uses_generic_registry() {
        for (name, canonical, family) in [
            ("chrome", "chrome_auto", "chrome"),
            ("firefox_105", "firefox_105", "firefox"),
            ("safari_16_0", "safari_16_0", "safari"),
            ("ios_14", "ios_14", "ios"),
            ("edge_106", "edge_106", "edge"),
            ("android_11_okhttp", "android_11_okhttp", "android"),
            ("randomizednoalpn", "randomizednoalpn", "random"),
        ] {
            let plan = resolve_resident_utls_fingerprint("test", name).unwrap();
            assert_eq!(plan.name, name);
            assert_eq!(plan.canonical, canonical);
            assert_eq!(plan.family, family);
        }

        let randomized_no_alpn =
            resolve_resident_utls_fingerprint("test", "randomizednoalpn").unwrap();
        assert!(randomized_no_alpn.randomized);
        assert_eq!(randomized_no_alpn.alpn_policy, "force-no-alpn");
    }
}
