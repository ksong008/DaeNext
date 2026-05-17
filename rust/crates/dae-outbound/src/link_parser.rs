use crate::error::OutboundError;
use crate::hysteria2::Hysteria2Link;
use crate::juicity::JuicityLink;
use crate::shadowsocks::ShadowsocksLink;
use crate::trojan::TrojanLink;
use crate::tuic::TuicLink;
use crate::vless::VLESSLink;
use crate::vmess::VMessLink;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkNode {
    pub raw: String,
    pub scheme: String,
    pub protocol: String,
    pub parent_dialer_non_nil: bool,
    pub adapter_mode: String,
    pub property_name: String,
    pub property_address: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkParseResult {
    pub linklike: String,
    pub plaintext_tag: Option<String>,
    pub property_name: String,
    pub property_protocol: String,
    pub property_address: String,
    pub nodes: Vec<LinkNode>,
}

pub fn parse_link_chain(link: &str) -> Result<LinkParseResult, OutboundError> {
    let (plaintext_tag, linklike) = split_plaintext_tag(link);
    let mut nodes = Vec::new();
    for part in linklike.split("->") {
        let raw = part.trim();
        let scheme_end = raw.find("://").ok_or(OutboundError::MissingScheme)?;
        let scheme = &raw[..scheme_end];
        let (protocol, parent_dialer_non_nil, adapter_mode) = classify_link(scheme, raw);
        let property_name = property_name(scheme, raw);
        let property_address = property_address(scheme, raw).unwrap_or_default();
        nodes.push(LinkNode {
            raw: raw.to_owned(),
            scheme: scheme.to_owned(),
            protocol: protocol.to_owned(),
            parent_dialer_non_nil,
            adapter_mode: adapter_mode.to_owned(),
            property_name,
            property_address,
        });
    }
    let property_protocol = nodes
        .iter()
        .filter(|node| node.parent_dialer_non_nil)
        .map(|node| node.protocol.as_str())
        .collect::<Vec<_>>()
        .join("->");
    let property_address = nodes
        .iter()
        .filter(|node| !node.property_address.is_empty())
        .map(|node| node.property_address.as_str())
        .collect::<Vec<_>>()
        .join("->");
    let mut property_name = nodes
        .iter()
        .filter(|node| !node.property_name.is_empty())
        .map(|node| node.property_name.as_str())
        .collect::<Vec<_>>()
        .join("->");
    if let Some(tag) = plaintext_tag.as_deref().filter(|tag| !tag.is_empty()) {
        property_name = tag.to_owned();
    }
    Ok(LinkParseResult {
        linklike: linklike.to_owned(),
        plaintext_tag,
        property_name,
        property_protocol,
        property_address,
        nodes,
    })
}

fn classify_link(scheme: &str, raw: &str) -> (&'static str, bool, &'static str) {
    match scheme {
        "direct" => ("direct", true, "native-boundary"),
        "block" => ("block", true, "native-boundary"),
        "ss" | "shadowsocks" => (shadowsocks_protocol(raw), true, "native-opt-in"),
        "socks" | "socks5" => ("socks5", true, "native-opt-in"),
        "http" | "https" => (scheme_to_protocol(scheme), true, "native-opt-in"),
        "trojan" | "trojan-go" => (trojan_protocol(raw), true, "native-opt-in"),
        "vmess" => ("vmess", true, "native-opt-in"),
        "vless" => ("vless", true, "native-opt-in"),
        "hysteria2" | "hy2" => ("hysteria2", true, "native-opt-in"),
        "tuic" => ("tuic", true, "native-opt-in"),
        "juicity" => ("juicity", true, "native-opt-in"),
        _ => ("unknown", false, "unsupported"),
    }
}

fn scheme_to_protocol(scheme: &str) -> &'static str {
    match scheme {
        "socks" | "socks5" => "socks5",
        "http" => "http",
        "https" => "https",
        "ss" | "shadowsocks" => "shadowsocks",
        "vmess" => "vmess",
        "vless" => "vless",
        "hysteria2" | "hy2" => "hysteria2",
        "trojan" => "trojan",
        "trojan-go" => "trojan-go",
        "tuic" => "tuic",
        "juicity" => "juicity",
        _ => "unknown",
    }
}

fn split_plaintext_tag(link: &str) -> (Option<String>, &str) {
    let Some(i_colon) = link.find(':') else {
        return (None, link);
    };
    if link[i_colon..].starts_with("://") {
        return (None, link);
    }
    (Some(link[..i_colon].to_owned()), &link[i_colon + 1..])
}

fn property_name(scheme: &str, raw: &str) -> String {
    if scheme == "vmess" {
        return VMessLink::parse(raw)
            .ok()
            .map(|link| link.ps)
            .unwrap_or_default();
    }
    raw.split_once('#')
        .map(|(_, fragment)| fragment.to_owned())
        .unwrap_or_default()
}

fn property_address(scheme: &str, raw: &str) -> Option<String> {
    if matches!(scheme, "ss" | "shadowsocks") {
        return ShadowsocksLink::parse(raw).ok().map(|link| link.address());
    }
    if matches!(scheme, "trojan" | "trojan-go") {
        return TrojanLink::parse(raw).ok().map(|link| link.address());
    }
    if scheme == "vmess" {
        return VMessLink::parse(raw).ok().map(|link| link.address());
    }
    if scheme == "vless" {
        return VLESSLink::parse(raw).ok().map(|link| link.address());
    }
    if matches!(scheme, "hysteria2" | "hy2") {
        return Hysteria2Link::parse(raw)
            .ok()
            .map(|link| link.property_address());
    }
    if scheme == "tuic" {
        return TuicLink::parse(raw).ok().map(|link| link.address());
    }
    if scheme == "juicity" {
        return JuicityLink::parse(raw).ok().map(|link| link.address());
    }
    if !matches!(scheme, "socks" | "socks5") {
        return None;
    }
    let (_, rest) = raw.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map(|(_, authority)| authority)
        .unwrap_or(authority);
    Some(authority.to_owned())
}

fn trojan_protocol(raw: &str) -> &'static str {
    TrojanLink::parse(raw)
        .ok()
        .map(|link| {
            if link.protocol == "trojan-go" {
                "trojan-go"
            } else {
                "trojan"
            }
        })
        .unwrap_or("trojan")
}

fn shadowsocks_protocol(raw: &str) -> &'static str {
    ShadowsocksLink::parse(raw)
        .ok()
        .and_then(|link| link.capability_label().ok())
        .unwrap_or_else(|| {
            if raw.contains("2022-blake3-") {
                "shadowsocks-2022"
            } else {
                "shadowsocks"
            }
        })
}
