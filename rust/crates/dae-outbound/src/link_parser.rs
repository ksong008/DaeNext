use crate::error::OutboundError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkNode {
    pub raw: String,
    pub scheme: String,
    pub protocol: String,
    pub parent_dialer_non_nil: bool,
    pub adapter_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkParseResult {
    pub nodes: Vec<LinkNode>,
}

pub fn parse_link_chain(link: &str) -> Result<LinkParseResult, OutboundError> {
    let mut nodes = Vec::new();
    for part in link.split("->") {
        let raw = part.trim();
        let scheme_end = raw.find("://").ok_or(OutboundError::MissingScheme)?;
        let scheme = &raw[..scheme_end];
        let (protocol, parent_dialer_non_nil, adapter_mode) = classify_link(scheme, raw);
        nodes.push(LinkNode {
            raw: raw.to_owned(),
            scheme: scheme.to_owned(),
            protocol: protocol.to_owned(),
            parent_dialer_non_nil,
            adapter_mode: adapter_mode.to_owned(),
        });
    }
    Ok(LinkParseResult { nodes })
}

fn classify_link(scheme: &str, raw: &str) -> (&'static str, bool, &'static str) {
    match scheme {
        "direct" => ("direct", true, "native-boundary"),
        "block" => ("block", true, "native-boundary"),
        "ss" if raw.contains("2022-blake3-") => ("shadowsocks-2022", true, "bridge-or-stub"),
        "ss" => ("shadowsocks", true, "bridge-or-stub"),
        "socks5" | "http" | "https" | "vmess" | "vless" | "hysteria2" | "tuic" | "juicity" => {
            (scheme_to_protocol(scheme), true, "bridge-or-stub")
        }
        _ => ("unknown", false, "unsupported"),
    }
}

fn scheme_to_protocol(scheme: &str) -> &'static str {
    match scheme {
        "socks5" => "socks5",
        "http" => "http",
        "https" => "https",
        "vmess" => "vmess",
        "vless" => "vless",
        "hysteria2" => "hysteria2",
        "tuic" => "tuic",
        "juicity" => "juicity",
        _ => "unknown",
    }
}
