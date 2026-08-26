use crate::StableNodeKey;

#[derive(Clone, Debug)]
pub struct ParsedNodeLink {
    pub display_name: String,
    pub address: String,
    pub protocol: String,
    pub stable_key: StableNodeKey,
    pub normalized_link: Option<String>,
}

pub fn parse_node_link(link: &str, tag: Option<&str>) -> ParsedNodeLink {
    if let Some(parsed) = parse_node_link_with_outbound_parser(link, tag) {
        return parsed;
    }
    let protocol = link
        .split_once("://")
        .map(|(value, _)| value)
        .unwrap_or("unknown");
    let parsed_url = url::Url::parse(link).ok();
    let address = parsed_url
        .as_ref()
        .and_then(url::Url::host_str)
        .map(str::to_owned)
        .or_else(|| {
            link.split_once("://").map(|(_, rest)| {
                rest.split(['@', '/', '?', '#'])
                    .next_back()
                    .unwrap_or(rest)
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .to_owned()
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let display_name = tag
        .map(decode_node_label)
        .or_else(|| parsed_url.and_then(|url| url.fragment().map(decode_node_label)))
        .unwrap_or_else(|| format!("{protocol}-{address}"));
    ParsedNodeLink {
        display_name,
        address,
        protocol: protocol.to_owned(),
        stable_key: StableNodeKey::from_link(link),
        normalized_link: None,
    }
}

fn parse_node_link_with_outbound_parser(link: &str, tag: Option<&str>) -> Option<ParsedNodeLink> {
    let tag = tag.map(decode_node_label);
    if let Ok(parsed) = dae_outbound::VMessLink::parse(link) {
        let address = parsed.address();
        return Some(ParsedNodeLink {
            display_name: tag
                .clone()
                .or_else(|| non_empty(decode_node_label(&parsed.ps)))
                .unwrap_or_else(|| format!("vmess-{address}")),
            address,
            protocol: parsed.protocol,
            stable_key: StableNodeKey::from_link(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::VLESSLink::parse(link) {
        let address = parsed.add.clone();
        return Some(ParsedNodeLink {
            display_name: tag
                .clone()
                .or_else(|| non_empty(decode_node_label(&parsed.ps)))
                .unwrap_or_else(|| format!("vless-{address}")),
            address,
            protocol: parsed.protocol,
            stable_key: StableNodeKey::from_link(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::ShadowsocksLink::parse(link) {
        let address = parsed.address();
        return Some(ParsedNodeLink {
            display_name: tag
                .clone()
                .or_else(|| non_empty(decode_node_label(&parsed.name)))
                .unwrap_or_else(|| format!("{}-{address}", parsed.protocol)),
            address: parsed.server,
            protocol: parsed.protocol,
            stable_key: StableNodeKey::from_link(link),
            normalized_link: None,
        });
    }
    if let Ok(parsed) = dae_outbound::Hysteria2Link::parse(link) {
        let address = parsed.property_address();
        let normalized_link = hysteria2_mport_query_present(link).then(|| parsed.export_url());
        return Some(ParsedNodeLink {
            display_name: tag
                .or_else(|| non_empty(parsed.name))
                .unwrap_or_else(|| format!("hysteria2-{address}")),
            address,
            protocol: "hysteria2".to_owned(),
            stable_key: StableNodeKey::from_link(link),
            normalized_link,
        });
    }
    None
}

fn hysteria2_mport_query_present(link: &str) -> bool {
    let Some((_, rest)) = link.split_once('?') else {
        return false;
    };
    let query = rest.split('#').next().unwrap_or(rest);
    url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key.as_ref() == "mport")
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

pub fn decode_node_label(value: &str) -> String {
    dae_product_core::decode_product_label(value)
}

pub fn decode_percent_escapes(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut changed = false;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            out.push((high << 4) | low);
            changed = true;
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    if changed {
        String::from_utf8_lossy(&out).into_owned()
    } else {
        value.to_owned()
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_is_utf8_boundary_safe() {
        assert_eq!(decode_node_label("%E6%B5%8B%E8%AF%95"), "\u{6d4b}\u{8bd5}");
        assert_eq!(
            decode_node_label("\u{539f}\u{59cb}%20label"),
            "\u{539f}\u{59cb} label"
        );
        assert_eq!(decode_node_label("invalid%GG"), "invalid%GG");
    }
}
