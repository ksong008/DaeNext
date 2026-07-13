use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SubscriptionContentKind {
    Empty,
    Sip008,
    PlainText,
    Base64,
    Unrecognized,
}

impl SubscriptionContentKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Sip008 => "sip008",
            Self::PlainText => "plain-text",
            Self::Base64 => "base64",
            Self::Unrecognized => "unrecognized",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SubscriptionContentReport {
    pub(super) kind: SubscriptionContentKind,
    pub(super) links: Vec<String>,
    pub(super) source_node_count: usize,
    pub(super) invalid_source_count: usize,
    pub(super) empty: bool,
}

impl SubscriptionContentReport {
    #[cfg(test)]
    pub(super) fn from_links(links: &[String]) -> Self {
        Self {
            kind: if links.is_empty() {
                SubscriptionContentKind::Empty
            } else {
                SubscriptionContentKind::PlainText
            },
            links: links.to_vec(),
            source_node_count: links.len(),
            invalid_source_count: 0,
            empty: links.is_empty(),
        }
    }
}

pub(super) fn parse_subscription_content(content: &str) -> SubscriptionContentReport {
    if content.trim().is_empty() {
        return SubscriptionContentReport {
            kind: SubscriptionContentKind::Empty,
            links: Vec::new(),
            source_node_count: 0,
            invalid_source_count: 0,
            empty: true,
        };
    }
    if let Some(report) = sip008_report_from_content(content) {
        return report;
    }
    let direct = node_link_report_from_text(content, SubscriptionContentKind::PlainText);
    if !direct.links.is_empty() {
        return direct;
    }
    if let Some(report) = decoded_node_link_report(content) {
        return report;
    }
    SubscriptionContentReport {
        kind: SubscriptionContentKind::Unrecognized,
        links: Vec::new(),
        source_node_count: direct.source_node_count,
        invalid_source_count: direct.source_node_count,
        empty: direct.empty,
    }
}

#[cfg(test)]
pub(crate) fn subscription_links_from_content(content: &str) -> Vec<String> {
    parse_subscription_content(content).links
}

fn decoded_node_link_report(content: &str) -> Option<SubscriptionContentReport> {
    let compact = content.split_whitespace().collect::<String>();
    let padded = format!("{compact}{}", "=".repeat((4 - compact.len() % 4) % 4));
    let candidates = [
        compact.clone(),
        padded,
        compact.trim_end_matches('=').to_owned(),
        compact.replace('+', "-").replace('/', "_"),
    ];
    let mut seen = HashSet::new();
    for candidate in candidates {
        if !seen.insert(candidate.clone()) {
            continue;
        }
        for decoded in [
            STANDARD.decode(candidate.as_bytes()),
            URL_SAFE_NO_PAD.decode(candidate.as_bytes()),
        ] {
            let Ok(decoded) = decoded else {
                continue;
            };
            let decoded = String::from_utf8_lossy(&decoded);
            let report = node_link_report_from_text(&decoded, SubscriptionContentKind::Base64);
            if !report.links.is_empty() {
                return Some(report);
            }
        }
    }
    None
}

fn node_link_report_from_text(
    text: &str,
    kind: SubscriptionContentKind,
) -> SubscriptionContentReport {
    let meaningful = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    let links = meaningful
        .iter()
        .filter(|line| line.contains("://"))
        .map(|line| (*line).to_owned())
        .collect::<Vec<_>>();
    SubscriptionContentReport {
        kind,
        source_node_count: meaningful.len(),
        invalid_source_count: meaningful.len().saturating_sub(links.len()),
        empty: meaningful.is_empty(),
        links,
    }
}

fn sip008_report_from_content(content: &str) -> Option<SubscriptionContentReport> {
    let value: Value = serde_json::from_str(content).ok()?;
    if value.get("version").and_then(Value::as_i64) != Some(1) {
        return None;
    }
    let servers = value.get("servers")?.as_array()?;
    let links = servers
        .iter()
        .filter_map(sip008_server_to_ss_link)
        .collect::<Vec<_>>();
    Some(SubscriptionContentReport {
        kind: SubscriptionContentKind::Sip008,
        source_node_count: servers.len(),
        invalid_source_count: servers.len().saturating_sub(links.len()),
        empty: servers.is_empty(),
        links,
    })
}

fn sip008_server_to_ss_link(server: &Value) -> Option<String> {
    let host = server.get("server")?.as_str()?.trim();
    let port = server.get("server_port")?.as_u64()?;
    let method = server.get("method")?.as_str()?;
    let password = server.get("password")?.as_str()?;
    if host.is_empty() || port > u16::MAX as u64 || method.is_empty() {
        return None;
    }
    let mut url = url::Url::parse(&format!("ss://{}", format_host_port(host, port as u16))).ok()?;
    url.set_username(method).ok()?;
    url.set_password(Some(password)).ok()?;
    let plugin = server.get("plugin").and_then(Value::as_str).unwrap_or("");
    let plugin_opts = server
        .get("plugin_opts")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !plugin.is_empty() || !plugin_opts.is_empty() {
        let plugin_value = if plugin.is_empty() {
            plugin_opts.to_owned()
        } else if plugin_opts.is_empty() {
            plugin.to_owned()
        } else {
            format!("{plugin};{plugin_opts}")
        };
        url.query_pairs_mut().append_pair("plugin", &plugin_value);
    }
    if let Some(remarks) = server.get("remarks").and_then(Value::as_str)
        && !remarks.is_empty()
    {
        url.set_fragment(Some(remarks));
    }
    Some(url.to_string())
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.starts_with('[') || !host.contains(':') {
        format!("{host}:{port}")
    } else {
        format!("[{host}]:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_report_distinguishes_empty_invalid_and_partial_sip008() {
        let empty = parse_subscription_content("  \n# comment\n");
        assert!(empty.empty);
        assert_eq!(empty.kind, SubscriptionContentKind::Unrecognized);
        assert_eq!(empty.source_node_count, 0);

        let invalid = parse_subscription_content("not-a-node\nstill-not-a-node\n");
        assert!(!invalid.empty);
        assert_eq!(invalid.kind, SubscriptionContentKind::Unrecognized);
        assert_eq!(invalid.source_node_count, 2);
        assert_eq!(invalid.invalid_source_count, 2);

        let sip008 = parse_subscription_content(
            r#"{
                "version": 1,
                "servers": [
                    {"server":"127.0.0.1","server_port":8388,"method":"aes-128-gcm","password":"secret"},
                    {"server":"missing-fields"}
                ]
            }"#,
        );
        assert_eq!(sip008.kind, SubscriptionContentKind::Sip008);
        assert_eq!(sip008.source_node_count, 2);
        assert_eq!(sip008.links.len(), 1);
        assert_eq!(sip008.invalid_source_count, 1);
    }
}
