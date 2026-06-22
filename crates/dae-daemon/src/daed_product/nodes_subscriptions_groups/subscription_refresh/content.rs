use super::*;

pub(crate) fn subscription_links_from_content(content: &str) -> Vec<String> {
    if let Some(links) = sip008_links_from_content(content) {
        return links;
    }
    let direct = node_links_from_text(content);
    if !direct.is_empty() {
        return direct;
    }
    let compact = content.split_whitespace().collect::<String>();
    for candidate in [
        compact.clone(),
        format!("{compact}{}", "=".repeat((4 - compact.len() % 4) % 4)),
    ] {
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            let decoded = String::from_utf8_lossy(&decoded);
            let links = node_links_from_text(&decoded);
            if !links.is_empty() {
                return links;
            }
        }
    }
    for candidate in [
        compact.clone(),
        compact.trim_end_matches('=').to_owned(),
        compact.replace('+', "-").replace('/', "_"),
    ] {
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate.as_bytes()) {
            let decoded = String::from_utf8_lossy(&decoded);
            let links = node_links_from_text(&decoded);
            if !links.is_empty() {
                return links;
            }
        }
    }
    Vec::new()
}

pub(crate) fn node_links_from_text(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.contains("://"))
        .map(str::to_owned)
        .collect()
}

pub(crate) fn sip008_links_from_content(content: &str) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(content).ok()?;
    if value.get("version").and_then(Value::as_i64) != Some(1) {
        return None;
    }
    let servers = value.get("servers")?.as_array()?;
    let mut links = Vec::with_capacity(servers.len());
    for server in servers {
        if let Some(link) = sip008_server_to_ss_link(server) {
            links.push(link);
        }
    }
    Some(links)
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
