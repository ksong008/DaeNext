use super::super::*;

pub(crate) fn fake_runtime_probe_node_latencies(links: &[String]) -> Vec<Value> {
    links
        .iter()
        .filter(|link| !link.is_empty())
        .map(|link| fake_runtime_tcp_latency_snapshot(link))
        .collect()
}

pub(crate) fn fake_runtime_tcp_latency_snapshot(link: &str) -> Value {
    let checked_at = unix_now() as i64;
    let started = Instant::now();
    let probe = fake_runtime_tcp_connect(link);
    let latency_ms = probe
        .as_ref()
        .ok()
        .map(|_| started.elapsed().as_millis() as i64);
    let display_name = node_name_from_link(link);
    let link_hash = runtime_link_hash(link);
    let execution_identity = runtime_execution_identity(link);
    let redacted_source = runtime_redacted_link_source(link);
    json!({
        "name": display_name.as_str(),
        "displayName": display_name.as_str(),
        "linkHash": link_hash.as_str(),
        "executionIdentity": execution_identity,
        "linkIdentity": runtime_link_identity_value(&display_name, &link_hash, &redacted_source),
        "latencyMs": latency_ms,
        "alive": latency_ms.is_some(),
        "checkedAtUnix": checked_at,
        "message": probe.err(),
        "scope": "fake-runtime-tcp-check",
    })
}

pub(crate) fn fake_runtime_tcp_connect(link: &str) -> Result<(), String> {
    let url = url::Url::parse(link).map_err(|err| format!("parse node link: {err}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "node link does not contain a host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "node link does not contain a port".to_owned())?;
    let mut last_error = None;
    for addr in resolve_tcp_addrs(host, port, Duration::from_millis(500))
        .map_err(|err| format!("resolve node endpoint: {err}"))?
    {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(_) => return Ok(()),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error
        .map(|err| format!("connect node endpoint: {err}"))
        .unwrap_or_else(|| "node endpoint resolved to no socket addresses".to_owned()))
}

pub(crate) fn node_name_from_link(link: &str) -> String {
    url::Url::parse(link)
        .ok()
        .and_then(|url| url.fragment().map(str::to_owned))
        .filter(|fragment| !fragment.is_empty())
        .unwrap_or_default()
}

pub(crate) fn runtime_link_identity_value(
    display_name: &str,
    link_hash: &str,
    redacted_source: &str,
) -> Value {
    json!({
        "schemaVersion": 1,
        "displayName": display_name,
        "linkHash": link_hash,
        "redactedSource": redacted_source,
    })
}

pub(crate) fn runtime_link_hash(link: &str) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(link.as_bytes())))
}

pub(crate) fn runtime_execution_identity(link: &str) -> String {
    runtime_link_hash(&dae_outbound::canonical_link_without_display_name(link))
}

pub(crate) fn runtime_redacted_link_source(link: &str) -> String {
    let Ok(url) = url::Url::parse(link) else {
        return "link:<redacted>".to_owned();
    };
    let mut value = format!("{}:<redacted>", url.scheme());
    if let Some(fragment) = url.fragment().filter(|fragment| !fragment.is_empty()) {
        value.push('#');
        value.push_str(fragment);
    }
    value
}
