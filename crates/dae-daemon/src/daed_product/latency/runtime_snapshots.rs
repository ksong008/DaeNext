use super::super::*;
pub(crate) use dae_product_control::subscription::{
    node_name_from_link, runtime_execution_identity, runtime_link_hash,
    runtime_link_identity_value, runtime_redacted_link_source,
};

pub(crate) fn fake_runtime_probe_node_latencies(
    control_runtime: &ProductControlRuntime,
    links: &[String],
) -> Vec<Value> {
    links
        .iter()
        .filter(|link| !link.is_empty())
        .map(|link| fake_runtime_tcp_latency_snapshot_on_control(control_runtime, link))
        .collect()
}

#[cfg(test)]
pub(crate) fn fake_runtime_tcp_latency_snapshot(link: &str) -> Value {
    let control_runtime = product_test_control_runtime();
    fake_runtime_tcp_latency_snapshot_on_control(&control_runtime, link)
}

fn fake_runtime_tcp_latency_snapshot_on_control(
    control_runtime: &ProductControlRuntime,
    link: &str,
) -> Value {
    let checked_at = unix_now() as i64;
    let started = Instant::now();
    let probe = fake_runtime_tcp_connect(control_runtime, link);
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

fn fake_runtime_tcp_connect(
    control_runtime: &ProductControlRuntime,
    link: &str,
) -> Result<(), String> {
    let url = url::Url::parse(link).map_err(|err| format!("parse node link: {err}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "node link does not contain a host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "node link does not contain a port".to_owned())?;
    let mut last_error = None;
    for addr in
        resolve_tcp_addrs_on_control(control_runtime, host, port, Duration::from_millis(500))
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
