use super::tcp::fetch_resident_proxy_http_response_async;
use super::*;

pub(crate) fn fetch_http_url_via_default_proxy(
    config: &Config,
    url: &url::Url,
    tls: bool,
    request: &[u8],
    response_limit: usize,
) -> Result<Vec<u8>, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "subscription proxy fetch missing host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "subscription proxy fetch missing port".to_owned())?;
    let plan = build_resident_dataplane_plan(config)?;
    let mut proxy = plan
        .default_proxy_snapshot()
        .ok_or_else(|| "subscription proxy fetch has no default proxy node".to_owned())?;
    proxy.apply_latency_probe_control_mark(plan::RESIDENT_CONTROL_PLANE_SO_MARK);
    proxy.disable_latency_probe_persistent_caches();
    proxy.compact_allocations();

    let runtime = build_transient_probe_runtime("subscription proxy fetch")?;
    let response = runtime.block_on(fetch_resident_proxy_http_response_async(
        Arc::new(proxy),
        tls,
        &format_subscription_target(host, port),
        host,
        request,
        response_limit,
        Duration::from_secs(20),
    ));
    drop(runtime);
    response
}

fn format_subscription_target(host: &str, port: u16) -> String {
    if host.starts_with('[') || !host.contains(':') {
        format!("{host}:{port}")
    } else {
        format!("[{host}]:{port}")
    }
}
