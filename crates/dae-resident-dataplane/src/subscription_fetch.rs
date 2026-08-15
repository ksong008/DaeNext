use super::control_transport_owners::{ControlTransportOwnerRequirements, ControlTransportOwners};
use super::tcp::fetch_resident_proxy_http_response_async;
use super::*;

#[cfg(test)]
mod tests;

pub async fn fetch_http_url_via_default_proxy_async<C>(
    config: &Config,
    url: &url::Url,
    tls: bool,
    request: &[u8],
    response_limit: usize,
    cancellation: C,
) -> Result<Vec<u8>, String>
where
    C: std::future::Future<Output = ()> + Send,
{
    let host = url
        .host_str()
        .ok_or_else(|| "subscription proxy fetch missing host".to_owned())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "subscription proxy fetch missing port".to_owned())?;
    let plan = build_resident_dataplane_plan(config)?;
    let mut proxy = plan
        .default_proxy_binding()
        .ok_or_else(|| "subscription proxy fetch has no default proxy node".to_owned())?;
    proxy.bind_control_plane();
    proxy.apply_control_socket_mark(plan::RESIDENT_CONTROL_PLANE_SO_MARK);
    let proxy = proxy.without_persistent_xhttp_reuse();
    let requirements = ControlTransportOwnerRequirements::from_binding(&proxy);
    let resources = ResidentRuntimeResourceConfig::from_config(config);
    let runtime = tokio::runtime::Handle::current();
    tokio::pin!(cancellation);
    let owner_admission = tokio::select! {
        _ = &mut cancellation => return Err("subscription proxy fetch cancelled".to_owned()),
        admission = ControlTransportOwners::admit(
            0,
            requirements,
        ) => admission.map_err(|error| error.to_string())?,
    };
    let mut owners = ControlTransportOwners::start_admitted(
        &runtime,
        0,
        resources.tcp_runtime_workers.value(),
        requirements,
        owner_admission,
    )
    .await
    .map_err(|error| error.to_string())?;
    let registries = owners.registries();
    let target = format_subscription_target(host, port);
    let response = tokio::select! {
        _ = &mut cancellation => Err("subscription proxy fetch cancelled".to_owned()),
        response = fetch_resident_proxy_http_response_async(
            proxy,
            tls,
            &target,
            host,
            request,
            response_limit,
            Duration::from_secs(20),
            registries.hysteria2(),
            registries.tuic(),
            registries.juicity(),
            registries.anytls(),
        ) => response,
    };
    let shutdown = owners.shutdown().await;
    if !shutdown.is_clean() {
        return Err(format!(
            "control transport owner cleanup degraded: joined={}, cancelled={}, panicked={}, forced={}",
            shutdown.joined, shutdown.cancelled, shutdown.panicked, shutdown.forced,
        ));
    }
    response
}

fn format_subscription_target(host: &str, port: u16) -> String {
    if host.starts_with('[') || !host.contains(':') {
        format!("{host}:{port}")
    } else {
        format!("[{host}]:{port}")
    }
}
