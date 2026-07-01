use std::sync::Arc;
use std::time::Duration;

use super::super::plan::ResidentProxyPlan;
use super::super::tcp::probe_resident_proxy_tcp_async;

#[allow(dead_code)]
pub(in crate::production_runtime_owner::resident_dataplane) async fn probe_native_proxy_tcp_async(
    proxy: Arc<ResidentProxyPlan>,
    scheme: &str,
    target: &str,
    host: &str,
    path: &str,
    method: &str,
    timeout: Duration,
) -> Result<(), String> {
    probe_resident_proxy_tcp_async(proxy, scheme, target, host, path, method, timeout).await
}
