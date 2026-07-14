use super::*;

pub(super) async fn wait_proxy_dns_udp_response(
    executor: &mut Option<Box<UdpSessionExecutor>>,
    enabled: bool,
) -> Result<Option<(&'static str, UdpExchangeResult)>, String> {
    if !enabled {
        return std::future::pending().await;
    }
    let Some(executor) = executor.as_mut() else {
        return std::future::pending().await;
    };
    executor.wait_response().await
}

pub(super) async fn reset_proxy_dns_udp_executor(
    executor: &mut Option<Box<UdpSessionExecutor>>,
    timeout: Duration,
    metrics: &ResidentDataplaneMetrics,
) {
    let Some(mut failed) = executor.take() else {
        return;
    };
    let _ = time::timeout(timeout, failed.shutdown()).await;
    metrics.proxy_dns_udp_executor_reset();
}
