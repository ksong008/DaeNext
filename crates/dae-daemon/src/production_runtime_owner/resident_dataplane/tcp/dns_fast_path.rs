use dae_dns::DNS_DEFAULT_PORT;

use super::*;
use crate::production_runtime_owner::resident_dataplane::RESIDENT_UDP_RESPONSE_TIMEOUT;
use crate::production_runtime_owner::resident_dataplane::dns::{
    build_dns_server_failure_response, handle_resident_dns_tcp_async, read_dns_tcp_payload_async,
    write_dns_tcp_payload_async,
};

pub(super) fn transparent_tcp_dns_fast_path_applies(original_dst: SocketAddr) -> bool {
    original_dst.port() == DNS_DEFAULT_PORT
}

pub(super) async fn handle_transparent_tcp_dns_fast_path_async(
    inbound: &mut TokioTcpStream,
    original_dst: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    stop: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<(), String> {
    let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let Some(request) = read_dns_tcp_payload_async(inbound).await? else {
            return Ok(());
        };
        metrics.add_upload(request.len());
        let response = match time::timeout(
            RESIDENT_UDP_RESPONSE_TIMEOUT,
            handle_resident_dns_tcp_async(&dns, original_dst, &request),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => build_dns_server_failure_response(&request)?,
        };
        write_dns_tcp_payload_async(inbound, &response).await?;
        metrics.add_download(response.len());
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use dae_dns::DNS_DEFAULT_PORT;

    use super::*;

    #[test]
    fn transparent_tcp_dns_fast_path_uses_dns_default_port() {
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), DNS_DEFAULT_PORT);
        let non_dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 853);

        assert!(transparent_tcp_dns_fast_path_applies(dns_dst));
        assert!(!transparent_tcp_dns_fast_path_applies(non_dns_dst));
    }
}
