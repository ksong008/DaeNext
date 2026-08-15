use dae_dns::DNS_DEFAULT_PORT;

use super::*;
use crate::RESIDENT_UDP_RESPONSE_TIMEOUT;
use crate::dns::{
    DnsTcpFrameReader, build_dns_server_failure_response, handle_resident_dns_tcp_async,
    write_dns_tcp_payload_async,
};

pub(super) fn transparent_tcp_dns_destination(original_dst: SocketAddr) -> bool {
    original_dst.port() == DNS_DEFAULT_PORT
}

pub(super) fn transparent_tcp_dns_fast_path_applies(
    original_dst: SocketAddr,
    initial_route: Option<&BpfRoutingResult>,
) -> bool {
    transparent_tcp_dns_destination(original_dst)
        && initial_route.is_none_or(|route| route.must == 0)
}

pub(super) async fn handle_transparent_tcp_dns_fast_path_async(
    inbound: &mut TokioTcpStream,
    original_dst: SocketAddr,
    dns: Arc<ResidentDnsPlan>,
    stop: SharedResidentStopSignal,
    metrics: Arc<ResidentDataplaneMetrics>,
) -> Result<(), String> {
    let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
    let mut frame_reader = DnsTcpFrameReader::default();
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let Some(request) = frame_reader.read_frame(inbound).await? else {
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
    fn transparent_tcp_dns_fast_path_uses_dns_default_port_without_an_explicit_route() {
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), DNS_DEFAULT_PORT);
        let non_dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), 853);

        assert!(transparent_tcp_dns_destination(dns_dst));
        assert!(transparent_tcp_dns_fast_path_applies(dns_dst, None));
        assert!(!transparent_tcp_dns_destination(non_dns_dst));
        assert!(!transparent_tcp_dns_fast_path_applies(non_dns_dst, None));
    }

    #[test]
    fn transparent_tcp_dns_fast_path_preserves_non_must_capture() {
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), DNS_DEFAULT_PORT);
        let route = BpfRoutingResult {
            outbound: OutboundIndex::USER_DEFINED_MIN.value(),
            must: 0,
            ..BpfRoutingResult::default()
        };

        assert!(transparent_tcp_dns_fast_path_applies(dns_dst, Some(&route)));
    }

    #[test]
    fn transparent_tcp_dns_fast_path_honors_every_must_outbound_kind() {
        let dns_dst = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 53).into(), DNS_DEFAULT_PORT);
        for outbound in [
            OUTBOUND_DIRECT,
            OUTBOUND_BLOCK,
            OutboundIndex::USER_DEFINED_MIN.value(),
        ] {
            let route = BpfRoutingResult {
                outbound,
                must: 1,
                ..BpfRoutingResult::default()
            };

            assert!(!transparent_tcp_dns_fast_path_applies(
                dns_dst,
                Some(&route)
            ));
        }
    }
}
