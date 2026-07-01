use super::super::*;
use super::plain::{
    forward_dns_tcp_to_routed_target_async, forward_dns_udp_to_routed_target_async,
};
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, resolved_upstream_targets,
    select_dns_upstream_targets,
};
use super::wire::dns_response_truncated;

pub(super) async fn forward_dns_tcp_udp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
) -> Result<Vec<u8>, String> {
    let resolved_targets = resolved_upstream_targets(upstream).await?;
    let mut failures = Vec::new();

    match select_dns_upstream_targets(plan, upstream, resolved_targets.clone(), L4Proto::Udp) {
        Ok((targets, selection_failures)) => {
            failures.extend(selection_failures);
            match forward_dns_tcp_udp_phase_async(upstream, payload, targets).await {
                DnsTcpUdpPhaseResult::Answered(response) => return Ok(response),
                DnsTcpUdpPhaseResult::TcpFallbackNeeded(phase_failures) => {
                    failures.extend(phase_failures);
                }
            }
        }
        Err(err) => failures.push(format!("select UDP phase: {err}")),
    }

    match select_dns_upstream_targets(plan, upstream, resolved_targets, L4Proto::Tcp) {
        Ok((targets, selection_failures)) => {
            failures.extend(selection_failures);
            for target in targets {
                match forward_dns_tcp_to_routed_target_async(upstream, target, payload).await {
                    Ok(response) => return Ok(response),
                    Err(err) => failures.push(format!("TCP fallback: {err}")),
                }
            }
        }
        Err(err) => failures.push(format!("select TCP fallback phase: {err}")),
    }

    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS tcp+udp to",
        failures,
    ))
}

enum DnsTcpUdpPhaseResult {
    Answered(Vec<u8>),
    TcpFallbackNeeded(Vec<String>),
}

async fn forward_dns_tcp_udp_phase_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    targets: Vec<ResidentDnsUpstreamRoutedTarget>,
) -> DnsTcpUdpPhaseResult {
    let mut failures = Vec::new();
    for target in targets {
        let target_text = target.target.to_string();
        match forward_dns_udp_to_routed_target_async(target, payload).await {
            Ok(response) if !dns_response_truncated(&response) => {
                return DnsTcpUdpPhaseResult::Answered(response);
            }
            Ok(_) => {
                failures.push(format!("{target_text} UDP response truncated"));
                return DnsTcpUdpPhaseResult::TcpFallbackNeeded(failures);
            }
            Err(err) => failures.push(format!("UDP: {err}")),
        }
    }
    if failures.is_empty() {
        failures.push(format!(
            "UDP phase for upstream {} {} had no target attempted",
            upstream.tag, upstream.target.authority
        ));
    }
    DnsTcpUdpPhaseResult::TcpFallbackNeeded(failures)
}
