use super::super::*;
use super::plain::{
    forward_dns_tcp_to_routed_target_async, forward_dns_udp_to_routed_target_async,
};
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_candidates_for_l4protos,
    dns_upstream_targets_failed, resolved_upstream_targets, select_dns_upstream_candidates,
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
    let candidates =
        dns_upstream_candidates_for_l4protos(&resolved_targets, &[L4Proto::Udp, L4Proto::Tcp]);
    match select_dns_upstream_candidates(plan, upstream, candidates) {
        Ok((mut targets, selection_failures)) => {
            failures.extend(selection_failures);
            if targets.is_empty() {
                failures.push(format!(
                    "candidate selection for upstream {} {} had no target attempted",
                    upstream.tag, upstream.target.authority
                ));
            } else {
                let primary = targets.remove(0);
                match primary.l4proto {
                    L4Proto::Tcp => {
                        let mut tcp_targets = vec![primary];
                        tcp_targets.extend(
                            targets
                                .into_iter()
                                .filter(|target| target.l4proto == L4Proto::Tcp),
                        );
                        if let Some(response) = forward_dns_tcp_candidates_async(
                            upstream,
                            payload,
                            tcp_targets,
                            &mut failures,
                        )
                        .await
                        {
                            return Ok(response);
                        }
                    }
                    L4Proto::Udp => {
                        match forward_dns_udp_primary_async(primary, payload).await {
                            DnsTcpUdpPrimaryResult::Answered(response) => return Ok(response),
                            DnsTcpUdpPrimaryResult::TcpFallbackNeeded(phase_failures) => {
                                failures.extend(phase_failures);
                            }
                        }
                        match select_dns_upstream_targets(
                            plan,
                            upstream,
                            resolved_targets,
                            L4Proto::Tcp,
                        ) {
                            Ok((tcp_targets, selection_failures)) => {
                                failures.extend(selection_failures);
                                if let Some(response) = forward_dns_tcp_candidates_async(
                                    upstream,
                                    payload,
                                    tcp_targets,
                                    &mut failures,
                                )
                                .await
                                {
                                    return Ok(response);
                                }
                            }
                            Err(err) => failures.push(format!("select TCP fallback phase: {err}")),
                        }
                    }
                }
            }
        }
        Err(err) => failures.push(format!("select tcp+udp candidate: {err}")),
    }

    Err(dns_upstream_targets_failed(
        upstream,
        "forward DNS tcp+udp to",
        failures,
    ))
}

enum DnsTcpUdpPrimaryResult {
    Answered(Vec<u8>),
    TcpFallbackNeeded(Vec<String>),
}

async fn forward_dns_udp_primary_async(
    target: ResidentDnsUpstreamRoutedTarget,
    payload: &[u8],
) -> DnsTcpUdpPrimaryResult {
    let target_text = target.target.to_string();
    match forward_dns_udp_to_routed_target_async(target, payload).await {
        Ok(response) if !dns_response_truncated(&response) => {
            DnsTcpUdpPrimaryResult::Answered(response)
        }
        Ok(_) => DnsTcpUdpPrimaryResult::TcpFallbackNeeded(vec![format!(
            "{target_text} UDP response truncated"
        )]),
        Err(err) => DnsTcpUdpPrimaryResult::TcpFallbackNeeded(vec![format!("UDP: {err}")]),
    }
}

async fn forward_dns_tcp_candidates_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    targets: Vec<ResidentDnsUpstreamRoutedTarget>,
    failures: &mut Vec<String>,
) -> Option<Vec<u8>> {
    let attempted = !targets.is_empty();
    for target in targets {
        match forward_dns_tcp_to_routed_target_async(upstream, target, payload).await {
            Ok(response) => return Some(response),
            Err(err) => failures.push(format!("TCP fallback: {err}")),
        }
    }
    if !attempted {
        failures.push(format!(
            "TCP fallback for upstream {} {} had no target attempted",
            upstream.tag, upstream.target.authority
        ));
    }
    None
}
