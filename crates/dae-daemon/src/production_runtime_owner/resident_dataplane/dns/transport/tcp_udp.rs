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
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Result<Vec<u8>, String> {
    let resolved_targets = resolved_upstream_targets(upstream).await?;
    let mut failures = Vec::new();
    match select_dns_upstream_targets(plan, upstream, resolved_targets.clone(), L4Proto::Udp) {
        Ok((targets, selection_failures)) => {
            failures.extend(selection_failures);
            if targets.is_empty() {
                failures.push(format!(
                    "UDP phase for upstream {} {} had no target attempted",
                    upstream.tag, upstream.target.authority
                ));
            } else if let Some(response) = forward_dns_udp_candidates_async(
                upstream,
                payload,
                targets,
                &mut failures,
                forwarders,
            )
            .await
            {
                return Ok(response);
            }
        }
        Err(err) => failures.push(format!("select UDP phase: {err}")),
    }

    match select_dns_upstream_targets(plan, upstream, resolved_targets, L4Proto::Tcp) {
        Ok((tcp_targets, selection_failures)) => {
            failures.extend(selection_failures);
            if let Some(response) = forward_dns_tcp_candidates_async(
                upstream,
                payload,
                tcp_targets,
                &mut failures,
                forwarders,
            )
            .await
            {
                return Ok(response);
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

async fn forward_dns_udp_candidates_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    targets: Vec<ResidentDnsUpstreamRoutedTarget>,
    failures: &mut Vec<String>,
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Option<Vec<u8>> {
    for target in targets {
        let target_text = target.target.to_string();
        match forward_dns_udp_to_routed_target_async(upstream, target, payload, forwarders).await {
            Ok(response) if !dns_response_truncated(&response) => return Some(response),
            Ok(_) => failures.push(format!("{target_text} UDP response truncated")),
            Err(err) => failures.push(format!("UDP: {err}")),
        }
    }
    None
}

async fn forward_dns_tcp_candidates_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    targets: Vec<ResidentDnsUpstreamRoutedTarget>,
    failures: &mut Vec<String>,
    forwarders: &Arc<ResidentDnsForwarderCache>,
) -> Option<Vec<u8>> {
    let attempted = !targets.is_empty();
    for target in targets {
        match forward_dns_tcp_to_routed_target_async(upstream, target, payload, forwarders).await {
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
