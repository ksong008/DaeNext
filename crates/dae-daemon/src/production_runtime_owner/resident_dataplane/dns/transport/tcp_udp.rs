use super::super::*;
use super::ResidentDnsTransportError;
use super::plain::{
    forward_dns_tcp_to_routed_target_async, forward_dns_udp_to_routed_target_async,
};
use super::route::{
    ResidentDnsUpstreamRoutedTarget, dns_upstream_targets_failed, race_dns_upstream_targets,
    resolved_upstream_targets, select_dns_upstream_targets,
};
use super::wire::dns_response_truncated;

pub(super) async fn forward_dns_tcp_udp_async(
    upstream: &ResidentDnsUpstream,
    payload: &[u8],
    plan: &ResidentDnsPlan,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let resolved = resolved_upstream_targets(upstream)
        .await
        .map_err(ResidentDnsTransportError::message)?;
    let udp_selection =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Udp);
    let tcp_selection =
        select_dns_upstream_targets(plan, upstream, resolved.to_vec(), L4Proto::Tcp);

    let udp = forward_dns_udp_branch_async(
        upstream,
        &resolved,
        payload,
        udp_selection,
        forwarders,
        context,
    );
    let tcp = forward_dns_tcp_branch_async(
        upstream,
        &resolved,
        payload,
        tcp_selection,
        forwarders,
        context,
    );
    tokio::pin!(udp);
    tokio::pin!(tcp);

    tokio::select! {
        udp_result = &mut udp => match udp_result {
            Ok(response) => Ok(response),
            Err(udp_error) => match tcp.await {
                Ok(response) => Ok(response),
                Err(tcp_error) => Err(combined_tcp_udp_error(upstream, udp_error, tcp_error)),
            },
        },
        tcp_result = &mut tcp => match tcp_result {
            Ok(response) => Ok(response),
            Err(tcp_error) => match udp.await {
                Ok(response) => Ok(response),
                Err(udp_error) => Err(combined_tcp_udp_error(upstream, udp_error, tcp_error)),
            },
        },
    }
}

async fn forward_dns_udp_branch_async(
    upstream: &ResidentDnsUpstream,
    resolved: &ResidentDnsResolvedTargetSnapshot,
    payload: &[u8],
    selection: Result<(Vec<ResidentDnsUpstreamRoutedTarget>, Vec<String>), String>,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let (targets, mut failures) = selection.map_err(|error| {
        ResidentDnsTransportError::message(format!("select UDP branch: {error}"))
    })?;
    if targets.is_empty() {
        failures.push(format!(
            "UDP branch for upstream {} {} had no target attempted",
            upstream.tag, upstream.target.authority
        ));
    }
    race_dns_upstream_targets(
        upstream,
        resolved,
        "forward DNS tcp+udp UDP branch to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        |target| async move {
            let target_text = target.target.to_string();
            let response = forward_dns_udp_to_routed_target_async(
                upstream, target, payload, forwarders, context,
            )
            .await?;
            if dns_response_truncated(&response) {
                Err(ResidentDnsTransportError::message(format!(
                    "{target_text} UDP response truncated"
                )))
            } else {
                Ok(response)
            }
        },
    )
    .await
}

async fn forward_dns_tcp_branch_async(
    upstream: &ResidentDnsUpstream,
    resolved: &ResidentDnsResolvedTargetSnapshot,
    payload: &[u8],
    selection: Result<(Vec<ResidentDnsUpstreamRoutedTarget>, Vec<String>), String>,
    forwarders: &Arc<ResidentDnsForwarderCache>,
    context: ProxyDnsRequestContext,
) -> Result<Vec<u8>, ResidentDnsTransportError> {
    let (targets, mut failures) = selection.map_err(|error| {
        ResidentDnsTransportError::message(format!("select TCP branch: {error}"))
    })?;
    if targets.is_empty() {
        failures.push(format!(
            "TCP branch for upstream {} {} had no target attempted",
            upstream.tag, upstream.target.authority
        ));
    }
    race_dns_upstream_targets(
        upstream,
        resolved,
        "forward DNS tcp+udp TCP branch to",
        targets,
        failures,
        forwarders.resources.upstream_candidate_race_width(),
        |target| async move {
            forward_dns_tcp_to_routed_target_async(upstream, target, payload, forwarders, context)
                .await
        },
    )
    .await
}

fn combined_tcp_udp_error(
    upstream: &ResidentDnsUpstream,
    udp: ResidentDnsTransportError,
    tcp: ResidentDnsTransportError,
) -> ResidentDnsTransportError {
    ResidentDnsTransportError::message(dns_upstream_targets_failed(
        upstream,
        "forward DNS tcp+udp to",
        vec![format!("UDP branch: {udp}"), format!("TCP branch: {tcp}")],
    ))
}
