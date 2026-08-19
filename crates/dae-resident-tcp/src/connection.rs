use super::*;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub async fn handle_tcp_connection_async_or_handoff(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    router: Arc<ResidentTcpRouter>,
    stop: SharedResidentStopSignal,
    metrics: Arc<ResidentDataplaneMetrics>,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
) -> Result<Option<Value>, String> {
    let original_dst = resident_normalized_socket_addr(
        match inbound
            .local_addr()
            .map_err(|err| format!("read original TCP destination: {err}"))?
        {
            addr @ (SocketAddr::V4(_) | SocketAddr::V6(_)) => addr,
        },
    );
    inbound
        .set_nodelay(true)
        .map_err(|err| format!("set inbound TCP_NODELAY: {err}"))?;
    let explicit_dns_route = if transparent_tcp_dns_destination(original_dst) {
        router
            .lookup_routing_result(peer, original_dst)
            .ok()
            .filter(|route| route.must > 0)
    } else {
        None
    };
    if transparent_tcp_dns_fast_path_applies(original_dst, explicit_dns_route.as_ref()) {
        let dns = router.dns();
        drop(router);
        Box::pin(handle_transparent_tcp_dns_fast_path_async(
            &mut inbound,
            original_dst,
            dns,
            Arc::clone(&stop),
            Arc::clone(&metrics),
        ))
        .await?;
        return Ok(None);
    }
    let sniffing_timeout = router.sniffing_timeout();
    let dial_mode = router.dial_mode_name();
    let (sniff, selection) = if let Some(initial_route) = explicit_dns_route {
        let sniff = TcpSniffReport {
            payload: Vec::new(),
            domain: String::new(),
            error: None,
        };
        let selection = router.select_from_routing_result_with_domain_real(
            peer,
            original_dst,
            &sniff.domain,
            initial_route,
            false,
        )?;
        (sniff, selection)
    } else {
        let sniff = sniff_initial_tcp_payload_async(&mut inbound, sniffing_timeout).await?;
        let selection = Box::pin(router.select(peer, original_dst, &sniff.domain)).await?;
        (sniff, selection)
    };
    append_event_with_metadata(
        event_file,
        event_lock,
        ResidentEventMetadata::new(ResidentEventKind::TcpRouteChosen),
        || tcp_route_chosen_event(peer, original_dst, &selection, &sniff, dial_mode),
    );
    match selection {
        TcpSelection::Direct(selection) => {
            drop(router);
            let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
            Box::pin(handle_direct_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                Arc::clone(&stop),
                sniff,
                &metrics,
            ))
            .await
            .map(Some)
        }
        TcpSelection::Block(selection) => {
            drop(router);
            let _ = inbound.shutdown().await;
            let mut event = json!({
                "event": "tcp_connection_blocked",
                "outbound_kind": "block",
                "peer": resident_socket_addr_display(peer),
                "original_dst": resident_socket_addr_display(original_dst),
                "dial_target": &selection.route.dial_target,
                "dial_ip": selection.route.dial_ip,
                "initial_outbound": selection.route.initial_outbound,
                "final_outbound": selection.route.final_outbound,
                "final_mark": selection.route.final_mark,
                "userspace_route_executed": selection.route.userspace_route_executed,
                "userspace_route_must": selection.route.userspace_route_must,
                "sniffed_domain": &sniff.domain,
                "sniff_error": &sniff.error,
            });
            append_tcp_execution_fields(&mut event, "async-block");
            append_tcp_route_log_fields(&mut event, &selection.route, "block", "fixed", "block");
            Ok(Some(event))
        }
        TcpSelection::Proxy(selection) => {
            let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
            let runtime_dispatch = selection.proxy.execution_plan().protocol.runtime_dispatch();
            let result = if runtime_dispatch == ResidentTcpRuntimeDispatch::PolicyClosed {
                drop(router);
                Err(format!(
                    "resident TCP dispatcher policy-closed for UDP-only exact protocol shape {:?}",
                    selection.proxy.execution_plan().protocol
                ))
            } else if runtime_dispatch == ResidentTcpRuntimeDispatch::Vless {
                drop(router);
                Box::pin(handle_proxy_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    sniff,
                    &metrics,
                ))
                .await
            } else if runtime_dispatch == ResidentTcpRuntimeDispatch::FrameTls {
                let anytls_owner_registry = router.anytls_owner_registry();
                drop(router);
                Box::pin(handle_frame_tls_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    sniff,
                    &metrics,
                    anytls_owner_registry.as_ref(),
                    None,
                ))
                .await
            } else if runtime_dispatch == ResidentTcpRuntimeDispatch::Quic {
                let hysteria2_owner_registry = router.hysteria2_owner_registry();
                let tuic_owner_registry = router.tuic_owner_registry();
                let juicity_owner_registry = router.juicity_owner_registry();
                drop(router);
                Box::pin(handle_quic_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    sniff,
                    &metrics,
                    hysteria2_owner_registry.as_ref(),
                    tuic_owner_registry.as_ref(),
                    juicity_owner_registry.as_ref(),
                    None,
                ))
                .await
            } else {
                drop(router);
                Box::pin(handle_resident_proxy_tcp_connection_async(
                    inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    sniff,
                    Arc::clone(&metrics),
                ))
                .await
            };
            result.map(Some)
        }
    }
}
