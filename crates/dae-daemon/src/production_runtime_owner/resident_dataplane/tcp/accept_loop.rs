use super::*;
use std::path::Path;
pub(crate) fn resident_tcp_accept_loop(
    listener: TcpListener,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    runtime_config: ResidentTcpRuntimeConfig,
) {
    if let Err(err) = listener.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "tcp_listener_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
    let runtime = match build_resident_tcp_runtime(runtime_config) {
        Ok(runtime) => runtime,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "tcp_async_runtime_build_failed", "error": err.to_string()}),
            );
            return;
        }
    };
    runtime.block_on(resident_tcp_accept_loop_async(
        listener,
        router,
        stop,
        event_file,
        event_lock,
        metrics,
        runtime_config,
    ));
}

pub(crate) async fn resident_tcp_accept_loop_async(
    listener: TcpListener,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    runtime_config: ResidentTcpRuntimeConfig,
) {
    let listener = match TokioTcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(err) => {
            append_event(
                &event_file,
                &event_lock,
                json!({"event": "tcp_async_listener_adopt_failed", "error": err.to_string()}),
            );
            return;
        }
    };
    let admission =
        ResidentTcpAdmission::new(runtime_config.connection_limit, Arc::clone(&metrics));
    let mut event = json!({
            "event": "tcp_worker_started",
            "proxy_count": router.proxy_count(),
            "dial_mode": router.dial_mode_name(),
            "flowStackBytes": runtime_config.worker_stack_bytes,
            "flowStackScope": "resident TCP runtime OS threads; not Tokio task stacks",
            "runtime": runtime_config.json(),
    });
    append_tcp_execution_fields(&mut event, "async-accept-direct");
    event["proxyExecutionDescriptor"] = tcp_execution_descriptor("async-proxy-tls").to_value();
    append_event(&event_file, &event_lock, event);
    while !stop.load(Ordering::Relaxed) {
        let permit = match time::timeout(RESIDENT_TCP_ACCEPT_SLEEP, admission.acquire()).await {
            Err(_) => {
                admission.record_capacity_wait();
                continue;
            }
            Ok(Ok(permit)) => permit,
            Ok(Err(err)) => {
                append_event(
                    &event_file,
                    &event_lock,
                    json!({"event": "tcp_admission_failed", "error": err}),
                );
                break;
            }
        };
        if stop.load(Ordering::Relaxed) {
            drop(permit);
            break;
        }
        match time::timeout(RESIDENT_TCP_ACCEPT_SLEEP, listener.accept()).await {
            Err(_) => drop(permit),
            Ok(Ok((stream, peer))) => {
                spawn_async_tcp_flow(
                    stream,
                    peer,
                    Arc::clone(&router),
                    Arc::clone(&stop),
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    Arc::clone(&metrics),
                    admission.admitted(permit),
                );
            }
            Ok(Err(err)) => {
                drop(permit);
                append_event(
                    &event_file,
                    &event_lock,
                    json!({"event": "tcp_accept_failed", "error": err.to_string()}),
                );
                time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    append_event(
        &event_file,
        &event_lock,
        json!({"event": "tcp_worker_stopped"}),
    );
}

#[allow(clippy::too_many_arguments)]
fn spawn_async_tcp_flow(
    stream: TokioTcpStream,
    peer: SocketAddr,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    metrics: Arc<ResidentDataplaneMetrics>,
    admission: ResidentTcpAdmissionGuard,
) {
    tokio::spawn(async move {
        let _admission = admission;
        match handle_tcp_connection_async_or_handoff(
            stream,
            peer,
            router,
            stop,
            Arc::clone(&metrics),
            &event_file,
            &event_lock,
        )
        .await
        {
            Ok(Some(event)) => append_event(&event_file, &event_lock, event),
            Ok(None) => {}
            Err(err) => append_event(
                &event_file,
                &event_lock,
                json!({"event": "tcp_connection_failed", "peer": resident_socket_addr_display(peer), "error": err}),
            ),
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tcp_connection_async_or_handoff(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    router: Arc<ResidentTcpRouter>,
    stop: Arc<AtomicBool>,
    metrics: Arc<ResidentDataplaneMetrics>,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
) -> Result<Option<Value>, String> {
    let original_dst = match inbound
        .local_addr()
        .map_err(|err| format!("read original TCP destination: {err}"))?
    {
        addr @ (SocketAddr::V4(_) | SocketAddr::V6(_)) => addr,
    };
    inbound
        .set_nodelay(true)
        .map_err(|err| format!("set inbound TCP_NODELAY: {err}"))?;
    if transparent_tcp_dns_fast_path_applies(original_dst) {
        handle_transparent_tcp_dns_fast_path_async(
            &mut inbound,
            original_dst,
            Arc::clone(&router.dns),
            Arc::clone(&stop),
            Arc::clone(&metrics),
        )
        .await?;
        return Ok(None);
    }
    let sniff = sniff_initial_tcp_payload_async(&mut inbound, router.sniffing_timeout).await?;
    let selection = router.select(peer, original_dst, &sniff.domain).await?;
    append_event(
        event_file,
        event_lock,
        tcp_route_chosen_event(
            peer,
            original_dst,
            &selection,
            &sniff,
            router.dial_mode_name(),
        ),
    );
    match selection {
        TcpSelection::Direct(selection) => {
            let _tcp_guard = ResidentTcpConnectionGuard::new(Arc::clone(&metrics));
            let result = handle_direct_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                Arc::clone(&stop),
                &sniff,
                &metrics,
            )
            .await;
            result.map(Some)
        }
        TcpSelection::Block(selection) => {
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
            let result = if matches!(
                &selection.proxy.handler,
                ResidentProxyProtocolPlan::VlessVisionTcpTls { .. }
                    | ResidentProxyProtocolPlan::VlessMuxTcpTls { .. }
            ) {
                handle_proxy_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    &sniff,
                    &metrics,
                )
                .await
            } else if matches!(
                &selection.proxy.handler,
                ResidentProxyProtocolPlan::TrojanTcpTls { .. }
                    | ResidentProxyProtocolPlan::TrojanInnerShadowsocksTcpTls { .. }
                    | ResidentProxyProtocolPlan::AnyTlsTcpTls { .. }
            ) {
                handle_frame_tls_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    &sniff,
                    &metrics,
                )
                .await
            } else if matches!(
                &selection.proxy.handler,
                ResidentProxyProtocolPlan::Hysteria2QuicTcp { .. }
                    | ResidentProxyProtocolPlan::TuicQuicTcp { .. }
                    | ResidentProxyProtocolPlan::JuicityQuicTcp { .. }
            ) {
                handle_quic_tcp_connection_async(
                    &mut inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    &sniff,
                    &metrics,
                )
                .await
            } else {
                handle_resident_proxy_tcp_connection_async(
                    inbound,
                    peer,
                    original_dst,
                    selection,
                    Arc::clone(&stop),
                    sniff,
                    Arc::clone(&metrics),
                )
                .await
            };
            result.map(Some)
        }
    }
}
