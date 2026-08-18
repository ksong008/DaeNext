use super::super::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use super::super::{ActiveGenerationSlot, ResidentDataplaneGeneration};
use super::*;
use std::path::Path;

pub(crate) async fn resident_tcp_accept_loop_async(
    listener: TcpListener,
    active_generation: ActiveGenerationSlot<ResidentDataplaneGeneration>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
) {
    if let Err(err) = listener.set_nonblocking(true) {
        append_event(
            &event_file,
            &event_lock,
            json!({"event": "tcp_listener_nonblocking_failed", "error": err.to_string()}),
        );
        return;
    }
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
    let initial_generation = active_generation.load();
    let mut event = json!({
            "event": "tcp_worker_started",
            "proxy_count": initial_generation.tcp_router.proxy_count(),
            "dial_mode": initial_generation.tcp_router.dial_mode_name(),
            "flowStackBytes": initial_generation.tcp_runtime_config.worker_stack_bytes,
            "flowStackScope": "resident shared data-plane runtime OS threads; not Tokio task stacks",
            "runtime": initial_generation.tcp_runtime_config.json(),
            "generationAdmission": "active-generation-read-once-at-accept",
    });
    append_tcp_execution_fields(&mut event, "async-accept-direct");
    event["proxyExecutionDescriptor"] = tcp_execution_descriptor("async-proxy-tls").to_value();
    drop(initial_generation);
    append_event(&event_file, &event_lock, event);
    let mut stop_listener = stop.listener();
    let mut publication_listener = active_generation.subscribe_publication();
    let mut flows = tokio::task::JoinSet::new();
    let mut flow_shutdown = ResidentTaskSetShutdown::default();
    'accept: while !stop.load(Ordering::Relaxed) {
        let (reserved_publication, reserved_generation) = active_generation.load_versioned();
        if *publication_listener.borrow_and_update() != reserved_publication {
            continue;
        }
        if !reserved_generation.admission_is_open() {
            if wait_while_tcp_admission_is_closed(
                &mut stop_listener,
                &mut publication_listener,
                &mut flows,
                &mut flow_shutdown,
            )
            .await
            {
                break;
            }
            continue;
        }
        let permit = loop {
            tokio::select! {
                _ = stop_listener.cancelled() => break 'accept,
                _ = publication_listener.changed() => continue 'accept,
                completed = flows.join_next(), if !flows.is_empty() => {
                    if let Some(completed) = completed {
                        record_resident_task_completion(&mut flow_shutdown, completed);
                    }
                }
                permit = reserved_generation.tcp_admission.acquire() => match permit {
                    Ok(permit) => break permit,
                    Err(err) => {
                        append_event(
                            &event_file,
                            &event_lock,
                            json!({
                                "event": "tcp_admission_failed",
                                "generation": reserved_generation.reload_generation,
                                "error": err,
                            }),
                        );
                        break 'accept;
                    }
                }
            }
        };
        if stop.load(Ordering::Relaxed) {
            drop(permit);
            break;
        }
        if !reserved_generation.admission_is_open() {
            drop(permit);
            continue;
        }
        let accepted = loop {
            tokio::select! {
                _ = stop_listener.cancelled() => {
                    drop(permit);
                    break 'accept;
                }
                _ = publication_listener.changed() => {
                    drop(permit);
                    continue 'accept;
                }
                completed = flows.join_next(), if !flows.is_empty() => {
                    if let Some(completed) = completed {
                        record_resident_task_completion(&mut flow_shutdown, completed);
                    }
                }
                accepted = listener.accept() => break accepted,
            }
        };
        match accepted {
            Ok((stream, peer)) => {
                let (accepted_publication, accepted_generation) =
                    active_generation.load_versioned();
                let (generation, permit) = if accepted_publication == reserved_publication {
                    (reserved_generation, permit)
                } else {
                    drop(permit);
                    let mut accepted_publication = accepted_publication;
                    let mut accepted_generation = accepted_generation;
                    let (generation, permit) = loop {
                        if !accepted_generation.admission_is_open() {
                            tokio::select! {
                                _ = stop_listener.cancelled() => break 'accept,
                                _ = publication_listener.changed() => {
                                    let (latest_publication, latest_generation) =
                                        active_generation.load_versioned();
                                    accepted_publication = latest_publication;
                                    accepted_generation = latest_generation;
                                    continue;
                                }
                                completed = flows.join_next(), if !flows.is_empty() => {
                                    if let Some(completed) = completed {
                                        record_resident_task_completion(&mut flow_shutdown, completed);
                                    }
                                    continue;
                                }
                            }
                        }
                        tokio::select! {
                            _ = stop_listener.cancelled() => break 'accept,
                            _ = publication_listener.changed() => {
                                let (latest_publication, latest_generation) =
                                    active_generation.load_versioned();
                                if latest_publication != accepted_publication {
                                    accepted_publication = latest_publication;
                                    accepted_generation = latest_generation;
                                }
                            }
                            completed = flows.join_next(), if !flows.is_empty() => {
                                if let Some(completed) = completed {
                                    record_resident_task_completion(&mut flow_shutdown, completed);
                                }
                            }
                            permit = accepted_generation.tcp_admission.acquire() => match permit {
                                Ok(permit) => {
                                    let (latest_publication, latest_generation) =
                                        active_generation.load_versioned();
                                    if latest_publication != accepted_publication
                                        || !accepted_generation.admission_is_open()
                                    {
                                        drop(permit);
                                        accepted_publication = latest_publication;
                                        accepted_generation = latest_generation;
                                        continue;
                                    }
                                    break (accepted_generation, permit);
                                }
                                Err(err) => {
                                    let (latest_publication, latest_generation) =
                                        active_generation.load_versioned();
                                    if latest_publication != accepted_publication {
                                        accepted_publication = latest_publication;
                                        accepted_generation = latest_generation;
                                        continue;
                                    }
                                    append_event(
                                        &event_file,
                                        &event_lock,
                                        json!({
                                            "event": "tcp_admission_failed",
                                            "generation": accepted_generation.reload_generation,
                                            "error": err,
                                        }),
                                    );
                                    break 'accept;
                                }
                            }
                        }
                    };
                    (generation, permit)
                };
                spawn_async_tcp_flow(
                    &mut flows,
                    stream,
                    peer,
                    generation,
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    permit,
                );
            }
            Err(err) => {
                drop(permit);
                append_event(
                    &event_file,
                    &event_lock,
                    json!({"event": "tcp_accept_failed", "error": err.to_string()}),
                );
                tokio::select! {
                    _ = stop_listener.cancelled() => break,
                    _ = time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
    let drained =
        shutdown_resident_task_set(&mut flows, RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE).await;
    flow_shutdown.joined = flow_shutdown.joined.saturating_add(drained.joined);
    flow_shutdown.cancelled = flow_shutdown.cancelled.saturating_add(drained.cancelled);
    flow_shutdown.panicked = flow_shutdown.panicked.saturating_add(drained.panicked);
    flow_shutdown.forced = flow_shutdown.forced.saturating_add(drained.forced);
    append_event(
        &event_file,
        &event_lock,
        json!({
            "event": "tcp_worker_stopped",
            "flowTasksJoined": flow_shutdown.joined,
            "flowTasksCancelled": flow_shutdown.cancelled,
            "flowTasksPanicked": flow_shutdown.panicked,
            "flowTasksForced": flow_shutdown.forced,
            "flowTasksPending": flows.len(),
        }),
    );
}

async fn wait_while_tcp_admission_is_closed(
    stop_listener: &mut crate::ResidentStopListener,
    publication_listener: &mut tokio::sync::watch::Receiver<u64>,
    flows: &mut tokio::task::JoinSet<()>,
    flow_shutdown: &mut ResidentTaskSetShutdown,
) -> bool {
    tokio::select! {
        _ = stop_listener.cancelled() => true,
        _ = publication_listener.changed() => false,
        completed = flows.join_next(), if !flows.is_empty() => {
            if let Some(completed) = completed {
                record_resident_task_completion(flow_shutdown, completed);
            }
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_async_tcp_flow(
    flows: &mut tokio::task::JoinSet<()>,
    stream: TokioTcpStream,
    peer: SocketAddr,
    generation: Arc<ResidentDataplaneGeneration>,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let peer = resident_tcp_accepted_endpoint(peer);
    let admission = generation.tcp_admission.clone();
    let router = Arc::clone(&generation.tcp_router);
    let metrics = Arc::clone(&generation.metrics);
    let flow_stop = generation.drain_control.flow_stop_handle();
    drop(generation);
    flows.spawn(async move {
        let _admission = admission.admitted(permit);
        let Some(outcome) = run_until_resident_stop(
            &flow_stop,
            handle_tcp_connection_async_or_handoff(
                stream,
                peer,
                router,
                Arc::clone(&flow_stop),
                metrics,
                &event_file,
                &event_lock,
            ),
        )
        .await
        else {
            return;
        };
        match outcome {
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod accept_loop_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn closed_tcp_admission_waits_for_a_real_state_change() {
        let stop = ResidentStopSignal::shared();
        let mut stop_listener = stop.listener();
        let (publication, mut publication_listener) = tokio::sync::watch::channel(1_u64);
        let mut flows = tokio::task::JoinSet::new();
        let mut shutdown = ResidentTaskSetShutdown::default();

        assert!(
            time::timeout(
                Duration::from_millis(25),
                wait_while_tcp_admission_is_closed(
                    &mut stop_listener,
                    &mut publication_listener,
                    &mut flows,
                    &mut shutdown,
                ),
            )
            .await
            .is_err()
        );

        publication.send_replace(2);
        assert!(
            !wait_while_tcp_admission_is_closed(
                &mut stop_listener,
                &mut publication_listener,
                &mut flows,
                &mut shutdown,
            )
            .await
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tcp_connection_async_or_handoff(
    mut inbound: TokioTcpStream,
    peer: SocketAddr,
    router: Arc<ResidentTcpRouter>,
    stop: SharedResidentStopSignal,
    metrics: Arc<ResidentDataplaneMetrics>,
    event_file: &Path,
    event_lock: &Arc<Mutex<()>>,
) -> Result<Option<Value>, String> {
    let original_dst = resident_tcp_accepted_endpoint(
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
        let dns = Arc::clone(&router.dns);
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
    let sniffing_timeout = router.sniffing_timeout;
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
            let result = Box::pin(handle_direct_tcp_connection_async(
                &mut inbound,
                peer,
                original_dst,
                selection,
                Arc::clone(&stop),
                sniff,
                &metrics,
            ))
            .await;
            result.map(Some)
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
                let anytls_owner_registry = router.anytls_owner_registry.clone();
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
                let hysteria2_owner_registry = router.hysteria2_owner_registry.clone();
                let tuic_owner_registry = router.tuic_owner_registry.clone();
                let juicity_owner_registry = router.juicity_owner_registry.clone();
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

pub(super) fn resident_tcp_accepted_endpoint(addr: SocketAddr) -> SocketAddr {
    resident_normalized_socket_addr(addr)
}
