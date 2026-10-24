use super::super::RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE;
use super::super::{PublicationEpoch, ResidentDataplaneGeneration, ResidentRuntimeCoordinator};
use super::*;

pub(crate) async fn resident_tcp_accept_loop_async(
    listener: TcpListener,
    coordinator: ResidentRuntimeCoordinator<ResidentDataplaneGeneration>,
    stop: SharedResidentStopSignal,
    event_file: PathBuf,
    event_lock: Arc<Mutex<()>>,
) {
    let active_generation = coordinator.active_generation_slot();
    let generation_gate = coordinator.generation_gate();
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
            "generationAdmission": "active-generation-at-admission-commit",
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
        if !generation_gate.is_active(reserved_generation.token()) {
            continue;
        }
        if !reserved_generation.admission_is_open()
            || !generation_gate.is_active(reserved_generation.token())
        {
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
        if !reserved_generation.admission_is_open()
            || !generation_gate.is_active(reserved_generation.token())
        {
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
                let mut permit = Some(permit);
                let mut committed = None;
                for _ in 0..2 {
                    let (publication, generation) = coordinator.load_versioned();
                    if let Some(result) = try_commit_tcp_flow(
                        &coordinator,
                        publication,
                        &generation,
                        "tcp",
                        &mut permit,
                    ) {
                        committed = result.ok().map(|lease| (generation, lease));
                        break;
                    }
                }
                let Some((generation, lease)) = committed else {
                    // No flow was committed. Dropping this accepted socket and
                    // reservation cannot affect any previously admitted flow.
                    continue;
                };
                spawn_async_tcp_flow(
                    &mut flows,
                    stream,
                    peer,
                    generation,
                    event_file.clone(),
                    Arc::clone(&event_lock),
                    lease,
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
    publication_listener: &mut tokio::sync::watch::Receiver<PublicationEpoch>,
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
    lease: super::flow_registry::ResidentTcpFlowLease,
) {
    let peer = resident_tcp_accepted_endpoint(peer);
    let router = Arc::clone(&generation.tcp_router);
    let metrics = Arc::clone(&generation.metrics);
    let flow_stop = lease.stop_handle();
    drop(generation);
    flows.spawn(async move {
        let _lease = lease;
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

pub(crate) fn try_commit_tcp_flow(
    coordinator: &ResidentRuntimeCoordinator<ResidentDataplaneGeneration>,
    publication: PublicationEpoch,
    generation: &Arc<ResidentDataplaneGeneration>,
    kind: &'static str,
    permit: &mut Option<super::admission::ResidentTcpPermit>,
) -> Option<Result<super::flow_registry::ResidentTcpFlowLease, String>> {
    coordinator
        .with_current(publication, generation.token(), generation, |current| {
            current.drain_control.with_admission(|| {
                let admission = permit
                    .take()
                    .map(|permit| current.tcp_admission.admitted(permit));
                current
                    .tcp_flows
                    .register(current.id.get(), kind, admission)
            })
        })
        .flatten()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod accept_loop_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn closed_tcp_admission_waits_for_a_real_state_change() {
        let stop = ResidentStopSignal::shared();
        let mut stop_listener = stop.listener();
        let (publication, mut publication_listener) =
            tokio::sync::watch::channel(PublicationEpoch::INITIAL);
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

        publication.send_replace(PublicationEpoch::new(2));
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

pub(super) fn resident_tcp_accepted_endpoint(addr: SocketAddr) -> SocketAddr {
    resident_normalized_socket_addr(addr)
}
