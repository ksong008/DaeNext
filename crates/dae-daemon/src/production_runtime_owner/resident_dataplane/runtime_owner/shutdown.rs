use super::*;
const RESIDENT_RUNTIME_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Debug, Default)]
struct ResidentRuntimeShutdownTasks {
    joined: usize,
    panicked: usize,
    timed_out: usize,
    results: Vec<Value>,
    pending: Vec<ResidentRuntimeTask>,
}

pub(super) fn shutdown_resident_runtime_owner(
    owner: &mut ResidentRuntimeOwner,
    grace: Duration,
) -> Value {
    let started = Instant::now();
    let deadline = started.checked_add(grace).unwrap_or(started);
    owner.stop.store(true, Ordering::Relaxed);
    let task_count_started = owner.tasks.len().saturating_add(owner.async_tasks.len());
    let async_shutdown = owner
        .data_plane_executor
        .join_tasks(std::mem::take(&mut owner.async_tasks), deadline);
    owner.data_plane_executor.shutdown(
        deadline
            .saturating_duration_since(Instant::now())
            .min(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE),
    );
    let mut task_shutdown =
        wait_for_runtime_tasks(std::mem::take(&mut owner.tasks), started, deadline, grace);
    owner.tasks.append(&mut task_shutdown.pending);
    let joined_worker_threads = task_shutdown.joined;
    let panicked_worker_threads = task_shutdown.panicked;
    let detached_worker_threads = task_shutdown.timed_out;
    task_shutdown.joined = task_shutdown.joined.saturating_add(async_shutdown.joined);
    task_shutdown.panicked = task_shutdown
        .panicked
        .saturating_add(async_shutdown.panicked);
    task_shutdown.timed_out = task_shutdown
        .timed_out
        .saturating_add(async_shutdown.timed_out);
    task_shutdown.results.extend(async_shutdown.results);

    let metrics = owner.metrics.snapshot();
    let active_tcp = metrics["activeTcpConnections"].as_u64().unwrap_or(0);
    let active_udp = metrics["activeUdpSessions"].as_u64().unwrap_or(0);
    let legacy_udp_active = owner.udp_sessions_active.load(Ordering::Relaxed);
    let event_writer = owner.event_writer.shutdown_until(deadline);
    let owned_cleanup = owner.cleanup_inventory.snapshot();
    let udp_payload_admission = owner.udp_payload_admission.snapshot();
    let udp_payload_released = udp_payload_admission["currentBytes"].as_u64() == Some(0);
    let hysteria2_owners = owner
        .hysteria2_owner_registry
        .as_ref()
        .map(Hysteria2OwnerRegistryHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let hysteria2_owners_released = hysteria2_owners.is_null()
        || (hysteria2_owners["activeOwners"].as_u64() == Some(0)
            && hysteria2_owners["activeLogicalLeases"].as_u64() == Some(0)
            && hysteria2_owners["activeUdpSessions"].as_u64() == Some(0)
            && hysteria2_owners["currentUdpQueuedBytes"].as_u64() == Some(0)
            && hysteria2_owners["activeUdpSessionQuarantine"].as_u64() == Some(0)
            && hysteria2_owners["shutdownTimedOut"].as_bool() == Some(false));
    let tuic_owners = owner
        .tuic_owner_registry
        .as_ref()
        .map(TuicOwnerRegistryHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let tuic_owners_released = tuic_owners.is_null()
        || (tuic_owners["activeOwners"].as_u64() == Some(0)
            && tuic_owners["activeLogicalLeases"].as_u64() == Some(0)
            && tuic_owners["activeUdpAssociations"].as_u64() == Some(0)
            && tuic_owners["currentUdpQueuedBytes"].as_u64() == Some(0)
            && tuic_owners["activeAssociationQuarantine"].as_u64() == Some(0)
            && tuic_owners["shutdownTimedOut"].as_bool() == Some(false));
    let juicity_owners = owner
        .juicity_owner_registry
        .as_ref()
        .map(JuicityOwnerRegistryHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let juicity_owners_released = juicity_owners.is_null()
        || (juicity_owners["activePools"].as_u64() == Some(0)
            && juicity_owners["activePhysicalOwners"].as_u64() == Some(0)
            && juicity_owners["activeBuilds"].as_u64() == Some(0)
            && juicity_owners["activeLogicalLeases"].as_u64() == Some(0)
            && juicity_owners["shutdownTimedOut"].as_bool() == Some(false));
    let anytls_owners = owner
        .anytls_owner_registry
        .as_ref()
        .map(AnyTlsOwnerRegistryHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let anytls_owners_released = anytls_owners.is_null()
        || (anytls_owners["registeredKeys"].as_u64() == Some(0)
            && anytls_owners["registeredPhysicalSessions"].as_u64() == Some(0)
            && anytls_owners["activePhysicalSessions"].as_u64() == Some(0)
            && anytls_owners["idlePhysicalSessions"].as_u64() == Some(0)
            && anytls_owners["activeLogicalStreams"].as_u64() == Some(0)
            && anytls_owners["currentLogicalBufferBytes"].as_u64() == Some(0)
            && anytls_owners["ownerStateBytesLowerBound"].as_u64() == Some(0)
            && anytls_owners["ownerPaddingSchemeBytes"].as_u64() == Some(0)
            && anytls_owners["activeBuilds"].as_u64() == Some(0)
            && anytls_owners["shutdownTimedOut"].as_bool() == Some(false));
    let h2_carrier_owners = owner
        .h2_carrier_generation_owner
        .as_ref()
        .map(H2CarrierGenerationOwnerHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let h2_carrier_owners_released = h2_carrier_owners.is_null()
        || (h2_carrier_owners["registeredKeys"].as_u64() == Some(0)
            && h2_carrier_owners["registeredBuildTasks"].as_u64() == Some(0)
            && h2_carrier_owners["registeredDriverTasks"].as_u64() == Some(0)
            && h2_carrier_owners["reservedPhysicalConnections"].as_u64() == Some(0)
            && h2_carrier_owners["activePhysicalConnections"].as_u64() == Some(0)
            && h2_carrier_owners["activeLogicalStreams"].as_u64() == Some(0)
            && h2_carrier_owners["activeBuilds"].as_u64() == Some(0)
            && h2_carrier_owners["ownerStateBytesLowerBound"].as_u64() == Some(0)
            && h2_carrier_owners["shutdownTimedOut"].as_bool() == Some(false));
    let meek_transport_owners = owner
        .meek_transport_generation_owner
        .as_ref()
        .map(MeekTransportGenerationOwnerHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let meek_transport_owners_released = meek_transport_owners.is_null()
        || (meek_transport_owners["registeredKeys"].as_u64() == Some(0)
            && meek_transport_owners["registeredBuildTasks"].as_u64() == Some(0)
            && meek_transport_owners["reservedPhysicalConnections"].as_u64() == Some(0)
            && meek_transport_owners["activePhysicalConnections"].as_u64() == Some(0)
            && meek_transport_owners["activeLeases"].as_u64() == Some(0)
            && meek_transport_owners["idlePhysicalConnections"].as_u64() == Some(0)
            && meek_transport_owners["activeBuilds"].as_u64() == Some(0)
            && meek_transport_owners["ownerStateBytesLowerBound"].as_u64() == Some(0)
            && meek_transport_owners["shutdownTimedOut"].as_bool() == Some(false));
    let vless_mux_owners = owner
        .vless_mux_generation_owner
        .as_ref()
        .map(VlessMuxGenerationOwnerHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let vless_mux_owners_released = vless_mux_owners.is_null()
        || (vless_mux_owners["registeredKeys"].as_u64() == Some(0)
            && vless_mux_owners["registeredPhysicalConnections"].as_u64() == Some(0)
            && vless_mux_owners["registeredBuildTasks"].as_u64() == Some(0)
            && vless_mux_owners["reservedPhysicalConnections"].as_u64() == Some(0)
            && vless_mux_owners["activePhysicalConnections"].as_u64() == Some(0)
            && vless_mux_owners["activeLogicalStreams"].as_u64() == Some(0)
            && vless_mux_owners["currentLogicalBufferBytes"].as_u64() == Some(0)
            && vless_mux_owners["activeBuilds"].as_u64() == Some(0)
            && vless_mux_owners["idlePhysicalConnections"].as_u64() == Some(0)
            && vless_mux_owners["ownerStateBytesLowerBound"].as_u64() == Some(0)
            && vless_mux_owners["shutdownTimedOut"].as_bool() == Some(false));
    let shutdown_elapsed_ns = elapsed_nanos(started);
    let shutdown_passed = task_shutdown.panicked == 0
        && task_shutdown.timed_out == 0
        && udp_payload_released
        && hysteria2_owners_released
        && tuic_owners_released
        && juicity_owners_released
        && anytls_owners_released
        && h2_carrier_owners_released
        && meek_transport_owners_released
        && vless_mux_owners_released
        && owned_cleanup["status"].as_str() == Some("pass")
        && event_writer["status"].as_str() == Some("pass");

    json!({
        "name": "stop-resident-dataplane-runtime",
        "status": if shutdown_passed { "pass" } else { "fail" },
        "owner": "resident-runtime-owner",
        "reload_generation": owner.reload_generation,
        "reloadGeneration": owner.reload_generation,
        "task_count_started": task_count_started,
        "task_count_joined": task_shutdown.joined,
        "task_count_timed_out": task_shutdown.timed_out,
        "task_count_aborted": async_shutdown.timed_out,
        "task_count_detached": detached_worker_threads,
        "task_count_panicked": task_shutdown.panicked,
        "task_count_join_exceeded_grace": 0,
        "join_grace_ms": duration_millis(grace),
        "joined_worker_threads": joined_worker_threads,
        "panicked_worker_threads": panicked_worker_threads,
        "joined_async_tasks": async_shutdown.joined,
        "panicked_async_tasks": async_shutdown.panicked,
        "aborted_async_tasks": async_shutdown.timed_out,
        "active_tcp_connections_at_shutdown": active_tcp,
        "active_udp_sessions_at_shutdown": active_udp,
        "udp_sessions_active_at_shutdown": legacy_udp_active,
        "udp_payload_admission": udp_payload_admission,
        "hysteria2_owners": hysteria2_owners,
        "tuic_owners": tuic_owners,
        "juicity_owners": juicity_owners,
        "anytls_owners": anytls_owners,
        "h2_carrier_owners": h2_carrier_owners,
        "meek_transport_owners": meek_transport_owners,
        "vless_mux_owners": vless_mux_owners,
        "owned_cleanup": owned_cleanup,
        "runtime_handle_owner": "resident-runtime-owner",
        "manual_probe_runtime_available": true,
        "manual_probe_runtime_persistent": false,
        "manual_probe_runtime_stopped": true,
        "event_writer": event_writer,
        "shutdown_elapsed_ns": shutdown_elapsed_ns,
        "shutdown_elapsed_ms": shutdown_elapsed_ns / 1_000_000,
        "shutdown_deadline_ms": duration_millis(grace),
        "event_file": Value::Null,
        "event_file_status": "disabled",
        "event_log": "product-log-sink",
        "tasks": task_shutdown.results,
    })
}

fn wait_for_runtime_tasks(
    mut pending: Vec<ResidentRuntimeTask>,
    started: Instant,
    deadline: Instant,
    grace: Duration,
) -> ResidentRuntimeShutdownTasks {
    let mut shutdown = ResidentRuntimeShutdownTasks {
        results: Vec::with_capacity(pending.len()),
        ..ResidentRuntimeShutdownTasks::default()
    };

    loop {
        let mut index = 0;
        while index < pending.len() {
            let finished = pending[index]
                .handle
                .as_ref()
                .is_none_or(JoinHandle::is_finished);
            if !finished {
                index += 1;
                continue;
            }

            let mut task = pending.swap_remove(index);
            let completion = task
                .completion
                .as_ref()
                .and_then(|receiver| receiver.try_recv().ok());
            let join_started = Instant::now();
            let join_result = task.handle.take().map(JoinHandle::join).unwrap_or(Ok(()));
            let join_elapsed_ns = elapsed_nanos(join_started);
            let panicked =
                completion == Some(ResidentRuntimeTaskExit::Panicked) || join_result.is_err();
            if panicked {
                shutdown.panicked += 1;
            } else {
                shutdown.joined += 1;
            }
            let completion_wait_elapsed_ns = elapsed_nanos(started);
            shutdown.results.push(json!({
                "name": task.name,
                "kind": task.kind,
                "status": if panicked { "panicked" } else { "joined" },
                "join_elapsed_ns": join_elapsed_ns,
                "join_elapsed_ms": join_elapsed_ns / 1_000_000,
                "completion_wait_elapsed_ns": completion_wait_elapsed_ns,
                "completion_wait_elapsed_ms": completion_wait_elapsed_ns / 1_000_000,
                "join_grace_ms": duration_millis(grace),
                "join_exceeded_grace": false,
            }));
        }

        if pending.is_empty() || Instant::now() >= deadline {
            break;
        }
        thread::park_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(RESIDENT_RUNTIME_COMPLETION_POLL_INTERVAL),
        );
    }

    for task in pending.drain(..) {
        shutdown.timed_out += 1;
        let completion_wait_elapsed_ns = elapsed_nanos(started);
        shutdown.results.push(json!({
            "name": task.name,
            "kind": task.kind,
            "status": "timed_out",
            "join_elapsed_ns": Value::Null,
            "join_elapsed_ms": Value::Null,
            "completion_wait_elapsed_ns": completion_wait_elapsed_ns,
            "completion_wait_elapsed_ms": completion_wait_elapsed_ns / 1_000_000,
            "join_grace_ms": duration_millis(grace),
            "join_exceeded_grace": false,
            "aborted": false,
            "detached": true,
        }));
        shutdown.pending.push(task);
    }
    shutdown
}

fn elapsed_nanos(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests;
