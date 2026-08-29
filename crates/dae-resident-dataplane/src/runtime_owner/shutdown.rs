use super::*;
use dae_resident_runtime::{
    ResidentRuntimeThreadShutdown, elapsed_nanos, take_resident_async_runtime_tasks,
    wait_for_resident_runtime_tasks,
};

pub(crate) struct ResidentRuntimeWorkloadShutdown {
    started: Instant,
    grace: Duration,
    elapsed_ns: u64,
    task_count_started: usize,
    async_shutdown: ResidentAsyncRuntimeShutdown,
    thread_shutdown: ResidentRuntimeThreadShutdown,
}

pub(super) fn shutdown_resident_runtime_workloads(
    owner: &mut ResidentRuntimeOwner,
    grace: Duration,
) -> ResidentRuntimeWorkloadShutdown {
    let started = Instant::now();
    let deadline = started.checked_add(grace).unwrap_or(started);
    owner.workload_stop.store(true, Ordering::Release);
    let mut workload_tasks = take_resident_async_runtime_tasks(
        &mut owner.async_tasks,
        ResidentRuntimeTaskRole::Workload,
    );
    workload_tasks.extend(take_resident_async_runtime_tasks(
        &mut owner.async_tasks,
        ResidentRuntimeTaskRole::Generation,
    ));
    let task_count_started = owner.tasks.len().saturating_add(workload_tasks.len());
    let async_shutdown = owner
        .data_plane_executor
        .join_tasks(workload_tasks, deadline);
    let mut thread_shutdown =
        wait_for_resident_runtime_tasks(std::mem::take(&mut owner.tasks), started, deadline, grace);
    owner.tasks.append(&mut thread_shutdown.pending);
    ResidentRuntimeWorkloadShutdown {
        started,
        grace,
        elapsed_ns: elapsed_nanos(started),
        task_count_started,
        async_shutdown,
        thread_shutdown,
    }
}

pub(super) fn shutdown_resident_runtime_owner(
    owner: &mut ResidentRuntimeOwner,
    workload: ResidentRuntimeWorkloadShutdown,
    grace: Duration,
) -> Value {
    let ResidentRuntimeWorkloadShutdown {
        started,
        grace: workload_grace,
        elapsed_ns: workload_shutdown_elapsed_ns,
        task_count_started: workload_task_count_started,
        async_shutdown: workload_async_shutdown,
        thread_shutdown,
    } = workload;
    let transport_started = Instant::now();
    let transport_deadline = transport_started
        .checked_add(grace)
        .unwrap_or(transport_started);
    owner.transport_stop.store(true, Ordering::Release);
    let transport_tasks = take_resident_async_runtime_tasks(
        &mut owner.async_tasks,
        ResidentRuntimeTaskRole::Transport,
    );
    let transport_task_count_started = transport_tasks.len();
    let transport_async_shutdown = owner
        .data_plane_executor
        .join_tasks(transport_tasks, transport_deadline);
    let transport_shutdown_elapsed_ns = elapsed_nanos(transport_started);
    owner
        .data_plane_executor
        .shutdown(RESIDENT_RUNTIME_RESOURCE_DRAIN_GRACE);

    let task_count_started =
        workload_task_count_started.saturating_add(transport_task_count_started);
    let joined_worker_threads = thread_shutdown.joined;
    let panicked_worker_threads = thread_shutdown.panicked;
    let detached_worker_threads = thread_shutdown.timed_out;
    let joined_async_tasks = workload_async_shutdown
        .joined
        .saturating_add(transport_async_shutdown.joined);
    let cancelled_async_tasks = workload_async_shutdown
        .cancelled
        .saturating_add(transport_async_shutdown.cancelled);
    let panicked_async_tasks = workload_async_shutdown
        .panicked
        .saturating_add(transport_async_shutdown.panicked);
    let aborted_async_tasks = workload_async_shutdown
        .timed_out
        .saturating_add(transport_async_shutdown.timed_out);
    let pending_async_tasks = workload_async_shutdown
        .pending
        .len()
        .saturating_add(transport_async_shutdown.pending.len());
    let mut task_results = thread_shutdown.results;
    task_results.extend(workload_async_shutdown.results);
    task_results.extend(transport_async_shutdown.results);
    let task_count_joined = joined_worker_threads.saturating_add(joined_async_tasks);
    let task_count_cancelled = cancelled_async_tasks;
    let task_count_panicked = panicked_worker_threads.saturating_add(panicked_async_tasks);
    let task_count_timed_out = detached_worker_threads.saturating_add(aborted_async_tasks);

    let metrics = owner.metrics.snapshot();
    let active_tcp = metrics["activeTcpConnections"].as_u64().unwrap_or(0);
    let active_udp = metrics["activeUdpSessions"].as_u64().unwrap_or(0);
    let legacy_udp_active = owner.udp_sessions_active.load(Ordering::Relaxed);
    let event_writer_started = Instant::now();
    let event_writer_deadline = event_writer_started
        .checked_add(grace)
        .unwrap_or(event_writer_started);
    let event_writer = owner.event_writer.shutdown_until(event_writer_deadline);
    let owned_cleanup = owner.cleanup_inventory.snapshot();
    let udp_payload_admission = owner.udp_payload_admission.snapshot();
    let udp_payload_released = udp_payload_admission["currentBytes"].as_u64() == Some(0);
    let hysteria2_owners = owner
        .hysteria2_owner_registry
        .as_ref()
        .map(Hysteria2OwnerRegistryHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let hysteria2_owners_released = hysteria2_owners.is_null()
        || (hysteria2_owners["registeredKeys"].as_u64() == Some(0)
            && hysteria2_owners["activeOwners"].as_u64() == Some(0)
            && hysteria2_owners["activeLogicalLeases"].as_u64() == Some(0)
            && hysteria2_owners["activeUdpSessions"].as_u64() == Some(0)
            && hysteria2_owners["currentUdpQueuedBytes"].as_u64() == Some(0)
            && hysteria2_owners["activeUdpSessionQuarantine"].as_u64() == Some(0)
            && hysteria2_owners["registryOwnershipReleased"].as_bool() == Some(true)
            && hysteria2_owners["shutdownTimedOut"].as_bool() == Some(false));
    let tuic_owners = owner
        .tuic_owner_registry
        .as_ref()
        .map(TuicOwnerRegistryHandle::metrics_snapshot)
        .unwrap_or(Value::Null);
    let tuic_owners_released = tuic_owners.is_null()
        || (tuic_owners["registeredKeys"].as_u64() == Some(0)
            && tuic_owners["activeOwners"].as_u64() == Some(0)
            && tuic_owners["activeLogicalLeases"].as_u64() == Some(0)
            && tuic_owners["activeUdpAssociations"].as_u64() == Some(0)
            && tuic_owners["currentUdpQueuedBytes"].as_u64() == Some(0)
            && tuic_owners["activeAssociationQuarantine"].as_u64() == Some(0)
            && tuic_owners["registryOwnershipReleased"].as_bool() == Some(true)
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
            && juicity_owners["activeWaiters"].as_u64() == Some(0)
            && juicity_owners["registryOwnershipReleased"].as_bool() == Some(true)
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
    let shutdown_safe = detached_worker_threads == 0
        && pending_async_tasks == 0
        && active_tcp == 0
        && active_udp == 0
        && legacy_udp_active == 0
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
    let graceful = shutdown_safe
        && task_count_panicked == 0
        && task_count_cancelled == 0
        && task_count_timed_out == 0
        && owned_cleanup["graceful"].as_bool().unwrap_or(true);
    let completion_mode = if !shutdown_safe {
        "incomplete"
    } else if aborted_async_tasks > 0
        || owned_cleanup["completionMode"].as_str() == Some("forced-bounded")
    {
        "forced-bounded"
    } else if graceful {
        "graceful"
    } else {
        "completed-degraded"
    };

    json!({
        "name": "stop-resident-dataplane-runtime",
        "status": if shutdown_safe { "pass" } else { "fail" },
        "safetyStatus": if shutdown_safe { "pass" } else { "fail" },
        "graceful": graceful,
        "completionMode": completion_mode,
        "owner": "resident-runtime-owner",
        "reload_generation": owner.reload_generation,
        "reloadGeneration": owner.reload_generation,
        "task_count_started": task_count_started,
        "task_count_joined": task_count_joined,
        "task_count_cancelled": task_count_cancelled,
        "task_count_timed_out": task_count_timed_out,
        "task_count_aborted": aborted_async_tasks,
        "task_count_pending": detached_worker_threads.saturating_add(pending_async_tasks),
        "task_count_detached": detached_worker_threads,
        "task_count_panicked": task_count_panicked,
        "task_count_join_exceeded_grace": 0,
        "join_grace_ms": duration_millis(grace),
        "joined_worker_threads": joined_worker_threads,
        "panicked_worker_threads": panicked_worker_threads,
        "joined_async_tasks": joined_async_tasks,
        "cancelled_async_tasks": cancelled_async_tasks,
        "panicked_async_tasks": panicked_async_tasks,
        "aborted_async_tasks": aborted_async_tasks,
        "pending_async_tasks": pending_async_tasks,
        "resource_release": {
            "activeTcpConnections": active_tcp == 0,
            "activeUdpSessions": active_udp == 0 && legacy_udp_active == 0,
            "udpPayload": udp_payload_released,
            "hysteria2Owners": hysteria2_owners_released,
            "tuicOwners": tuic_owners_released,
            "juicityOwners": juicity_owners_released,
            "anytlsOwners": anytls_owners_released,
            "h2CarrierOwners": h2_carrier_owners_released,
            "meekTransportOwners": meek_transport_owners_released,
            "vlessMuxOwners": vless_mux_owners_released,
            "ownedCleanup": owned_cleanup["status"].as_str() == Some("pass"),
            "eventWriter": event_writer["status"].as_str() == Some("pass"),
        },
        "workload_shutdown": {
            "join_grace_ms": duration_millis(workload_grace),
            "elapsed_ns": workload_shutdown_elapsed_ns,
            "elapsed_ms": workload_shutdown_elapsed_ns / 1_000_000,
            "joined": workload_async_shutdown.joined,
            "cancelled": workload_async_shutdown.cancelled,
            "panicked": workload_async_shutdown.panicked,
            "forced": workload_async_shutdown.timed_out,
            "pending": workload_async_shutdown.pending.len(),
        },
        "transport_shutdown": {
            "join_grace_ms": duration_millis(grace),
            "elapsed_ns": transport_shutdown_elapsed_ns,
            "elapsed_ms": transport_shutdown_elapsed_ns / 1_000_000,
            "joined": transport_async_shutdown.joined,
            "cancelled": transport_async_shutdown.cancelled,
            "panicked": transport_async_shutdown.panicked,
            "forced": transport_async_shutdown.timed_out,
            "pending": transport_async_shutdown.pending.len(),
        },
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
        "tasks": task_results,
    })
}

#[cfg(test)]
mod tests;
