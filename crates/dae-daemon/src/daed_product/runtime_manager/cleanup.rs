use super::*;

pub(super) fn cleanup_runtime_instance(runtime: Option<ProductRuntimeInstance>) -> Option<Value> {
    match runtime? {
        ProductRuntimeInstance::Resident(mut runtime) => runtime.cleanup(),
        ProductRuntimeInstance::Fake(fake) => Some(json!({
            "status": "pass",
            "cleanupRuntime": "fake-resident-runtime-test-only",
            "fakeRuntime": true,
            "startedAt": fake.started_at,
            "tproxyPort": fake.tproxy_port,
        })),
    }
}

pub(super) fn cleanup_runtime_instance_with_reclaim(
    runtime: Option<ProductRuntimeInstance>,
    reason: AllocatorReclaimReason,
) -> Option<Value> {
    let mut cleanup_report = cleanup_runtime_instance(runtime);
    let reclaim = allocator_reclaim(reason);
    match cleanup_report.as_mut() {
        Some(Value::Object(map)) => {
            map.insert("allocatorReclaim".to_owned(), reclaim);
        }
        Some(_) | None => {
            cleanup_report = Some(json!({
                "status": "pass",
                "cleanupRuntime": "background-stop",
                "allocatorReclaim": reclaim,
            }));
        }
    }
    cleanup_report
}

pub(super) fn spawn_background_cleanup(
    inner: Arc<Mutex<ProductRuntimeState>>,
    cleanup_epoch: u64,
    runtime: Option<ProductRuntimeInstance>,
) {
    let _ = thread::spawn(move || {
        let cleanup_report =
            cleanup_runtime_instance_with_reclaim(runtime, AllocatorReclaimReason::StopRuntime);
        if let Ok(mut inner) = inner.lock()
            && inner.cleanup.epoch == cleanup_epoch
        {
            inner.cleanup.finish(cleanup_report);
        }
    });
}

pub(super) fn wait_for_cleanup_idle_for_inner(
    inner: &Arc<Mutex<ProductRuntimeState>>,
    timeout: Duration,
) -> bool {
    let started = Instant::now();
    loop {
        let cleanup_running = inner
            .lock()
            .map(|inner| inner.cleanup.running)
            .unwrap_or(false);
        if !cleanup_running {
            return true;
        }
        if started.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn ensure_cleanup_allows_start_for_inner(
    inner: &Arc<Mutex<ProductRuntimeState>>,
) -> Result<(), String> {
    if !wait_for_cleanup_idle_for_inner(inner, PRODUCT_RUNTIME_CLEANUP_INTERLOCK_WAIT) {
        return Err(cleanup_start_blocker_for_inner(inner).unwrap_or_else(|| {
            "product runtime cleanup is still running; retry after cleanup finishes".to_owned()
        }));
    }
    if let Some(blocker) = cleanup_start_blocker_for_inner(inner) {
        return Err(blocker);
    }
    Ok(())
}

fn cleanup_start_blocker_for_inner(inner: &Arc<Mutex<ProductRuntimeState>>) -> Option<String> {
    let Ok(inner) = inner.lock() else {
        return Some("product runtime manager lock poisoned while checking cleanup".to_owned());
    };
    cleanup_start_blocker(&inner.cleanup)
}

fn cleanup_start_blocker(cleanup: &RuntimeCleanupState) -> Option<String> {
    if cleanup.running {
        return Some(format!(
            "product runtime cleanup is still running: epoch={}, mode={}",
            cleanup.epoch,
            cleanup.mode.as_deref().unwrap_or("unknown")
        ));
    }
    cleanup.last_error.as_ref().map(|err| {
        format!(
            "previous product runtime cleanup failed: epoch={}, mode={}, error={err}",
            cleanup.epoch,
            cleanup.mode.as_deref().unwrap_or("unknown")
        )
    })
}

pub(super) fn cleanup_start_blocker_from_report(report: Option<&Value>) -> Option<String> {
    cleanup_report_error(report)
}

pub(super) fn cleanup_report_error(report: Option<&Value>) -> Option<String> {
    let report = report?;
    if report.get("status").and_then(Value::as_str) == Some("pass") {
        return None;
    }
    let failed_steps = report
        .get("cleanup_steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|step| {
            matches!(
                step["status"].as_str(),
                Some("fail" | "partial" | "timed_out")
            )
        })
        .filter_map(|step| step["name"].as_str())
        .take(8)
        .collect::<Vec<_>>()
        .join(",");
    let failed_step_details = report
        .get("cleanup_steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|step| {
            matches!(
                step["status"].as_str(),
                Some("fail" | "partial" | "timed_out")
            )
        })
        .take(8)
        .map(cleanup_step_failure_detail)
        .collect::<Vec<_>>();
    Some(format!(
        "runtime cleanup failed: cleanup_step_failed={}, failed_steps={}, failed_step_details={}, loaded_map_cleaned={}, cleanup_command_timed_out={}, sys_fs_bpf_dae_mutated={}, leftovers_after_cleanup={}",
        report
            .get("cleanup_step_failed")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        if failed_steps.is_empty() {
            "none"
        } else {
            &failed_steps
        },
        Value::Array(failed_step_details),
        report
            .get("loaded_map_cleaned")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        report
            .get("cleanup_command_timed_out")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        report
            .get("sys_fs_bpf_dae_mutated")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned()),
        report
            .get("leftovers_after_cleanup")
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_owned())
    ))
}

fn cleanup_step_failure_detail(step: &Value) -> Value {
    let mut detail = serde_json::Map::new();
    for key in [
        "name",
        "status",
        "safetyStatus",
        "graceful",
        "completionMode",
        "task_count_timed_out",
        "task_count_aborted",
        "task_count_pending",
        "task_count_detached",
        "task_count_panicked",
        "active_tcp_connections_at_shutdown",
        "active_udp_sessions_at_shutdown",
        "udp_sessions_active_at_shutdown",
        "resource_release",
    ] {
        if let Some(value) = step.get(key) {
            detail.insert(key.to_owned(), value.clone());
        }
    }
    let owner_release_details = compact_owner_release_failure_details(step);
    if !owner_release_details.is_empty() {
        detail.insert(
            "ownerReleaseDetails".to_owned(),
            Value::Object(owner_release_details),
        );
    }
    Value::Object(detail)
}

fn compact_owner_release_failure_details(step: &Value) -> serde_json::Map<String, Value> {
    let mut details = serde_json::Map::new();
    let specifications = [
        (
            "hysteria2Owners",
            "hysteria2",
            "hysteria2_owners",
            &[
                "registeredKeys",
                "activeOwners",
                "activeLogicalLeases",
                "activeUdpSessions",
                "currentUdpQueuedBytes",
                "activeUdpSessionQuarantine",
                "registryOwnershipReleased",
                "endpointDrain",
                "shutdownTimedOut",
            ][..],
        ),
        (
            "tuicOwners",
            "tuic",
            "tuic_owners",
            &[
                "registeredKeys",
                "activeOwners",
                "activeLogicalLeases",
                "activeUdpAssociations",
                "currentUdpQueuedBytes",
                "activeAssociationQuarantine",
                "registryOwnershipReleased",
                "endpointDrain",
                "shutdownTimedOut",
            ][..],
        ),
        (
            "juicityOwners",
            "juicity",
            "juicity_owners",
            &[
                "activePools",
                "activePhysicalOwners",
                "activeBuilds",
                "activeLogicalLeases",
                "activeWaiters",
                "registryOwnershipReleased",
                "endpointDrain",
                "shutdownTimedOut",
            ][..],
        ),
    ];
    for (release_key, detail_key, snapshot_key, fields) in specifications {
        if step
            .pointer(&format!("/resource_release/{release_key}"))
            .and_then(Value::as_bool)
            != Some(false)
        {
            continue;
        }
        let mut selected = serde_json::Map::new();
        if let Some(snapshot) = step.get(snapshot_key) {
            for field in fields {
                if let Some(value) = snapshot.get(*field) {
                    selected.insert((*field).to_owned(), value.clone());
                }
            }
        }
        if selected.is_empty() {
            selected.insert("snapshotMissing".to_owned(), json!(true));
        }
        details.insert(detail_key.to_owned(), Value::Object(selected));
    }
    details
}
