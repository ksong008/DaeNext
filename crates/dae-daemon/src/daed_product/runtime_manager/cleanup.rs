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
    Some(format!(
        "runtime cleanup failed: loaded_map_cleaned={}, cleanup_command_timed_out={}, sys_fs_bpf_dae_mutated={}, leftovers_after_cleanup={}",
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
