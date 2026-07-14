use super::*;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

#[derive(Debug)]
pub(super) struct ProductRuntimeInterfaceRecoverySupervisor {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterfaceRecoveryIdentity {
    lifecycle_epoch: u64,
    active_generation: Option<String>,
    host_observation_revision: u64,
}

#[derive(Clone, Debug)]
struct FailedInterfaceRecoveryAttempt {
    identity: InterfaceRecoveryIdentity,
    failed_at: Instant,
}

impl ProductRuntimeInterfaceRecoverySupervisor {
    pub(super) fn start(
        coordinator: RuntimeApplyCoordinator,
        lifecycle: Arc<Mutex<()>>,
        inner: Arc<Mutex<ProductRuntimeState>>,
        state: Option<PathBuf>,
    ) -> ProductRuntimeInterfaceRecoverySupervisor {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("product-runtime-interface-recovery".to_owned())
            .spawn(move || {
                let mut last_failure = None::<FailedInterfaceRecoveryAttempt>;
                while !thread_stop.load(AtomicOrdering::Relaxed) {
                    if let Some(request) = resident_interface_recovery_request(&inner)
                        && interface_recovery_retry_ready(
                            last_failure.as_ref(),
                            &request,
                            Instant::now(),
                        )
                        && let Ok(permit) =
                            coordinator.begin_apply(RuntimeApplyIntent::InterfaceRecovery)
                    {
                        permit.set_phase("revalidating-host");
                        let result = reload_resident_interface_if_current(
                            &lifecycle,
                            &inner,
                            &request,
                            state.as_deref(),
                        );
                        let succeeded = result.is_ok();
                        permit.finish(if succeeded { "succeeded" } else { "failed" });
                        last_failure = if succeeded {
                            None
                        } else {
                            Some(FailedInterfaceRecoveryAttempt {
                                identity: request.identity(),
                                failed_at: Instant::now(),
                            })
                        };
                    }
                    sleep_interface_recovery_poll(&thread_stop);
                }
            })
            .ok();
        ProductRuntimeInterfaceRecoverySupervisor { stop, handle }
    }

    pub(super) fn shutdown(&mut self) {
        self.stop.store(true, AtomicOrdering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub(in crate::daed_product) struct ResidentInterfaceRecoveryRequest {
    lifecycle_epoch: u64,
    active_generation: Option<String>,
    host_observation_revision: u64,
}

impl ResidentInterfaceRecoveryRequest {
    fn identity(&self) -> InterfaceRecoveryIdentity {
        InterfaceRecoveryIdentity {
            lifecycle_epoch: self.lifecycle_epoch,
            active_generation: self.active_generation.clone(),
            host_observation_revision: self.host_observation_revision,
        }
    }
}

pub(in crate::daed_product) fn resident_interface_recovery_request(
    inner: &Arc<Mutex<ProductRuntimeState>>,
) -> Option<ResidentInterfaceRecoveryRequest> {
    let inner = inner.lock().ok()?;
    if inner.cleanup.running {
        return None;
    }
    let ProductRuntimeInstance::Resident(runtime) = inner.runtime.as_ref()? else {
        return None;
    };
    let snapshot = runtime.resident_interface_reattach_ready_snapshot()?;
    let host_observation_revision = recovery_observation_revision(&snapshot).ok()?;
    Some(ResidentInterfaceRecoveryRequest {
        lifecycle_epoch: inner.lifecycle_epoch,
        active_generation: inner.active_generation.clone(),
        host_observation_revision,
    })
}

fn interface_recovery_retry_ready(
    last_failure: Option<&FailedInterfaceRecoveryAttempt>,
    request: &ResidentInterfaceRecoveryRequest,
    now: Instant,
) -> bool {
    let Some(last_failure) = last_failure else {
        return true;
    };
    last_failure.identity.lifecycle_epoch != request.lifecycle_epoch
        || last_failure.identity.active_generation != request.active_generation
        || last_failure.identity.host_observation_revision != request.host_observation_revision
        || now.saturating_duration_since(last_failure.failed_at)
            >= PRODUCT_RUNTIME_INTERFACE_RECOVERY_RETRY
}

fn recovery_observation_revision(snapshot: &Value) -> Result<u64, String> {
    snapshot
        .pointer("/recoveryDebounce/candidateRevision")
        .and_then(Value::as_u64)
        .filter(|revision| *revision != 0)
        .ok_or_else(|| "interface recovery observation revision is missing".to_owned())
}

fn reload_resident_interface_if_current(
    lifecycle: &Arc<Mutex<()>>,
    inner: &Arc<Mutex<ProductRuntimeState>>,
    request: &ResidentInterfaceRecoveryRequest,
    state: Option<&Path>,
) -> Result<(), String> {
    let (config, config_content) = {
        let inner = inner
            .lock()
            .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
        if inner.cleanup.running
            || inner.lifecycle_epoch != request.lifecycle_epoch
            || inner.active_generation != request.active_generation
        {
            return Err("interface recovery intent was superseded by a newer runtime".to_owned());
        }
        let ProductRuntimeInstance::Resident(runtime) = inner
            .runtime
            .as_ref()
            .ok_or_else(|| "interface recovery runtime is no longer active".to_owned())?
        else {
            return Err("interface recovery requires a resident runtime".to_owned());
        };
        let snapshot = runtime
            .resident_interface_reattach_ready_snapshot()
            .ok_or_else(|| "interface recovery observation is no longer ready".to_owned())?;
        if recovery_observation_revision(&snapshot)? != request.host_observation_revision {
            return Err("interface recovery host observation was superseded".to_owned());
        }
        (
            inner
                .config
                .clone()
                .ok_or_else(|| "interface recovery active config is missing".to_owned())?,
            inner.config_content.clone(),
        )
    };
    reload_product_runtime_with_config_content(
        lifecycle,
        inner,
        config,
        config_content,
        PRODUCT_RUNTIME_INTERFACE_RECOVERY_SOURCE,
        &[],
    )?;
    let identity = recovered_runtime_identity(inner, request)?;
    if let Some(state) = state {
        super::activation_identity::persist_recovered_runtime_identity(state, &identity)?;
    }
    Ok(())
}

fn recovered_runtime_identity(
    inner: &Arc<Mutex<ProductRuntimeState>>,
    request: &ResidentInterfaceRecoveryRequest,
) -> Result<super::activation_identity::RuntimeActivationIdentity, String> {
    let inner = inner
        .lock()
        .map_err(|_| "product runtime manager lock poisoned".to_owned())?;
    if inner.active_generation != request.active_generation {
        return Err("interface recovery identity was superseded by a newer runtime".to_owned());
    }
    let product_generation = inner
        .active_generation
        .clone()
        .ok_or_else(|| "interface recovery active product generation is missing".to_owned())?;
    let ProductRuntimeInstance::Resident(runtime) = inner
        .runtime
        .as_ref()
        .ok_or_else(|| "interface recovery runtime is no longer active".to_owned())?
    else {
        return Err("interface recovery requires a resident runtime".to_owned());
    };
    let probe_generation = runtime
        .manual_probe_handle()
        .map(|handle| handle.reload_generation());
    Ok(super::activation_identity::RuntimeActivationIdentity {
        product_generation,
        probe_generation,
    })
}

fn sleep_interface_recovery_poll(stop: &AtomicBool) {
    let deadline = Instant::now() + PRODUCT_RUNTIME_INTERFACE_RECOVERY_POLL;
    while !stop.load(AtomicOrdering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        thread::sleep((deadline - now).min(PRODUCT_RUNTIME_RECOVERY_STOP_CHECK_INTERVAL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(revision: u64) -> ResidentInterfaceRecoveryRequest {
        ResidentInterfaceRecoveryRequest {
            lifecycle_epoch: 7,
            active_generation: Some("active-generation".to_owned()),
            host_observation_revision: revision,
        }
    }

    #[test]
    fn failed_recovery_is_rate_limited_only_for_the_same_host_observation() {
        let now = Instant::now();
        let failed = FailedInterfaceRecoveryAttempt {
            identity: request(11).identity(),
            failed_at: now,
        };

        assert!(!interface_recovery_retry_ready(
            Some(&failed),
            &request(11),
            now
        ));
        assert!(interface_recovery_retry_ready(
            Some(&failed),
            &request(12),
            now
        ));
        assert!(interface_recovery_retry_ready(
            Some(&failed),
            &request(11),
            now + PRODUCT_RUNTIME_INTERFACE_RECOVERY_RETRY
        ));
    }

    #[test]
    fn recovery_revision_requires_a_nonzero_stable_candidate_identity() {
        assert_eq!(
            recovery_observation_revision(&json!({
                "recoveryDebounce": {"candidateRevision": 9}
            }))
            .unwrap(),
            9
        );
        assert!(
            recovery_observation_revision(&json!({
                "recoveryDebounce": {"candidateRevision": null}
            }))
            .is_err()
        );
    }
}
