use super::*;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

#[derive(Debug)]
pub(super) struct ProductRuntimeInterfaceRecoverySupervisor {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProductRuntimeInterfaceRecoverySupervisor {
    pub(super) fn start(
        coordinator: RuntimeApplyCoordinator,
        lifecycle: Arc<Mutex<()>>,
        inner: Arc<Mutex<ProductRuntimeState>>,
    ) -> ProductRuntimeInterfaceRecoverySupervisor {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("product-runtime-interface-recovery".to_owned())
            .spawn(move || {
                let mut last_attempt = None::<Instant>;
                while !thread_stop.load(AtomicOrdering::Relaxed) {
                    let retry_elapsed = last_attempt
                        .map(|attempt| {
                            attempt.elapsed() >= PRODUCT_RUNTIME_INTERFACE_RECOVERY_RETRY
                        })
                        .unwrap_or(true);
                    if retry_elapsed
                        && let Some(request) = resident_interface_recovery_request(&inner)
                    {
                        if let Ok(permit) =
                            coordinator.begin_apply(RuntimeApplyIntent::InterfaceRecovery)
                        {
                            permit.set_phase("revalidating-host");
                            let result =
                                reload_resident_interface_if_current(&lifecycle, &inner, &request);
                            permit.finish(if result.is_ok() {
                                "succeeded"
                            } else {
                                "failed"
                            });
                        }
                        last_attempt = Some(Instant::now());
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
    runtime.resident_interface_reattach_ready_snapshot()?;
    Some(ResidentInterfaceRecoveryRequest {
        lifecycle_epoch: inner.lifecycle_epoch,
        active_generation: inner.active_generation.clone(),
    })
}

fn reload_resident_interface_if_current(
    lifecycle: &Arc<Mutex<()>>,
    inner: &Arc<Mutex<ProductRuntimeState>>,
    request: &ResidentInterfaceRecoveryRequest,
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
        runtime
            .resident_interface_reattach_ready_snapshot()
            .ok_or_else(|| "interface recovery observation is no longer ready".to_owned())?;
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
    )
    .map(|_| ())
}

fn sleep_interface_recovery_poll(stop: &AtomicBool) {
    let sleep_step = PRODUCT_RUNTIME_INTERFACE_RECOVERY_POLL / 20;
    for _ in 0..20 {
        if stop.load(AtomicOrdering::Relaxed) {
            return;
        }
        thread::sleep(sleep_step);
    }
}
