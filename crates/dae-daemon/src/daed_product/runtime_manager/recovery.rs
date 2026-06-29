use super::*;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

#[derive(Debug)]
pub(super) struct ProductRuntimeInterfaceRecoverySupervisor {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProductRuntimeInterfaceRecoverySupervisor {
    pub(super) fn start(
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
                        let _ = reload_product_runtime_with_config_content(
                            &lifecycle,
                            &inner,
                            request.config,
                            request.config_content,
                            PRODUCT_RUNTIME_INTERFACE_RECOVERY_SOURCE,
                            &[],
                        );
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
    config: Config,
    config_content: Option<String>,
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
        config: inner.config.clone()?,
        config_content: inner.config_content.clone(),
    })
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
