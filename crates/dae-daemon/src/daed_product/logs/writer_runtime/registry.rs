use super::*;
use std::sync::{PoisonError, Weak};

type LogRuntimes = HashMap<PathBuf, (Weak<ProductLogRuntime>, Weak<ProductLogQueue>)>;
static PRODUCT_LOG_RUNTIME_REGISTRY: OnceLock<Mutex<LogRuntimes>> = OnceLock::new();

pub(super) fn reserve_product_log_worker(
    config_dir: &Path,
    queue: &Arc<ProductLogQueue>,
) -> io::Result<()> {
    let mut registry = registry_guard();
    let key = product_log_file(config_dir);
    if registry.contains_key(&key) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "product log worker is still active",
        ));
    }
    registry.insert(key, (Weak::new(), Arc::downgrade(queue)));
    Ok(())
}

pub(super) fn ensure_product_log_worker_stopped(config_dir: &Path) -> io::Result<()> {
    if registry_guard().contains_key(&product_log_file(config_dir)) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "previous product log worker is still stopping",
        ));
    }
    Ok(())
}

// Startup holds FALLBACK_WRITERS through reservation, spawn and association.
pub(super) fn register_product_log_runtime(runtime: &Arc<ProductLogRuntime>) {
    registry_guard().insert(
        runtime.registry_key.clone(),
        (Arc::downgrade(runtime), Arc::downgrade(&runtime.queue)),
    );
}

pub(crate) fn product_log_runtime_for(config_dir: &Path) -> Option<Arc<ProductLogRuntime>> {
    registry_guard()
        .get(&product_log_file(config_dir))
        .and_then(|(runtime, _)| runtime.upgrade())
}

fn registry_guard() -> std::sync::MutexGuard<'static, LogRuntimes> {
    let mutex = PRODUCT_LOG_RUNTIME_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = mutex.lock().unwrap_or_else(PoisonError::into_inner);
    // The worker retains its queue through startup, final drain and detach.
    // A dead runtime Weak must not allow a second writer during that interval.
    registry.retain(|_, (runtime, queue)| runtime.strong_count() > 0 || queue.strong_count() > 0);
    registry
}

#[cfg(test)]
mod poison_tests;
