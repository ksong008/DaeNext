use super::*;
use std::sync::{PoisonError, Weak};

type LogRuntimes = HashMap<PathBuf, Weak<ProductLogRuntime>>;
static PRODUCT_LOG_RUNTIME_REGISTRY: OnceLock<Mutex<LogRuntimes>> = OnceLock::new();

pub(super) fn register_product_log_runtime(runtime: &Arc<ProductLogRuntime>) -> io::Result<()> {
    let mut registry = registry_guard();
    if registry
        .get(runtime.registry_key())
        .and_then(std::sync::Weak::upgrade)
        .is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "product log runtime is already active for this log store",
        ));
    }
    registry.insert(runtime.registry_key.clone(), Arc::downgrade(runtime));
    Ok(())
}

pub(super) fn unregister_product_log_runtime(runtime: &ProductLogRuntime) {
    let mut registry = registry_guard();
    let remove = registry
        .get(runtime.registry_key())
        .and_then(std::sync::Weak::upgrade)
        .is_none_or(|registered| std::ptr::eq(Arc::as_ptr(&registered), runtime));
    if remove {
        registry.remove(runtime.registry_key());
    }
}

pub(crate) fn product_log_runtime_for(config_dir: &Path) -> Option<Arc<ProductLogRuntime>> {
    registry_guard()
        .get(&product_log_file(config_dir))
        .and_then(std::sync::Weak::upgrade)
}

fn registry_guard() -> std::sync::MutexGuard<'static, LogRuntimes> {
    let mutex = PRODUCT_LOG_RUNTIME_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = mutex.lock().unwrap_or_else(PoisonError::into_inner);
    // Preserve live Weak identities so poison cannot start a second writer.
    registry.retain(|_, runtime| runtime.strong_count() > 0);
    mutex.clear_poison();
    registry
}

#[cfg(test)]
mod poison_tests;
