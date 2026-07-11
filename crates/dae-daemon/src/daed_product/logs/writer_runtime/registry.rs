use super::*;

static PRODUCT_LOG_RUNTIME_REGISTRY: OnceLock<
    Mutex<HashMap<PathBuf, std::sync::Weak<ProductLogRuntime>>>,
> = OnceLock::new();

pub(super) fn register_product_log_runtime(runtime: &Arc<ProductLogRuntime>) -> io::Result<()> {
    let mut registry = registry()
        .lock()
        .map_err(|_| io::Error::other("product log runtime registry is unavailable"))?;
    registry.retain(|_, runtime| runtime.strong_count() > 0);
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
    registry.insert(
        runtime.registry_key().to_path_buf(),
        Arc::downgrade(runtime),
    );
    Ok(())
}

pub(super) fn unregister_product_log_runtime(runtime: &ProductLogRuntime) {
    let Ok(mut registry) = registry().lock() else {
        return;
    };
    let remove = registry
        .get(runtime.registry_key())
        .and_then(std::sync::Weak::upgrade)
        .is_none_or(|registered| std::ptr::eq(Arc::as_ptr(&registered), runtime));
    if remove {
        registry.remove(runtime.registry_key());
    }
}

pub(crate) fn product_log_runtime_for(config_dir: &Path) -> Option<Arc<ProductLogRuntime>> {
    let key = product_log_file(config_dir);
    let mut registry = registry().lock().ok()?;
    let runtime = registry.get(&key).and_then(std::sync::Weak::upgrade);
    if runtime.is_none() {
        registry.remove(&key);
    }
    runtime
}

fn registry() -> &'static Mutex<HashMap<PathBuf, std::sync::Weak<ProductLogRuntime>>> {
    PRODUCT_LOG_RUNTIME_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}
