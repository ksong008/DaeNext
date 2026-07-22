use super::*;

#[derive(Clone, Debug)]
pub(super) struct ProductGeodataUpdateContext {
    pub(super) state: PathBuf,
    pub(super) dir: PathBuf,
    pub(super) runtime: Arc<ProductRuntimeManager>,
    pub(super) control_runtime: Arc<ProductControlRuntime>,
    pub(super) updates: Arc<ProductGeodataUpdateCoordinator>,
    pub(super) status_cache: Arc<Mutex<GeodataStatusCache>>,
}

impl ProductGeodataUpdateContext {
    pub(super) fn from_app(app: &AppState) -> Self {
        Self {
            state: app.state.clone(),
            dir: super::status::geodata_dir(app),
            runtime: Arc::clone(&app.runtime),
            control_runtime: Arc::clone(&app.control_runtime),
            updates: Arc::clone(&app.geodata_updates),
            status_cache: Arc::clone(&app.geodata_status_cache),
        }
    }

    #[cfg(test)]
    pub(super) fn new(
        state: PathBuf,
        web_root: &Path,
        runtime: Arc<ProductRuntimeManager>,
        control_runtime: Arc<ProductControlRuntime>,
        updates: Arc<ProductGeodataUpdateCoordinator>,
        status_cache: Arc<Mutex<GeodataStatusCache>>,
    ) -> Self {
        Self {
            state,
            dir: super::status::geodata_dir_for_web_root(web_root),
            runtime,
            control_runtime,
            updates,
            status_cache,
        }
    }
}
