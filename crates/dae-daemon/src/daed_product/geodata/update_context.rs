use super::*;

#[derive(Clone, Debug)]
pub(crate) struct ProductGeodataUpdateContext {
    pub(super) state: PathBuf,
    pub(super) paths: Arc<ProductGeodataPaths>,
    pub(super) runtime: Arc<ProductRuntimeManager>,
    pub(super) control_runtime: Arc<ProductControlRuntime>,
    pub(super) updates: Arc<ProductGeodataUpdateCoordinator>,
    pub(super) status_cache: Arc<Mutex<GeodataStatusCache>>,
}

impl ProductGeodataUpdateContext {
    pub(super) fn from_app(app: &AppState) -> Self {
        Self {
            state: app.state.clone(),
            paths: Arc::clone(&app.geodata_paths),
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
            paths: Arc::new(ProductGeodataPaths::for_directory(
                web_root.parent().unwrap_or(web_root),
            )),
            runtime,
            control_runtime,
            updates,
            status_cache,
        }
    }
}

impl dae_product_control::geodata::GeodataUpdateRuntimeContext for ProductGeodataUpdateContext {
    fn state_path(&self) -> &Path {
        &self.state
    }

    fn directory(&self, kind: GeodataKind) -> io::Result<PathBuf> {
        self.paths.recover(&self.state, kind)?;
        Ok(self.paths.update_directory(kind))
    }
}
