use super::*;

const GEODATA_STAGING_PATH_CREATE_ATTEMPTS: usize = 64;

#[derive(Debug, Default)]
struct ProductGeodataUpdateState {
    geosite_in_progress: bool,
    geoip_in_progress: bool,
}

#[derive(Debug, Default)]
pub(in crate::daed_product) struct ProductGeodataUpdateCoordinator {
    state: Mutex<ProductGeodataUpdateState>,
    next_generation: AtomicU64,
}

#[derive(Debug)]
pub(super) struct ProductGeodataUpdateLease {
    coordinator: Arc<ProductGeodataUpdateCoordinator>,
    kind: GeodataKind,
}

impl ProductGeodataUpdateCoordinator {
    pub(super) fn acquire(
        self: &Arc<Self>,
        kind: GeodataKind,
    ) -> io::Result<ProductGeodataUpdateLease> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("geodata update coordinator is unavailable"))?;
        let in_progress = match kind {
            GeodataKind::Geosite => &mut state.geosite_in_progress,
            GeodataKind::Geoip => &mut state.geoip_in_progress,
        };
        if *in_progress {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("{} update is already in progress", kind.response_key()),
            ));
        }
        *in_progress = true;
        Ok(ProductGeodataUpdateLease {
            coordinator: Arc::clone(self),
            kind,
        })
    }

    pub(super) fn reserve_staging_path(
        &self,
        dir: &Path,
        kind: GeodataKind,
        purpose: &str,
    ) -> io::Result<PathBuf> {
        for _ in 0..GEODATA_STAGING_PATH_CREATE_ATTEMPTS {
            let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
            let path = dir.join(format!(
                ".{}.{}.tmp.{}.{}",
                kind.file_name(),
                purpose,
                std::process::id(),
                generation
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    drop(file);
                    return Ok(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "cannot reserve unique {} staging path for {}",
                purpose,
                kind.response_key()
            ),
        ))
    }

    fn release(&self, kind: GeodataKind) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        match kind {
            GeodataKind::Geosite => state.geosite_in_progress = false,
            GeodataKind::Geoip => state.geoip_in_progress = false,
        }
    }
}

impl Drop for ProductGeodataUpdateLease {
    fn drop(&mut self) {
        self.coordinator.release(self.kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geodata_update_admission_is_independent_per_kind() {
        let coordinator = Arc::new(ProductGeodataUpdateCoordinator::default());
        let geosite = coordinator.acquire(GeodataKind::Geosite).unwrap();
        let geoip = coordinator.acquire(GeodataKind::Geoip).unwrap();
        assert_eq!(
            coordinator
                .acquire(GeodataKind::Geosite)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(geosite);
        assert!(coordinator.acquire(GeodataKind::Geosite).is_ok());
        drop(geoip);
    }

    #[test]
    fn geodata_staging_paths_are_atomically_unique_and_skip_stale_files() {
        let dir = std::env::temp_dir().join(format!(
            "daed-product-geodata-staging-path-{}",
            fastrand::u64(..)
        ));
        fs::create_dir_all(&dir).unwrap();
        let coordinator = ProductGeodataUpdateCoordinator::default();
        let stale = dir.join(format!(
            ".{}.download.tmp.{}.1",
            GeodataKind::Geosite.file_name(),
            std::process::id()
        ));
        fs::write(&stale, b"stale").unwrap();

        let first = coordinator
            .reserve_staging_path(&dir, GeodataKind::Geosite, "download")
            .unwrap();
        let second = coordinator
            .reserve_staging_path(&dir, GeodataKind::Geosite, "download")
            .unwrap();

        assert_ne!(first, stale);
        assert_ne!(first, second);
        assert!(first.is_file());
        assert!(second.is_file());
        fs::remove_dir_all(dir).unwrap();
    }
}
