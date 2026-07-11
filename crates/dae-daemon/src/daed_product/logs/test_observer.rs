use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProductLogIoTestSnapshot {
    pub(crate) runtime_level_reads: u64,
    pub(crate) settings_reads: u64,
    pub(crate) append_opens: u64,
    pub(crate) file_permission_writes: u64,
    pub(crate) dir_permission_writes: u64,
    pub(crate) prune_rewrites: u64,
}

#[derive(Debug, Default)]
struct ProductLogIoTestState {
    log_file: Option<PathBuf>,
    log_dir: Option<PathBuf>,
    state_file: Option<PathBuf>,
    snapshot: ProductLogIoTestSnapshot,
}

static PRODUCT_LOG_IO_TEST_STATE: OnceLock<Mutex<ProductLogIoTestState>> = OnceLock::new();

pub(crate) struct ProductLogIoTestObservation;

pub(crate) fn observe_product_log_io(
    config_dir: &Path,
    state_file: &Path,
) -> ProductLogIoTestObservation {
    let mut state = test_state().lock().unwrap();
    state.log_file = Some(product_log_file(config_dir));
    state.log_dir = Some(product_log_dir(config_dir));
    state.state_file = Some(state_file.to_path_buf());
    state.snapshot = ProductLogIoTestSnapshot::default();
    ProductLogIoTestObservation
}

pub(crate) fn product_log_io_test_snapshot() -> ProductLogIoTestSnapshot {
    test_state().lock().unwrap().snapshot
}

pub(crate) fn observe_runtime_level_read(path: &Path) {
    observe_path(path, ProductLogIoTestPathKind::State, |snapshot| {
        snapshot.runtime_level_reads = snapshot.runtime_level_reads.saturating_add(1);
    });
}

pub(crate) fn observe_log_settings_read(path: &Path) {
    observe_path(path, ProductLogIoTestPathKind::State, |snapshot| {
        snapshot.settings_reads = snapshot.settings_reads.saturating_add(1);
    });
}

pub(crate) fn observe_log_append_open(path: &Path) {
    observe_path(path, ProductLogIoTestPathKind::File, |snapshot| {
        snapshot.append_opens = snapshot.append_opens.saturating_add(1);
    });
}

pub(crate) fn observe_log_file_permission_write(path: &Path) {
    observe_path(path, ProductLogIoTestPathKind::File, |snapshot| {
        snapshot.file_permission_writes = snapshot.file_permission_writes.saturating_add(1);
    });
}

pub(crate) fn observe_log_dir_permission_write(path: &Path) {
    observe_path(path, ProductLogIoTestPathKind::Dir, |snapshot| {
        snapshot.dir_permission_writes = snapshot.dir_permission_writes.saturating_add(1);
    });
}

pub(crate) fn observe_log_prune_rewrite(path: &Path) {
    observe_path(path, ProductLogIoTestPathKind::File, |snapshot| {
        snapshot.prune_rewrites = snapshot.prune_rewrites.saturating_add(1);
    });
}

impl Drop for ProductLogIoTestObservation {
    fn drop(&mut self) {
        *test_state().lock().unwrap() = ProductLogIoTestState::default();
    }
}

#[derive(Clone, Copy)]
enum ProductLogIoTestPathKind {
    File,
    Dir,
    State,
}

fn test_state() -> &'static Mutex<ProductLogIoTestState> {
    PRODUCT_LOG_IO_TEST_STATE.get_or_init(|| Mutex::new(ProductLogIoTestState::default()))
}

fn observe_path(
    path: &Path,
    kind: ProductLogIoTestPathKind,
    update: impl FnOnce(&mut ProductLogIoTestSnapshot),
) {
    let mut state = test_state().lock().unwrap();
    let tracked = match kind {
        ProductLogIoTestPathKind::File => state.log_file.as_deref(),
        ProductLogIoTestPathKind::Dir => state.log_dir.as_deref(),
        ProductLogIoTestPathKind::State => state.state_file.as_deref(),
    };
    if tracked == Some(path) {
        update(&mut state.snapshot);
    }
}
