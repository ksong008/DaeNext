use super::*;

pub(super) struct ProductLogAppendRequest {
    pub(super) level: String,
    pub(super) message: String,
    pub(super) fields: BTreeMap<String, String>,
    pub(super) respect_runtime_log_level: bool,
}

pub(super) enum ProductLogAction {
    Append(ProductLogAppendRequest),
    Clear,
    ClearPreservingLifecycle,
    ReplacePolicy(ProductLogPolicy),
    ApplyLimits { max_entries: i64, max_bytes: i64 },
}

pub(super) struct ProductLogCommand {
    pub(super) action: ProductLogAction,
    pub(super) completion: mpsc::SyncSender<io::Result<()>>,
}
