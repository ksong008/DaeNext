use std::sync::{Mutex, MutexGuard};

// Resource inventories must survive a panic until every recorded task/connection
// is retired. Keep poison sticky so admission still fails closed; only cleanup
// and observation may use this guard. Never reset a resource inventory to empty.
pub(crate) fn cleanup_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
