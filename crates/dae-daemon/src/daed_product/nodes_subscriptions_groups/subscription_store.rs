use super::*;

pub(super) fn subscription_write_guard() -> io::Result<std::sync::MutexGuard<'static, ()>> {
    static SUBSCRIPTION_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    SUBSCRIPTION_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| io::Error::other("subscription write lock poisoned"))
}
