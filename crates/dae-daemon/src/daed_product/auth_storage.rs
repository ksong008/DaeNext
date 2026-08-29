use super::*;

pub(crate) use dae_product_control::auth_crypto::{
    password_hash_needs_migration, random_secret_hex, secure_random_index, signed_token,
    validate_password_strength, verify_token,
};

pub(crate) fn hash_password(salt: &[u8], password: &str) -> String {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Auth);
    #[cfg(test)]
    record_password_execution_thread(password);
    dae_product_control::auth_crypto::hash_password(salt, password)
}

pub(crate) fn verify_password_hash(stored_hash: &str, salt: &[u8], password: &str) -> bool {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Auth);
    #[cfg(test)]
    record_password_execution_thread(password);
    dae_product_control::auth_crypto::verify_password_hash(stored_hash, salt, password)
}

#[cfg(test)]
pub(crate) fn begin_password_execution_probe(password: &str) {
    password::begin_password_execution_probe(password);
}

#[cfg(test)]
pub(crate) fn finish_password_execution_probe() -> Vec<String> {
    password::finish_password_execution_probe()
}

#[cfg(test)]
mod password {
    use super::*;

    #[derive(Default)]
    struct PasswordExecutionProbe {
        password: String,
        threads: Vec<String>,
    }

    static PASSWORD_EXECUTION_PROBE: OnceLock<Mutex<Option<PasswordExecutionProbe>>> =
        OnceLock::new();

    pub(super) fn begin_password_execution_probe(password: &str) {
        let probe = PASSWORD_EXECUTION_PROBE.get_or_init(|| Mutex::new(None));
        *probe.lock().expect("password execution probe lock") = Some(PasswordExecutionProbe {
            password: password.to_owned(),
            threads: Vec::new(),
        });
    }

    pub(super) fn finish_password_execution_probe() -> Vec<String> {
        PASSWORD_EXECUTION_PROBE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("password execution probe lock")
            .take()
            .map(|probe| probe.threads)
            .unwrap_or_default()
    }

    pub(super) fn record_password_execution_thread(password: &str) {
        let probe = PASSWORD_EXECUTION_PROBE.get_or_init(|| Mutex::new(None));
        let Ok(mut probe) = probe.lock() else {
            return;
        };
        let Some(probe) = probe.as_mut().filter(|probe| probe.password == password) else {
            return;
        };
        probe
            .threads
            .push(thread::current().name().unwrap_or("unnamed").to_owned());
    }
}

#[cfg(test)]
fn record_password_execution_thread(password: &str) {
    password::record_password_execution_thread(password);
}

#[cfg(test)]
pub(crate) use dae_product_identity::legacy_password_hash_for_test;
