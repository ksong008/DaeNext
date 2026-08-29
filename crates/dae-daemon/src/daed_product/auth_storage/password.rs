use super::*;

pub(crate) fn hash_password(salt: &[u8], password: &str) -> String {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Auth);
    #[cfg(test)]
    record_password_execution_thread(password);
    dae_product_identity::hash_password(salt, password)
}

pub(crate) fn verify_password_hash(stored_hash: &str, salt: &[u8], password: &str) -> bool {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Auth);
    #[cfg(test)]
    record_password_execution_thread(password);
    dae_product_identity::verify_password_hash(stored_hash, salt, password)
}

#[cfg(test)]
#[derive(Default)]
struct PasswordExecutionProbe {
    password: String,
    threads: Vec<String>,
}

#[cfg(test)]
static PASSWORD_EXECUTION_PROBE: OnceLock<Mutex<Option<PasswordExecutionProbe>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn begin_password_execution_probe(password: &str) {
    let probe = PASSWORD_EXECUTION_PROBE.get_or_init(|| Mutex::new(None));
    *probe.lock().expect("password execution probe lock") = Some(PasswordExecutionProbe {
        password: password.to_owned(),
        threads: Vec::new(),
    });
}

#[cfg(test)]
pub(crate) fn finish_password_execution_probe() -> Vec<String> {
    PASSWORD_EXECUTION_PROBE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("password execution probe lock")
        .take()
        .map(|probe| probe.threads)
        .unwrap_or_default()
}

#[cfg(test)]
fn record_password_execution_thread(password: &str) {
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

pub(crate) fn password_hash_needs_migration(stored_hash: &str) -> bool {
    dae_product_identity::password_hash_needs_migration(stored_hash)
}

#[cfg(test)]
pub(crate) fn legacy_password_hash_for_test(salt: &[u8], password: &str) -> String {
    dae_product_identity::legacy_password_hash_for_test(salt, password)
}

pub(crate) fn validate_password_strength(password: &str) -> Result<(), String> {
    dae_product_identity::validate_password_strength(password)
}

pub(crate) fn random_secret_hex() -> io::Result<String> {
    dae_product_identity::random_secret_hex()
}

pub(crate) fn secure_random_index<R: Read>(rng: &mut R, upper: usize) -> io::Result<usize> {
    dae_product_identity::secure_random_index(rng, upper)
}
