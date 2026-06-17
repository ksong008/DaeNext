use super::*;

const ARGON2ID_HASH_PREFIX: &str = "$argon2id$";
const PASSWORD_MIN_LEN: usize = 8;

pub(crate) fn hash_password(salt: &[u8], password: &str) -> String {
    hash_password_argon2id(salt, password)
}

pub(crate) fn verify_password_hash(stored_hash: &str, salt: &[u8], password: &str) -> bool {
    if stored_hash.starts_with(ARGON2ID_HASH_PREFIX) {
        return verify_argon2id_password_hash(stored_hash, password);
    }
    hash_password_legacy_shake256(salt, password) == stored_hash
}

pub(crate) fn password_hash_needs_migration(stored_hash: &str) -> bool {
    !stored_hash.starts_with(ARGON2ID_HASH_PREFIX)
}

fn hash_password_argon2id(salt: &[u8], password: &str) -> String {
    let salt_digest = Sha256::digest(salt);
    let salt = SaltString::encode_b64(&salt_digest[..16])
        .expect("sha256-derived password salt is valid base64 salt input");
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2id password hashing with fixed parameters should not fail")
        .to_string()
}

fn verify_argon2id_password_hash(stored_hash: &str, password: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn hash_password_legacy_shake256(salt: &[u8], password: &str) -> String {
    let mut h = Shake256::default();
    h.update(salt);
    h.update(password.as_bytes());
    let mut reader = h.finalize_xof();
    let mut hash = [0_u8; 32];
    XofReader::read(&mut reader, &mut hash);
    hex_encode(&hash)
}

#[cfg(test)]
pub(crate) fn legacy_password_hash_for_test(salt: &[u8], password: &str) -> String {
    hash_password_legacy_shake256(salt, password)
}

pub(crate) fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < PASSWORD_MIN_LEN
        || !password.chars().any(char::is_alphabetic)
        || !password.chars().any(|ch| ch.is_ascii_digit())
    {
        return Err(format!(
            "too weak password; should contain numbers and letters, and no less than {PASSWORD_MIN_LEN} in length"
        ));
    }
    Ok(())
}

pub(crate) fn random_secret_hex() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    fill_random_bytes(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

pub(crate) fn fill_random_bytes(bytes: &mut [u8]) -> io::Result<()> {
    fs::File::open("/dev/urandom")?.read_exact(bytes)
}

pub(crate) fn secure_random_index(rng: &mut fs::File, upper: usize) -> io::Result<usize> {
    if upper == 0 || upper > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure random index upper bound must be in 1..=256",
        ));
    }
    let rejection_floor = 256 - (256 % upper);
    let mut byte = [0_u8; 1];
    loop {
        rng.read_exact(&mut byte)?;
        let value = byte[0] as usize;
        if value < rejection_floor {
            return Ok(value % upper);
        }
    }
}
