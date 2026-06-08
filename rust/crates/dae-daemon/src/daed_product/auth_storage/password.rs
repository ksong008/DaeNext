use super::*;
pub(crate) fn hash_password(salt: &[u8], password: &str) -> String {
    let mut h = Shake256::default();
    h.update(salt);
    h.update(password.as_bytes());
    let mut reader = h.finalize_xof();
    let mut hash = [0_u8; 32];
    XofReader::read(&mut reader, &mut hash);
    hex_encode(&hash)
}

pub(crate) fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 6
        || !password.chars().any(char::is_alphabetic)
        || !password.chars().any(|ch| ch.is_ascii_digit())
    {
        return Err(
            "too weak password; should contain numbers and letters, and no less than 6 in length"
                .to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn random_secret_hex() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex_encode(&bytes))
}
