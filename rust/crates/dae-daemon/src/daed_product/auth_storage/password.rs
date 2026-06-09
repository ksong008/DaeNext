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
