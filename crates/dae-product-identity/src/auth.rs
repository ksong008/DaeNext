use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::Digest;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::io::{self, Read};

const MAX_JWT_TOKEN_BYTES: usize = 8 * 1024;
const MAX_JWT_PART_BYTES: usize = 4 * 1024;
const MAX_JWT_SUBJECT_BYTES: usize = 256;
const ARGON2ID_HASH_PREFIX: &str = "$argon2id$";
const PASSWORD_MIN_LEN: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedJwtToken {
    encoded_header: String,
    encoded_payload: String,
    signature: Vec<u8>,
    subject: String,
    expiration: u64,
}

impl ParsedJwtToken {
    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn expiration(&self) -> u64 {
        self.expiration
    }

    pub fn verify_signature(&self, secret: &[u8]) -> bool {
        let signing_input = format!("{}.{}", self.encoded_header, self.encoded_payload);
        constant_time_eq(
            &hmac_sha256(secret, signing_input.as_bytes()),
            &self.signature,
        )
    }
}

pub fn sign_hs256_token(username: &str, jwt_secret: &[u8], expiration: u64) -> String {
    let header = json!({"alg": "HS256", "typ": "JWT"}).to_string();
    let payload = json!({
        "role": "admin",
        "sub": username,
        "exp": expiration,
    })
    .to_string();
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = hmac_sha256(jwt_secret, signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

pub fn parse_hs256_token(token: &str) -> io::Result<Option<ParsedJwtToken>> {
    if token.len() > MAX_JWT_TOKEN_BYTES {
        return Ok(None);
    }
    let mut parts = token.split('.');
    let Some(encoded_header) = parts.next() else {
        return Ok(None);
    };
    let Some(encoded_payload) = parts.next() else {
        return Ok(None);
    };
    let Some(encoded_signature) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some()
        || encoded_header.len() > MAX_JWT_PART_BYTES
        || encoded_payload.len() > MAX_JWT_PART_BYTES
        || encoded_signature.len() > MAX_JWT_PART_BYTES
    {
        return Ok(None);
    }
    let header = match decode_jwt_part(encoded_header) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(None),
        Err(error) => return Err(error),
    };
    if header.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Ok(None);
    }
    let payload = match decode_jwt_part(encoded_payload) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(subject) = payload.get("sub").and_then(Value::as_str) else {
        return Ok(None);
    };
    if subject.is_empty() || subject.len() > MAX_JWT_SUBJECT_BYTES {
        return Ok(None);
    }
    let Ok(signature) = URL_SAFE_NO_PAD.decode(encoded_signature.as_bytes()) else {
        return Ok(None);
    };
    Ok(Some(ParsedJwtToken {
        encoded_header: encoded_header.to_owned(),
        encoded_payload: encoded_payload.to_owned(),
        signature,
        subject: subject.to_owned(),
        expiration: payload.get("exp").and_then(Value::as_u64).unwrap_or(0),
    }))
}

pub fn decode_jwt_part(part: &str) -> io::Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        let digest = sha2::Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];
    for index in 0..64 {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = sha2::Sha256::new();
    sha2::Digest::update(&mut inner, ipad);
    sha2::Digest::update(&mut inner, data);
    let inner = inner.finalize();
    let mut outer = sha2::Sha256::new();
    sha2::Digest::update(&mut outer, opad);
    sha2::Digest::update(&mut outer, inner);
    let digest = outer.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

pub fn hash_password(salt: &[u8], password: &str) -> String {
    let salt_digest = sha2::Sha256::digest(salt);
    let salt = SaltString::encode_b64(&salt_digest[..16])
        .expect("sha256-derived password salt is valid base64 salt input");
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2id password hashing with fixed parameters should not fail")
        .to_string()
}

pub fn verify_password_hash(stored_hash: &str, salt: &[u8], password: &str) -> bool {
    if stored_hash.starts_with(ARGON2ID_HASH_PREFIX) {
        let Ok(parsed_hash) = PasswordHash::new(stored_hash) else {
            return false;
        };
        return Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();
    }
    hash_password_legacy_shake256(salt, password) == stored_hash
}

pub fn password_hash_needs_migration(stored_hash: &str) -> bool {
    !stored_hash.starts_with(ARGON2ID_HASH_PREFIX)
}

pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < PASSWORD_MIN_LEN
        || !password.chars().any(char::is_alphabetic)
        || !password.chars().any(|character| character.is_ascii_digit())
    {
        return Err(format!(
            "too weak password; should contain numbers and letters, and no less than {PASSWORD_MIN_LEN} in length"
        ));
    }
    Ok(())
}

pub fn random_secret_hex() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    fill_random_bytes(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

pub fn fill_random_bytes(bytes: &mut [u8]) -> io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}

pub fn secure_random_index<R: Read>(reader: &mut R, upper: usize) -> io::Result<usize> {
    if upper == 0 || upper > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secure random index upper bound must be in 1..=256",
        ));
    }
    let rejection_floor = 256 - (256 % upper);
    let mut byte = [0_u8; 1];
    loop {
        reader.read_exact(&mut byte)?;
        let value = byte[0] as usize;
        if value < rejection_floor {
            return Ok(value % upper);
        }
    }
}

fn hash_password_legacy_shake256(salt: &[u8], password: &str) -> String {
    let mut hasher = Shake256::default();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut hash = [0_u8; 32];
    XofReader::read(&mut reader, &mut hash);
    hex_encode(&hash)
}

pub fn legacy_password_hash_for_test(salt: &[u8], password: &str) -> String {
    hash_password_legacy_shake256(salt, password)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
