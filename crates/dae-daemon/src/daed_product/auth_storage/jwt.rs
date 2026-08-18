use super::*;

const MAX_JWT_TOKEN_BYTES: usize = 8 * 1024;
const MAX_JWT_PART_BYTES: usize = 4 * 1024;
const MAX_JWT_SUBJECT_BYTES: usize = 256;
pub(crate) fn signed_token(user: &UserRecord) -> io::Result<String> {
    let exp = unix_now()
        .checked_add(TOKEN_TTL_SECONDS)
        .ok_or_else(|| io::Error::other("token expiration overflow"))?;
    let header = json!({"alg": "HS256", "typ": "JWT"}).to_string();
    let payload = json!({
        "role": "admin",
        "sub": user.username,
        "exp": exp,
    })
    .to_string();
    let encoded_header = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = hmac_sha256(user.jwt_secret.as_bytes(), signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

pub(crate) fn verify_token(state: &Path, token: &str) -> io::Result<Option<UserRecord>> {
    if token.len() > MAX_JWT_TOKEN_BYTES {
        return Ok(None);
    }
    let mut parts = token.split('.');
    let Some(header) = parts.next() else {
        return Ok(None);
    };
    let Some(payload) = parts.next() else {
        return Ok(None);
    };
    let Some(signature) = parts.next() else {
        return Ok(None);
    };
    if header.len() > MAX_JWT_PART_BYTES
        || payload.len() > MAX_JWT_PART_BYTES
        || signature.len() > MAX_JWT_PART_BYTES
    {
        return Ok(None);
    }
    if parts.next().is_some() {
        return Ok(None);
    }
    let header_value = match decode_jwt_part(header) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::InvalidData => return Ok(None),
        Err(err) => return Err(err),
    };
    if header_value.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Ok(None);
    }
    let payload_value = match decode_jwt_part(payload) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::InvalidData => return Ok(None),
        Err(err) => return Err(err),
    };
    let Some(username) = payload_value.get("sub").and_then(Value::as_str) else {
        return Ok(None);
    };
    if username.is_empty() || username.len() > MAX_JWT_SUBJECT_BYTES {
        return Ok(None);
    }
    // F-05: 认证热路径跳过重复 schema 校验（启动时已执行）。
    let Some(user) = load_user_by_username_without_schema_check(state, username)? else {
        return Ok(None);
    };
    let signing_input = format!("{header}.{payload}");
    let expected = hmac_sha256(user.jwt_secret.as_bytes(), signing_input.as_bytes());
    let Ok(actual) = URL_SAFE_NO_PAD.decode(signature.as_bytes()) else {
        return Ok(None);
    };
    if !constant_time_eq(&expected, &actual) {
        return Ok(None);
    }
    let exp = payload_value
        .get("exp")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if exp <= unix_now() {
        return Ok(None);
    }
    Ok(Some(user))
}

pub(crate) fn decode_jwt_part(part: &str) -> io::Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    sha2::Digest::update(&mut inner, ipad);
    sha2::Digest::update(&mut inner, data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    sha2::Digest::update(&mut outer, opad);
    sha2::Digest::update(&mut outer, inner);
    let digest = outer.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}
