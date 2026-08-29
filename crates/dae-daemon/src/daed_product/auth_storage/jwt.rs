use super::*;

pub(crate) fn signed_token(user: &UserRecord) -> io::Result<String> {
    let exp = unix_now()
        .checked_add(TOKEN_TTL_SECONDS)
        .ok_or_else(|| io::Error::other("token expiration overflow"))?;
    Ok(dae_product_identity::sign_hs256_token(
        user.username(),
        user.jwt_secret().as_bytes(),
        exp,
    ))
}

pub(crate) fn verify_token(state: &Path, token: &str) -> io::Result<Option<UserRecord>> {
    let Some(parsed) = dae_product_identity::parse_hs256_token(token)? else {
        return Ok(None);
    };
    let Some(user) = load_user_by_username_without_schema_check(state, parsed.subject())? else {
        return Ok(None);
    };
    if !parsed.verify_signature(user.jwt_secret().as_bytes()) {
        return Ok(None);
    }
    if parsed.expiration() <= unix_now() {
        return Ok(None);
    }
    Ok(Some(user))
}
