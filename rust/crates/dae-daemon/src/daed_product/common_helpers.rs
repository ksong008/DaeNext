use super::*;
pub(super) fn integer_array(body: &Value, key: &str) -> Vec<i64> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn now_text() -> String {
    iso8601_utc(unix_now())
}

pub(super) fn iso8601_utc(timestamp: u64) -> String {
    let seconds = timestamp as i64;
    let days = seconds.div_euclid(86_400);
    let rem = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub(super) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

pub(super) fn reset_all_user_passwords(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id, username FROM users ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_io_error)?;
    let mut users = Vec::new();
    for row in rows {
        let (id, username) = row.map_err(sqlite_io_error)?;
        let password = random_recovery_password();
        let secret = random_secret_hex()?;
        let password_hash = hash_password(secret.as_bytes(), &password);
        conn.execute(
            "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
            params![password_hash, secret, id],
        )
        .map_err(sqlite_io_error)?;
        users.push(json!({
            "id": id,
            "username": username,
            "password": password,
        }));
    }
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "rustDaedWritesWingDbByDefault": false,
        "users": users,
    }))
}

pub(super) fn random_recovery_password() -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const ALL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = Vec::with_capacity(12);
    out.push(LETTERS[fastrand::usize(..LETTERS.len())]);
    out.push(DIGITS[fastrand::usize(..DIGITS.len())]);
    for _ in 2..12 {
        out.push(ALL[fastrand::usize(..ALL.len())]);
    }
    fastrand::shuffle(&mut out);
    String::from_utf8(out).unwrap_or_else(|_| "a1fallback".to_owned())
}

pub(super) fn user_count(state: &Path) -> io::Result<i64> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)
}

pub(super) fn create_user(state: &Path, username: &str, password: &str) -> io::Result<String> {
    validate_password_strength(password)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)?;
    if count > 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a user already exists",
        ));
    }
    let secret = random_secret_hex()?;
    let password_hash = hash_password(secret.as_bytes(), password);
    conn.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage) VALUES(?1, ?2, ?3, '{}')",
        params![username, password_hash, secret],
    )
    .map_err(sqlite_io_error)?;
    let user = load_user_by_username(state, username)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "created user could not be loaded")
    })?;
    signed_token(&user)
}

pub(super) fn issue_token(state: &Path, username: &str, password: &str) -> io::Result<String> {
    let Some(user) = load_user_by_username(state, username)? else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    };
    let hashed = hash_password(user.jwt_secret.as_bytes(), password);
    if hashed != user.password_hash {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    }
    signed_token(&user)
}

pub(super) fn authenticate_request(app: &AppState, request: &HttpRequest) -> Option<UserRecord> {
    let token = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            if request.method == "GET"
                && (request.path == "/api/events/runtime" || request.path == "/api/events/logs")
            {
                request
                    .query
                    .get("access_token")
                    .and_then(|values| values.first())
                    .map(String::as_str)
            } else {
                None
            }
        })?;
    verify_token(&app.state, token).ok().flatten()
}
