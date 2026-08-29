use std::fs;
use std::io;
use std::path::Path;

use dae_product_core::path_string;
use dae_product_persistence::{
    ProductUserRecord, ensure_state_schema, load_user_by_username, open_state_connection,
    sqlite_io_error,
};
use rusqlite::{TransactionBehavior, params};
use serde_json::{Value, json};

use crate::auth_crypto::{
    hash_password, password_hash_needs_migration, random_secret_hex, secure_random_index,
    signed_token, validate_password_strength, verify_password_hash,
};

pub fn reset_all_user_passwords(state: &Path) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let materials = {
        let mut stmt = tx
            .prepare("SELECT id, username FROM users ORDER BY id")
            .map_err(sqlite_io_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_io_error)?;
        let mut materials = Vec::new();
        for row in rows {
            let (id, username) = row.map_err(sqlite_io_error)?;
            let password = random_recovery_password()?;
            let secret = random_secret_hex()?;
            let password_hash = hash_password(secret.as_bytes(), &password);
            materials.push((id, username, password_hash, secret, password));
        }
        materials
    };
    let mut users = Vec::new();
    for (id, username, password_hash, secret, password) in materials {
        tx.execute(
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
    tx.commit().map_err(sqlite_io_error)?;
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "rustDaedWritesWingDbByDefault": false,
        "users": users,
    }))
}

pub fn random_recovery_password() -> io::Result<String> {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const ALL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = fs::File::open("/dev/urandom")?;
    let mut output = Vec::with_capacity(12);
    output.push(LETTERS[secure_random_index(&mut rng, LETTERS.len())?]);
    output.push(DIGITS[secure_random_index(&mut rng, DIGITS.len())?]);
    for _ in 2..12 {
        output.push(ALL[secure_random_index(&mut rng, ALL.len())?]);
    }
    for index in (1..output.len()).rev() {
        let swap = secure_random_index(&mut rng, index + 1)?;
        output.swap(index, swap);
    }
    String::from_utf8(output).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn user_count(state: &Path) -> io::Result<i64> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)
}

pub fn create_user(state: &Path, username: &str, password: &str) -> io::Result<String> {
    create_user_with_crypto(
        state,
        username,
        password,
        hash_password,
        random_secret_hex,
        signed_token,
    )
}

pub fn create_user_with_crypto<Hash, Secret, Sign>(
    state: &Path,
    username: &str,
    password: &str,
    hash: Hash,
    random_secret: Secret,
    sign: Sign,
) -> io::Result<String>
where
    Hash: Fn(&[u8], &str) -> String,
    Secret: Fn() -> io::Result<String>,
    Sign: Fn(&ProductUserRecord) -> io::Result<String>,
{
    validate_password_strength(password)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
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
    drop(conn);
    let secret = random_secret()?;
    let password_hash = hash(secret.as_bytes(), password);
    let mut conn = open_state_connection(state)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_io_error)?;
    let count: i64 = tx
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)?;
    if count > 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a user already exists",
        ));
    }
    tx.execute(
        "INSERT INTO users(username, password_hash, jwt_secret, json_storage) VALUES(?1, ?2, ?3, '{}')",
        params![username, password_hash, secret],
    )
    .map_err(sqlite_io_error)?;
    let user = ProductUserRecord::new(
        tx.last_insert_rowid(),
        username.to_owned(),
        password_hash,
        secret,
        "{}".to_owned(),
        None,
        None,
    );
    tx.commit().map_err(sqlite_io_error)?;
    sign(&user)
}

pub fn issue_token(state: &Path, username: &str, password: &str) -> io::Result<String> {
    issue_token_with_crypto(
        state,
        username,
        password,
        verify_password_hash,
        hash_password,
        signed_token,
    )
}

pub fn issue_token_with_crypto<Verify, Hash, Sign>(
    state: &Path,
    username: &str,
    password: &str,
    verify: Verify,
    hash: Hash,
    sign: Sign,
) -> io::Result<String>
where
    Verify: Fn(&str, &[u8], &str) -> bool,
    Hash: Fn(&[u8], &str) -> String,
    Sign: Fn(&ProductUserRecord) -> io::Result<String>,
{
    let Some(mut user) = load_user_by_username(state, username)? else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    };
    if !verify(user.password_hash(), user.jwt_secret().as_bytes(), password) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "incorrect username or password",
        ));
    }
    if password_hash_needs_migration(user.password_hash()) {
        let migrated_hash = hash(user.jwt_secret().as_bytes(), password);
        let conn = open_state_connection(state)?;
        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2 AND password_hash = ?3",
            params![migrated_hash, user.id(), user.password_hash()],
        )
        .map_err(sqlite_io_error)?;
        user.set_password_hash(migrated_hash);
    }
    sign(&user)
}
