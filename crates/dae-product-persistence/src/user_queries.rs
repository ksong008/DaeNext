use crate::{ProductUserRecord, ensure_state_schema, open_state_connection, sqlite_io_error};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use std::io;
use std::path::Path;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static USER_QUERY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_user_query_count_for_current_thread() {
    USER_QUERY_COUNT.set(0);
}

#[cfg(any(test, feature = "test-support"))]
pub fn user_query_count_for_current_thread() -> usize {
    USER_QUERY_COUNT.get()
}

pub fn load_user_by_username(
    state: &Path,
    username: &str,
) -> io::Result<Option<ProductUserRecord>> {
    ensure_state_schema(state)?;
    load_user_by_username_without_schema_check(state, username)
}

pub fn load_user_by_username_without_schema_check(
    state: &Path,
    username: &str,
) -> io::Result<Option<ProductUserRecord>> {
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE username = ?1",
        params![username],
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn load_user_by_id(state: &Path, id: i64) -> io::Result<Option<ProductUserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE id = ?1",
        params![id],
    )
}

pub fn query_user<P>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> io::Result<Option<ProductUserRecord>>
where
    P: rusqlite::Params,
{
    #[cfg(any(test, feature = "test-support"))]
    USER_QUERY_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    conn.query_row(sql, params, |row| {
        Ok(ProductUserRecord::new(
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get::<_, Option<String>>(4)?
                .unwrap_or_else(|| "{}".to_owned()),
            row.get(5)?,
            row.get(6)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

pub fn user_resource(user: &ProductUserRecord) -> Value {
    let mut map = Map::new();
    map.insert("username".to_owned(), json!(user.username()));
    if let Some(name) = user.name() {
        map.insert("name".to_owned(), json!(name));
    }
    if let Some(avatar) = user.avatar() {
        map.insert("avatar".to_owned(), json!(avatar));
    }
    Value::Object(map)
}
