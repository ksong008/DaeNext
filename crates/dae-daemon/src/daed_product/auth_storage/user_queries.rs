use super::*;

#[cfg(test)]
thread_local! {
    static USER_QUERY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_user_query_count_for_current_thread() {
    USER_QUERY_COUNT.set(0);
}

#[cfg(test)]
pub(crate) fn user_query_count_for_current_thread() -> usize {
    USER_QUERY_COUNT.get()
}

pub(crate) fn load_user_by_username(
    state: &Path,
    username: &str,
) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    load_user_by_username_without_schema_check(state, username)
}

pub(crate) fn load_user_by_username_without_schema_check(
    state: &Path,
    username: &str,
) -> io::Result<Option<UserRecord>> {
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE username = ?1",
        params![username],
    )
}

#[cfg(test)]
pub(crate) fn load_user_by_id(state: &Path, id: i64) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE id = ?1",
        params![id],
    )
}

pub(crate) fn query_user<P>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> io::Result<Option<UserRecord>>
where
    P: rusqlite::Params,
{
    #[cfg(test)]
    USER_QUERY_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    conn.query_row(sql, params, |row| {
        Ok(UserRecord {
            id: row.get(0)?,
            username: row.get(1)?,
            password_hash: row.get(2)?,
            jwt_secret: row.get(3)?,
            json_storage: row
                .get::<_, Option<String>>(4)?
                .unwrap_or_else(|| "{}".to_owned()),
            avatar: row.get(5)?,
            name: row.get(6)?,
        })
    })
    .optional()
    .map_err(sqlite_io_error)
}

pub(crate) fn user_resource(user: &UserRecord) -> Value {
    let mut map = Map::new();
    map.insert("username".to_owned(), json!(user.username));
    if let Some(name) = &user.name {
        map.insert("name".to_owned(), json!(name));
    }
    if let Some(avatar) = &user.avatar {
        map.insert("avatar".to_owned(), json!(avatar));
    }
    Value::Object(map)
}
