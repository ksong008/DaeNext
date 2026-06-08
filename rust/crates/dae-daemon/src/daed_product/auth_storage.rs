fn load_user_by_username(state: &Path, username: &str) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE username = ?1",
        params![username],
    )
}

fn load_user_by_id(state: &Path, id: i64) -> io::Result<Option<UserRecord>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    query_user(
        &conn,
        "SELECT id, username, password_hash, jwt_secret, json_storage, avatar, name FROM users WHERE id = ?1",
        params![id],
    )
}

fn query_user<P>(conn: &Connection, sql: &str, params: P) -> io::Result<Option<UserRecord>>
where
    P: rusqlite::Params,
{
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

fn user_resource(user: &UserRecord) -> Value {
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

fn ensure_default_resources(state: &Path, body: &Value) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config_name = body
        .get("configName")
        .and_then(Value::as_str)
        .unwrap_or("global");
    let dns_name = body
        .get("dnsName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let routing_name = body
        .get("routingName")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let group_name = body
        .get("groupName")
        .and_then(Value::as_str)
        .unwrap_or("proxy");
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or("random");
    let mode = body.get("mode").and_then(Value::as_str).unwrap_or("rule");
    let global = body
        .get("global")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| body.get("global").map(Value::to_string))
        .unwrap_or_else(|| "global {}".to_owned());
    let dns = body
        .get("dns")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let routing = body
        .get("routing")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let config = upsert_named_resource(
        &conn,
        "configs",
        "global",
        config_name,
        &global,
        "selected, version",
        "0, 0",
    )?;
    let dns = upsert_named_resource(
        &conn,
        "dns",
        "dns",
        dns_name,
        &dns,
        "selected, version",
        "0, 0",
    )?;
    let routing = upsert_named_resource(
        &conn,
        "routings",
        "routing",
        routing_name,
        &routing,
        "selected, version",
        "0, 0",
    )?;
    let group = upsert_group(&conn, group_name, policy)?;
    let group_id = group.id;
    let mut group_changed = false;
    if group.created {
        if let Some(params_value) = body.get("policyParams").and_then(Value::as_array) {
            let desired = desired_policy_params(params_value);
            if group_policy_param_pairs(&conn, group_id)? != desired {
                conn.execute(
                    "DELETE FROM group_policy_params WHERE group_id = ?1",
                    params![group_id],
                )
                .map_err(sqlite_io_error)?;
                for (key, value) in &desired {
                    conn.execute(
                        "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                        params![key, value, group_id],
                    )
                    .map_err(sqlite_io_error)?;
                }
                group_changed = true;
            }
        }
        if body.get("nodeIds").is_some() {
            let desired = integer_array(body, "nodeIds")
                .into_iter()
                .collect::<BTreeSet<_>>();
            if group_node_id_set(&conn, group_id)? != desired {
                conn.execute(
                    "DELETE FROM group_nodes WHERE group_id = ?1",
                    params![group_id],
                )
                .map_err(sqlite_io_error)?;
                let desired_ids = desired.iter().copied().collect::<Vec<_>>();
                apply_group_node_ids(&conn, group_id, &desired_ids, true)?;
                group_changed = true;
            }
        }
        if body.get("subscriptionIds").is_some() {
            let ids = integer_array(body, "subscriptionIds");
            let name_filter_regex = body
                .get("nameFilterRegex")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let desired = ids
                .iter()
                .map(|id| (*id, name_filter_regex.clone()))
                .collect::<BTreeSet<_>>();
            if group_subscription_binding_set(&conn, group_id)? != desired {
                conn.execute(
                    "DELETE FROM group_subscriptions WHERE group_id = ?1",
                    params![group_id],
                )
                .map_err(sqlite_io_error)?;
                apply_group_subscription_ids(
                    &conn,
                    group_id,
                    &ids,
                    name_filter_regex.as_deref(),
                    true,
                )?;
                group_changed = true;
            }
        }
    }
    if group_changed {
        conn.execute(
            "UPDATE groups SET version = version + 1 WHERE id = ?1",
            params![group_id],
        )
        .map_err(sqlite_io_error)?;
    }
    Ok(json!({
        "defaultConfigID": config.id.to_string(),
        "defaultRoutingID": routing.id.to_string(),
        "defaultDNSID": dns.id.to_string(),
        "defaultGroupID": group_id.to_string(),
        "mode": mode,
    }))
}

fn desired_policy_params(items: &[Value]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|item| {
            let key = item
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            (key, value)
        })
        .collect()
}

fn group_policy_param_pairs(conn: &Connection, group_id: i64) -> io::Result<Vec<(String, String)>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM group_policy_params WHERE group_id = ?1 ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

fn group_node_id_set(conn: &Connection, group_id: i64) -> io::Result<BTreeSet<i64>> {
    let mut stmt = conn
        .prepare("SELECT node_id FROM group_nodes WHERE group_id = ?1")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut out = BTreeSet::new();
    for row in rows {
        out.insert(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

fn group_subscription_binding_set(
    conn: &Connection,
    group_id: i64,
) -> io::Result<BTreeSet<(i64, Option<String>)>> {
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, name_filter_regex FROM group_subscriptions WHERE group_id = ?1",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty()),
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = BTreeSet::new();
    for row in rows {
        out.insert(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

struct EnsuredResource {
    id: i64,
    created: bool,
}

fn upsert_named_resource(
    conn: &Connection,
    table: &str,
    value_column: &str,
    name: &str,
    value: &str,
    extra_columns: &str,
    extra_values: &str,
) -> io::Result<EnsuredResource> {
    let select_sql = format!("SELECT id FROM {table} WHERE name = ?1 LIMIT 1");
    if let Some(id) = conn
        .query_row(&select_sql, params![name], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)?
    {
        return Ok(EnsuredResource { id, created: false });
    }
    let insert_sql = format!(
        "INSERT INTO {table}(name, {value_column}, {extra_columns}) VALUES(?1, ?2, {extra_values})"
    );
    conn.execute(&insert_sql, params![name, value])
        .map_err(sqlite_io_error)?;
    Ok(EnsuredResource {
        id: conn.last_insert_rowid(),
        created: true,
    })
}

fn upsert_group(conn: &Connection, name: &str, policy: &str) -> io::Result<EnsuredResource> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM groups WHERE name = ?1 LIMIT 1",
            params![name],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
    {
        return Ok(EnsuredResource { id, created: false });
    }
    conn.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    )
    .map_err(sqlite_io_error)?;
    Ok(EnsuredResource {
        id: conn.last_insert_rowid(),
        created: true,
    })
}

fn signed_token(user: &UserRecord) -> io::Result<String> {
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

fn verify_token(state: &Path, token: &str) -> io::Result<Option<UserRecord>> {
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
    if parts.next().is_some() {
        return Ok(None);
    }
    let header_value = decode_jwt_part(header)?;
    if header_value.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Ok(None);
    }
    let payload_value = decode_jwt_part(payload)?;
    let Some(username) = payload_value.get("sub").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some(user) = load_user_by_username(state, username)? else {
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
    load_user_by_id(state, user.id)
}

fn decode_jwt_part(part: &str) -> io::Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn hash_password(salt: &[u8], password: &str) -> String {
    let mut h = Shake256::default();
    h.update(salt);
    h.update(password.as_bytes());
    let mut reader = h.finalize_xof();
    let mut hash = [0_u8; 32];
    XofReader::read(&mut reader, &mut hash);
    hex_encode(&hash)
}

fn validate_password_strength(password: &str) -> Result<(), String> {
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

fn random_secret_hex() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

fn query_json_storage(storage: &str, paths: &[String]) -> Vec<String> {
    if paths.is_empty() {
        return vec![storage.to_owned()];
    }
    let root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    paths
        .iter()
        .map(|path| {
            value_at_path(&root, path)
                .map(value_to_storage_string)
                .unwrap_or_default()
        })
        .collect()
}

fn set_json_storage(
    storage: &mut String,
    paths: &[String],
    values: &[String],
) -> Result<i32, String> {
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    if !root.is_object() {
        root = json!({});
    }
    for (path, value) in paths.iter().zip(values.iter()) {
        set_value_at_path(&mut root, path, Value::String(value.clone()))?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

fn remove_json_storage(storage: &mut String, paths: &[String]) -> Result<i32, String> {
    if paths.is_empty() {
        *storage = "{}".to_owned();
        return Ok(1);
    }
    let mut root = serde_json::from_str::<Value>(storage).unwrap_or_else(|_| json!({}));
    for path in paths {
        delete_value_at_path(&mut root, path)?;
    }
    *storage = root.to_string();
    Ok(paths.len() as i32)
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        current = current.get(segment)?;
    }
    Some(current)
}

fn set_value_at_path(root: &mut Value, path: &str, value: Value) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        if !current.is_object() {
            *current = json!({});
        }
        let object = current.as_object_mut().unwrap();
        current = object
            .entry((*segment).to_owned())
            .or_insert_with(|| json!({}));
    }
    if !current.is_object() {
        *current = json!({});
    }
    current
        .as_object_mut()
        .unwrap()
        .insert(segments[segments.len() - 1].to_owned(), value);
    Ok(())
}

fn delete_value_at_path(root: &mut Value, path: &str) -> Result<(), String> {
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err("storage path must not be empty".to_owned());
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let Some(next) = current.get_mut(*segment) else {
            return Ok(());
        };
        current = next;
    }
    if let Some(object) = current.as_object_mut() {
        object.remove(segments[segments.len() - 1]);
    }
    Ok(())
}

fn value_to_storage_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn save_json_storage(state: &Path, user_id: i64, storage: &str) -> io::Result<()> {
    let conn = open_state_connection(state)?;
    conn.execute(
        "UPDATE users SET json_storage = ?1 WHERE id = ?2",
        params![storage, user_id],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}
