fn list_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let expand_nodes = request
        .query
        .get("expand")
        .map(|values| values.iter().any(|value| value == "nodes"))
        .unwrap_or(false);
    match list_subscriptions_value(state, expand_nodes) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn list_subscriptions_value(state: &Path, expand_nodes: bool) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare("SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let mut value = row.map_err(sqlite_io_error)?;
        let id = value["id"].as_i64().unwrap_or(0);
        let node_count = count_nodes_for_subscription(&conn, id)?;
        if let Value::Object(map) = &mut value {
            map.insert("nodeCount".to_owned(), json!(node_count));
            if expand_nodes {
                map.insert("nodes".to_owned(), list_nodes_value(state, Some(id))?);
            }
        }
        items.push(value);
    }
    Ok(json!({"items": items}))
}

fn create_subscription(state: &Path, config_dir: &Path, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let link = body.get("link").and_then(Value::as_str).unwrap_or("");
    if link.is_empty() {
        return HttpResponse::json(400, json!({"error": "link is required"}));
    }
    let tag = body.get("tag").and_then(Value::as_str);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let now = now_text();
    if let Err(err) = conn.execute(
        "INSERT INTO subscriptions(updated_at, link, cron_exp, cron_enable, status, info, tag) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![now, link, body.get("cronExp").and_then(Value::as_str).unwrap_or("10 */6 * * *"), body.get("cronEnable").and_then(Value::as_bool).unwrap_or(true) as i64, "imported", "", tag],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    let id = conn.last_insert_rowid();
    let _ = append_log_for_config(
        config_dir,
        state,
        "info",
        &format!("subscription {id} imported"),
    );
    let import_report = refresh_subscription_from_remote(state, id).unwrap_or_else(|err| {
        json!({
            "link": link,
            "nodeImportResult": [{
                "link": link,
                "error": err.to_string(),
                "node": Value::Null
            }]
        })
    });
    HttpResponse::json(
        201,
        json!({
            "link": link,
            "subscription": {"id": id},
            "nodeImportResult": import_report["nodeImportResult"].clone()
        }),
    )
}

fn get_subscription(state: &Path, id: i64) -> HttpResponse {
    match get_subscription_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "subscription not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn get_subscription_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag FROM subscriptions WHERE id = ?1",
        params![id],
        subscription_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn update_subscription(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let link = body.get("link").and_then(Value::as_str);
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    let cron_exp = body.get("cronExp").and_then(Value::as_str);
    let cron_enable = body
        .get("cronEnable")
        .and_then(Value::as_bool)
        .map(|value| value as i64);
    if let Err(err) = conn.execute(
        "UPDATE subscriptions
         SET link = COALESCE(?1, link),
             tag = CASE WHEN ?2 THEN ?3 ELSE tag END,
             cron_exp = COALESCE(?4, cron_exp),
             cron_enable = COALESCE(?5, cron_enable),
             updated_at = ?6
         WHERE id = ?7",
        params![
            link,
            tag_present,
            tag,
            cron_exp,
            cron_enable,
            now_text(),
            id
        ],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    get_subscription(state, id)
}

fn refresh_subscription(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    id: i64,
) -> HttpResponse {
    match refresh_subscription_from_remote(state, id) {
        Ok(mut report) => {
            let _ = append_log_for_config(
                config_dir,
                state,
                "info",
                &format!("subscription {id} refreshed"),
            );
            match reload_runtime_after_subscription_refresh(state, config_dir, runtime) {
                Ok(Some(reload_report)) => {
                    if let Value::Object(map) = &mut report {
                        map.insert("runtimeReloaded".to_owned(), json!(true));
                        map.insert("runtimeReload".to_owned(), reload_report);
                    }
                }
                Ok(None) => {
                    if let Value::Object(map) = &mut report {
                        map.insert("runtimeReloaded".to_owned(), json!(false));
                    }
                }
                Err(err) => return HttpResponse::json(500, json!({"error": err})),
            }
            if let Some(subscription) = get_subscription_value(state, id)
                .ok()
                .flatten()
                .and_then(|value| value.as_object().cloned())
            {
                if let Value::Object(map) = &mut report {
                    for (key, value) in subscription {
                        map.insert(key, value);
                    }
                }
            }
            HttpResponse::json(200, report)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            HttpResponse::json(404, json!({"error": err.to_string()}))
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn reload_runtime_after_subscription_refresh(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
) -> Result<Option<Value>, String> {
    if !should_restore_runtime_on_start(state).map_err(|err| err.to_string())? {
        return Ok(None);
    }
    let conn = open_state_connection(state).map_err(|err| err.to_string())?;
    if !runtime_modified(&conn, true).map_err(|err| err.to_string())? {
        return Ok(None);
    }
    drop(conn);

    let reload_started_at = Instant::now();
    match restore_runtime_from_state(
        runtime,
        state,
        Some(config_dir),
        ProductRuntimeLifecycleLogMode::ReloadSubscriptionRefresh,
    ) {
        Ok(report) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "subscription-refresh".to_owned());
            fields.insert("applied".to_owned(), "true".to_owned());
            fields.insert(
                "elapsed".to_owned(),
                format!("{:?}", reload_started_at.elapsed()),
            );
            let _ = append_lifecycle_log_fields_for_config(
                config_dir,
                state,
                "info",
                "[Reload] Finished",
                fields,
            );
            Ok(Some(report))
        }
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "subscription-refresh".to_owned());
            fields.insert("error".to_owned(), err.clone());
            let _ = append_lifecycle_log_fields_for_config(
                config_dir,
                state,
                "error",
                "[Reload] Failed to reload",
                fields,
            );
            Err(format!(
                "failed to reload runtime after subscription refresh: {err}"
            ))
        }
    }
}

fn delete_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let mut removed = 0_usize;
    for id in ids {
        if let Ok(value) = delete_subscription(state, id) {
            removed += value;
        }
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

fn delete_subscription_by_id(state: &Path, id: i64) -> HttpResponse {
    match delete_subscription(state, id) {
        Ok(removed) => HttpResponse::json(200, json!({"removed": removed})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn delete_subscription(state: &Path, id: i64) -> io::Result<usize> {
    let conn = open_state_connection(state)?;
    conn.execute(
        "DELETE FROM group_subscriptions WHERE subscription_id = ?1",
        params![id],
    )
    .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM nodes WHERE subscription_id = ?1", params![id])
        .map_err(sqlite_io_error)?;
    conn.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])
        .map_err(sqlite_io_error)
}

fn subscription_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "updatedAt": row.get::<_, String>(1)?,
        "link": row.get::<_, String>(2)?,
        "cronExp": row.get::<_, Option<String>>(3)?.unwrap_or_else(|| "10 */6 * * *".to_owned()),
        "cronEnable": row.get::<_, i64>(4)? != 0,
        "status": row.get::<_, String>(5)?,
        "info": row.get::<_, String>(6)?,
        "tag": row.get::<_, Option<String>>(7)?,
    }))
}

fn count_nodes_for_subscription(conn: &Connection, subscription_id: i64) -> io::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM nodes WHERE subscription_id = ?1",
        params![subscription_id],
        |row| row.get(0),
    )
    .map_err(sqlite_io_error)
}
