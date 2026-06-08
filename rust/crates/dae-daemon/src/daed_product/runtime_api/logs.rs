use super::*;

pub(in crate::daed_product) fn api_logs(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let level = match log_level_filter_from_request(request) {
        Ok(level) => level,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let query = request
        .query
        .get("q")
        .and_then(|values| values.first())
        .filter(|value| !value.is_empty())
        .cloned();
    let limit = request
        .query
        .get("limit")
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|limit| *limit > 0)
        .unwrap_or(DEFAULT_LOG_QUERY_LIMIT);
    match list_logs_value(
        &app.config_dir,
        &app.state,
        level.as_deref(),
        query.as_deref(),
        limit,
    ) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn log_level_filter_from_request(
    request: &HttpRequest,
) -> Result<Option<String>, String> {
    let level = request
        .query
        .get("level")
        .and_then(|values| values.first())
        .map(String::as_str);
    normalize_log_level_filter(level).map_err(|err| err.to_string())
}

pub(in crate::daed_product) fn api_clear_logs(app: &AppState) -> HttpResponse {
    match clear_log_file(&app.config_dir).and_then(|()| app.runtime.clear_resident_event_log()) {
        Ok(()) => HttpResponse::json(200, json!({"cleared": true})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_get_log_settings(app: &AppState) -> HttpResponse {
    match log_settings_value(&app.state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_set_log_settings(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match open_state_connection(&app.state).and_then(|conn| {
        let (current_entries, current_bytes) = log_settings_tuple(&conn)?;
        let max_entries = normalize_log_max_entries(
            body.get("maxEntries")
                .and_then(Value::as_i64)
                .unwrap_or(current_entries),
        );
        let max_bytes = normalize_log_max_bytes(
            body.get("maxBytes")
                .and_then(Value::as_i64)
                .unwrap_or(current_bytes),
        );
        conn.execute(
            "INSERT OR REPLACE INTO log_settings(id, max_entries, max_bytes) VALUES(1, ?1, ?2)",
            params![max_entries, max_bytes],
        )
        .map_err(sqlite_io_error)?;
        drop(conn);
        refresh_log_policy_and_apply_log_limits(&app.config_dir, &app.state, Some(&app.runtime))?;
        Ok(())
    }) {
        Ok(()) => match log_settings_value(&app.state) {
            Ok(value) => HttpResponse::json(200, value),
            Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
        },
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}
