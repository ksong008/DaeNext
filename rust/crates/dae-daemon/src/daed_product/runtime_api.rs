fn api_runtime_reload(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let reload_started_at = Instant::now();
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let dry = body.get("dry").and_then(Value::as_bool).unwrap_or(false);
    let preview = match materialize_runtime(&app.state, Some(&app.config_dir), true) {
        Ok(report) => report,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), dry.to_string());
            fields.insert("error".to_owned(), err.to_string());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to materialize runtime preview",
                fields,
            );
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
    };
    let content = match preview.get("content").and_then(Value::as_str) {
        Some(content) => content,
        None => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), dry.to_string());
            fields.insert(
                "error".to_owned(),
                "runtime materializer did not return content".to_owned(),
            );
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to materialize runtime preview",
                fields,
            );
            return HttpResponse::json(
                500,
                json!({"error": "runtime materializer did not return content"}),
            );
        }
    };
    let config = match build_runtime_config_from_content(content) {
        Ok(config) => config,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), dry.to_string());
            fields.insert("error".to_owned(), err.clone());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to build runtime config",
                fields,
            );
            return HttpResponse::json(400, json!({"error": err}));
        }
    };
    if dry {
        let mut fields = BTreeMap::new();
        fields.insert("source".to_owned(), "api".to_owned());
        fields.insert("dry".to_owned(), "true".to_owned());
        fields.insert("applied".to_owned(), "false".to_owned());
        fields.insert(
            "elapsed".to_owned(),
            format!("{:?}", reload_started_at.elapsed()),
        );
        let _ = append_lifecycle_log_fields_for_config(
            &app.config_dir,
            &app.state,
            "info",
            "[Reload] Preview finished",
            fields,
        );
        let mut response = preview.as_object().cloned().unwrap_or_default();
        response.insert("applied".to_owned(), json!(0));
        response.insert("dry".to_owned(), json!(true));
        response.insert("runtimeStarted".to_owned(), json!(false));
        return HttpResponse::json(200, Value::Object(response));
    }
    if let Err(err) = set_runtime_log_level_from_config(&app.state, &config) {
        let mut fields = BTreeMap::new();
        fields.insert("source".to_owned(), "api".to_owned());
        fields.insert("dry".to_owned(), "false".to_owned());
        fields.insert("error".to_owned(), err.to_string());
        let _ = append_lifecycle_log_fields_for_config(
            &app.config_dir,
            &app.state,
            "error",
            "[Reload] Failed to apply runtime log level",
            fields,
        );
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    let runtime = match app.runtime.reload(config, "api-runtime-reload") {
        Ok(outcome) => outcome.report,
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), "false".to_owned());
            fields.insert("error".to_owned(), err.clone());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to reload",
                fields,
            );
            return HttpResponse::json(500, json!({"error": err}));
        }
    };
    let mut fields = BTreeMap::new();
    fields.insert("source".to_owned(), "api".to_owned());
    fields.insert("dry".to_owned(), "false".to_owned());
    fields.insert("applied".to_owned(), "true".to_owned());
    fields.insert(
        "elapsed".to_owned(),
        format!("{:?}", reload_started_at.elapsed()),
    );
    match materialize_runtime(&app.state, Some(&app.config_dir), false) {
        Ok(report) => {
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "info",
                "[Reload] Finished",
                fields,
            );
            let mut response = report.as_object().cloned().unwrap_or_default();
            response.insert("applied".to_owned(), json!(1));
            response.insert("dry".to_owned(), json!(false));
            response.insert("runtimeStarted".to_owned(), json!(true));
            response.insert("runtime".to_owned(), runtime);
            HttpResponse::json(200, Value::Object(response))
        }
        Err(err) => {
            let _ = app.runtime.stop();
            let _ = mark_system_stopped(&app.state);
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), "false".to_owned());
            fields.insert("error".to_owned(), err.to_string());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to materialize applied runtime config",
                fields,
            );
            HttpResponse::json(500, json!({"error": err.to_string()}))
        }
    }
}

fn api_runtime_stop(app: &AppState) -> HttpResponse {
    match app.runtime.stop() {
        Ok(mut report) => {
            if let Err(err) = mark_system_stopped(&app.state) {
                return HttpResponse::json(500, json!({"error": err.to_string()}));
            }
            let _ = append_lifecycle_log_for_config(
                &app.config_dir,
                &app.state,
                "info",
                "[Stop] runtime stopped by Rust daed",
            );
            if let Value::Object(map) = &mut report {
                map.insert("runtime".to_owned(), app.runtime.summary());
            }
            HttpResponse::json(200, report)
        }
        Err(err) => HttpResponse::json(500, json!({"error": err})),
    }
}

fn api_get_runtime_log_level(app: &AppState) -> HttpResponse {
    let level = get_metadata(&app.state, "runtime_log_level")
        .unwrap_or_else(|_| Some("info".to_owned()))
        .unwrap_or_else(|| "info".to_owned());
    let level = normalize_runtime_log_level(&level).unwrap_or_else(|| "info".to_owned());
    HttpResponse::json(200, json!({"level": level}))
}

fn api_set_runtime_log_level(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let Some(level) =
        normalize_runtime_log_level(body.get("level").and_then(Value::as_str).unwrap_or("info"))
    else {
        return HttpResponse::json(400, json!({"error": "invalid log level"}));
    };
    if let Err(err) = set_metadata(&app.state, "runtime_log_level", &level) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"level": level}))
}

fn normalize_runtime_log_level(level: &str) -> Option<String> {
    normalize_log_level_name(level)
}

fn api_runtime_events(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let full = runtime_overview_report(app, request);
    thread::sleep(Duration::from_millis(200));
    let delta = runtime_overview_delta_report(app, request);
    sse_response_events(
        &[
            ("runtime.overview", full),
            ("runtime.overview.delta", delta),
        ],
        Some(LOG_STREAM_RETRY_MS),
    )
}

fn stream_runtime_events(
    stream: &mut TcpStream,
    app: &AppState,
    request: &HttpRequest,
) -> io::Result<()> {
    write_sse_stream_headers(stream)?;
    write!(stream, "retry: {LOG_STREAM_RETRY_MS}\n\n")?;
    let first = runtime_overview_report(app, request);
    let mut last_reload_count = first
        .pointer("/runtime/reloadCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    write_sse_stream_event(stream, "runtime.overview", &first)?;
    let mut last_heartbeat = Instant::now();
    loop {
        thread::sleep(Duration::from_secs(1));
        let delta = runtime_overview_delta_report(app, request);
        let reload_count = delta["reloadCount"].as_u64().unwrap_or(last_reload_count);
        if reload_count != last_reload_count {
            let full = runtime_overview_report(app, request);
            last_reload_count = full
                .pointer("/runtime/reloadCount")
                .and_then(Value::as_u64)
                .unwrap_or(reload_count);
            write_sse_stream_event(stream, "runtime.overview", &full)?;
        } else {
            write_sse_stream_event(stream, "runtime.overview.delta", &delta)?;
        }
        if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
            stream.write_all(b": keep-alive\n\n")?;
            stream.flush()?;
            last_heartbeat = Instant::now();
        }
    }
}

fn api_log_events(_app: &AppState, request: &HttpRequest) -> HttpResponse {
    match log_level_filter_from_request(request) {
        Ok(_) => sse_response_events(&[], Some(LOG_STREAM_RETRY_MS)),
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    }
}

fn stream_log_events(
    stream: &mut TcpStream,
    app: &AppState,
    request: &HttpRequest,
) -> io::Result<()> {
    let level = match log_level_filter_from_request(request) {
        Ok(level) => level,
        Err(err) => {
            let response = HttpResponse::json(400, json!({"error": err}));
            return write_http_response(stream, &response, false);
        }
    };
    let query = request
        .query
        .get("q")
        .and_then(|values| values.first())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    write_sse_stream_headers(stream)?;
    write!(stream, "retry: {LOG_STREAM_RETRY_MS}\n\n")?;
    stream.flush()?;

    let log_file = product_log_file(&app.config_dir);
    let mut last_seen_id = cached_last_log_id(&log_file).unwrap_or(0);
    let mut last_heartbeat = Instant::now();
    loop {
        let current_last_id = cached_last_log_id(&log_file).unwrap_or(0);
        if current_last_id < last_seen_id {
            last_seen_id = 0;
        }
        if current_last_id == last_seen_id {
            if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
                stream.write_all(b": heartbeat\n\n")?;
                stream.flush()?;
                last_heartbeat = Instant::now();
            }
            thread::sleep(LOG_STREAM_POLL_INTERVAL);
            continue;
        }
        let (entries, max_seen_id) =
            scan_log_entries_after_id(&app.config_dir, last_seen_id).unwrap_or_default();
        for entry in entries {
            if log_entry_matches_filter(&entry, level.as_deref(), query.as_deref()) {
                write_sse_stream_event(stream, "log.entry", &log_entry_value(entry))?;
            }
        }
        if max_seen_id > last_seen_id {
            last_seen_id = max_seen_id;
        }
        if last_heartbeat.elapsed() >= LOG_STREAM_HEARTBEAT_INTERVAL {
            stream.write_all(b": heartbeat\n\n")?;
            stream.flush()?;
            last_heartbeat = Instant::now();
        }
        thread::sleep(LOG_STREAM_POLL_INTERVAL);
    }
}

fn api_logs(app: &AppState, request: &HttpRequest) -> HttpResponse {
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

fn log_level_filter_from_request(request: &HttpRequest) -> Result<Option<String>, String> {
    let level = request
        .query
        .get("level")
        .and_then(|values| values.first())
        .map(String::as_str);
    normalize_log_level_filter(level).map_err(|err| err.to_string())
}

fn api_clear_logs(app: &AppState) -> HttpResponse {
    match clear_log_file(&app.config_dir) {
        Ok(()) => HttpResponse::json(200, json!({"cleared": true})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_log_settings(app: &AppState) -> HttpResponse {
    match log_settings_value(&app.state) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_set_log_settings(app: &AppState, request: &HttpRequest) -> HttpResponse {
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
        prune_log_file(&app.config_dir, &conn)?;
        Ok(())
    }) {
        Ok(()) => match log_settings_value(&app.state) {
            Ok(value) => HttpResponse::json(200, value),
            Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
        },
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_node_latencies(app: &AppState) -> HttpResponse {
    match list_node_latencies_value(&app.state, &app.runtime) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_test_node_latencies(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    match update_node_latencies(&app.state, &app.config_dir, &app.runtime, &ids) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_get_bundle(app: &AppState, user: &UserRecord) -> HttpResponse {
    match export_bundle(&app.state, user) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_put_bundle(app: &AppState, request: &HttpRequest, user: &UserRecord) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match import_bundle(&app.state, &app.config_dir, &body, user) {
        Ok(imported) => HttpResponse::json(200, json!({"imported": imported})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_get_dae_config_file(app: &AppState) -> HttpResponse {
    match materialize_runtime(&app.state, None, true) {
        Ok(report) => HttpResponse::json(
            200,
            json!({
                "filename": "generated.dae",
                "content": report["content"].as_str().unwrap_or(""),
                "generated": true
            }),
        ),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn api_put_dae_config_file(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let content = body.get("content").and_then(Value::as_str).unwrap_or("");
    let name_prefix = body
        .get("namePrefix")
        .and_then(Value::as_str)
        .unwrap_or("imported");
    let import_body = json!({
        "configName": format!("{name_prefix}-global"),
        "global": content,
        "dnsName": format!("{name_prefix}-dns"),
        "dns": "",
        "routingName": format!("{name_prefix}-routing"),
        "routing": "",
        "groupName": format!("{name_prefix}-group"),
        "policy": "random",
        "policyParams": [],
        "mode": "rule"
    });
    match ensure_default_resources(&app.state, &import_body) {
        Ok(response) => {
            let _ = append_log_for_config(
                &app.config_dir,
                &app.state,
                "info",
                "dae config file imported by Rust daed",
            );
            let _ = save_json_storage(&app.state, user.id, &user.json_storage);
            HttpResponse::json(
                200,
                json!({"imported": true, "defaults": response, "warnings": []}),
            )
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

fn api_preview_dae_config_file(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let content = body.get("content").and_then(Value::as_str).unwrap_or("");
    match export_bundle(&app.state, user) {
        Ok(bundle) => HttpResponse::json(
            200,
            json!({
                "bundle": bundle,
                "warnings": [{
                    "level": "info",
                    "code": "rust_daed_local_preview",
                    "message": format!("Rust daed local preview accepted {} bytes", content.len())
                }]
            }),
        ),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}
