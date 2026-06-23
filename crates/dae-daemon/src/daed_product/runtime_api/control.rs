use super::*;

pub(in crate::daed_product) fn api_runtime_reload(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let reload_started_at = Instant::now();
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let dry = body.get("dry").and_then(Value::as_bool).unwrap_or(false);
    if !dry
        && let Err(err) = refresh_log_policy_and_reset_runtime_cycle_logs(
            &app.config_dir,
            &app.state,
            Some(&app.runtime),
        )
    {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
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
        Some(content) => content.to_owned(),
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
    let config = match build_runtime_config_from_content(&content) {
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
    let config_content = content.clone();
    drop(content);
    drop(preview);
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
    if let Err(err) = refresh_log_policy_and_reset_runtime_cycle_logs(
        &app.config_dir,
        &app.state,
        Some(&app.runtime),
    ) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    if let Err(err) =
        app.runtime
            .reload_with_config_content(config, Some(config_content), "api-runtime-reload")
    {
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
            let reload_reclaim = allocator_reclaim(AllocatorReclaimReason::ReloadCompleted);
            let mut response = report.as_object().cloned().unwrap_or_default();
            response.insert("applied".to_owned(), json!(1));
            response.insert("dry".to_owned(), json!(false));
            response.insert("runtimeStarted".to_owned(), json!(true));
            response.insert("allocatorReclaim".to_owned(), reload_reclaim);
            let response = HttpResponse::json(200, Value::Object(response));
            let _ = allocator_reclaim(AllocatorReclaimReason::ReloadCompleted);
            response
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

pub(in crate::daed_product) fn api_runtime_stop(app: &AppState) -> HttpResponse {
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

pub(in crate::daed_product) fn api_get_runtime_log_level(app: &AppState) -> HttpResponse {
    let level = get_metadata(&app.state, "runtime_log_level")
        .unwrap_or_else(|_| Some("info".to_owned()))
        .unwrap_or_else(|| "info".to_owned());
    let level = normalize_runtime_log_level(&level).unwrap_or_else(|| "info".to_owned());
    HttpResponse::json(200, json!({"level": level}))
}

pub(in crate::daed_product) fn api_set_runtime_log_level(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
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
    if let Err(err) =
        refresh_log_policy_and_reset_logs(&app.config_dir, &app.state, Some(&app.runtime))
    {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"level": level}))
}

pub(in crate::daed_product) fn normalize_runtime_log_level(level: &str) -> Option<String> {
    normalize_log_level_name(level)
}
