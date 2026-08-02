use super::*;

pub(in crate::daed_product) fn api_runtime_reload(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let reload_started_at = Instant::now();
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let dry = body.get("dry").and_then(Value::as_bool).unwrap_or(false);
    if dry {
        let plan = match prepare_runtime_reload_preview(&app.state) {
            Ok(plan) => plan,
            Err(err) => {
                let mut fields = BTreeMap::new();
                fields.insert("source".to_owned(), "api".to_owned());
                fields.insert("dry".to_owned(), dry.to_string());
                fields.insert("error".to_owned(), err.to_string());
                let _ = append_lifecycle_log_fields_for_config(
                    &app.config_dir,
                    &app.state,
                    "error",
                    err.api_log_message(),
                    fields,
                );
                return HttpResponse::json(err.http_status(), json!({"error": err.to_string()}));
            }
        };
        let preview = plan.report(Some(&app.config_dir), true);
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
    let latency_seed =
        stored_successful_node_latency_seed_snapshots(&app.state).unwrap_or_default();
    let reload_app = app.clone();
    let applied = match app.control_runtime.execute_to_completion(
        ProductControlTaskKind::RuntimeLifecycle,
        move |_cancellation| async move {
            coordinate_runtime_reload_inner(
                &reload_app.runtime,
                &reload_app.state,
                Some(&reload_app.config_dir),
                RuntimeApplyIntent::ApiReload,
                &latency_seed,
                AllocatorReclaimReason::ReloadCompleted,
            )
        },
    ) {
        Ok(Ok(applied)) => applied,
        Ok(Err(err)) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), "false".to_owned());
            fields.insert("error".to_owned(), err.to_string());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                err.api_log_message(),
                fields,
            );
            return HttpResponse::json(err.http_status(), json!({"error": err.to_string()}));
        }
        Err(err) => {
            let mut fields = BTreeMap::new();
            fields.insert("source".to_owned(), "api".to_owned());
            fields.insert("dry".to_owned(), "false".to_owned());
            fields.insert("error".to_owned(), err.to_string());
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "error",
                "[Reload] Failed to enter the product control runtime",
                fields,
            );
            return HttpResponse::json(503, json!({"error": err.to_string()}));
        }
    };
    let mut fields = BTreeMap::new();
    fields.insert("source".to_owned(), "api".to_owned());
    fields.insert("dry".to_owned(), "false".to_owned());
    fields.insert("applied".to_owned(), applied.applied.to_string());
    fields.insert("coalesced".to_owned(), applied.coalesced.to_string());
    fields.insert(
        "elapsed".to_owned(),
        format!("{:?}", reload_started_at.elapsed()),
    );
    let _ = append_lifecycle_log_fields_for_config(
        &app.config_dir,
        &app.state,
        "info",
        "[Reload] Finished",
        fields,
    );
    let mut response = applied
        .materialized_report
        .as_object()
        .cloned()
        .unwrap_or_default();
    response.insert(
        "applied".to_owned(),
        json!(if applied.applied { 1 } else { 0 }),
    );
    response.insert("dry".to_owned(), json!(false));
    response.insert("coalesced".to_owned(), json!(applied.coalesced));
    response.insert("runtimeStarted".to_owned(), json!(app.runtime.is_running()));
    response.insert(
        "pendingProcessTransition".to_owned(),
        json!(applied.pending_process_transition),
    );
    response.insert("allocatorReclaim".to_owned(), applied.allocator_reclaim);
    HttpResponse::json(200, Value::Object(response))
}

pub(in crate::daed_product) fn api_runtime_stop(app: &AppState) -> HttpResponse {
    match stop_runtime_and_persist(&app.state, &app.runtime) {
        Ok(mut report) => {
            let mut fields = BTreeMap::new();
            fields.insert(
                "was_running".to_owned(),
                report["wasRunning"].as_bool().unwrap_or(false).to_string(),
            );
            if let Some(elapsed_ms) = report["stopElapsedMs"].as_u64() {
                fields.insert("stop_elapsed_ms".to_owned(), elapsed_ms.to_string());
            }
            let _ = append_lifecycle_log_fields_for_config(
                &app.config_dir,
                &app.state,
                "info",
                "[Stop] runtime stopped by Rust daed",
                fields,
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
        .unwrap_or_else(|_| Some(DEFAULT_RUNTIME_LOG_LEVEL.to_owned()))
        .unwrap_or_else(|| DEFAULT_RUNTIME_LOG_LEVEL.to_owned());
    let level =
        normalize_runtime_log_level(&level).unwrap_or_else(|| DEFAULT_RUNTIME_LOG_LEVEL.to_owned());
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
    let Some(level) = normalize_runtime_log_level(
        body.get("level")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_RUNTIME_LOG_LEVEL),
    ) else {
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
