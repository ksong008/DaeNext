use super::*;

pub(in crate::daed_product) fn api_get_bundle(app: &AppState, user: &UserRecord) -> HttpResponse {
    with_large_control_reclaim(|| match export_bundle(&app.state, user) {
        Ok(value) => {
            let response = HttpResponse::json(200, value);
            if response.body.len() <= MAX_BUNDLE_BODY_BYTES {
                response
            } else {
                HttpResponse::json(
                    413,
                    json!({
                        "error": "exported bundle exceeds the supported round-trip size",
                        "maxBytes": MAX_BUNDLE_BODY_BYTES,
                    }),
                )
            }
        }
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    })
}

pub(in crate::daed_product) fn api_put_bundle(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    with_large_control_reclaim(|| {
        let body = match json_body(request) {
            Ok(body) => body,
            Err(err) => return HttpResponse::json(400, json!({"error": err})),
        };
        match import_bundle(&app.state, &app.config_dir, &body, user) {
            Ok(outcome) => {
                let mut response = Map::new();
                response.insert("imported".to_owned(), json!(outcome.imported));
                if outcome.runtime_reload_required {
                    response.insert("runtimeReloadRequired".to_owned(), json!(true));
                }
                HttpResponse::json(200, Value::Object(response))
            }
            Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
        }
    })
}

pub(in crate::daed_product) fn api_get_dae_config_file(app: &AppState) -> HttpResponse {
    with_large_control_reclaim(|| match materialize_runtime(&app.state, None, true) {
        Ok(report) => HttpResponse::json(
            200,
            json!({
                "filename": "generated.dae",
                "content": report["content"].as_str().unwrap_or(""),
                "generated": true
            }),
        ),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    })
}

pub(in crate::daed_product) fn api_put_dae_config_file(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    with_large_control_reclaim(|| {
        let body = match json_body(request) {
            Ok(body) => body,
            Err(err) => return HttpResponse::json(400, json!({"error": err})),
        };
        let content = body.get("content").and_then(Value::as_str).unwrap_or("");
        let name_prefix = body
            .get("namePrefix")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_IMPORTED_CONFIG_NAME_PREFIX);
        match import_dae_file(&app.state, content, name_prefix, user) {
            Ok(outcome) => {
                let _ = append_log_for_config(
                    &app.config_dir,
                    &app.state,
                    "info",
                    "dae config file imported by Rust daed",
                );
                HttpResponse::json(
                    200,
                    json!({
                        "imported": true,
                        "defaults": {
                            "configId": outcome.config_id,
                            "dnsId": outcome.dns_id,
                            "routingId": outcome.routing_id,
                            "groupId": outcome.group_ids.first(),
                        },
                        "resources": {
                            "nodeIds": outcome.node_ids,
                            "groupIds": outcome.group_ids,
                        },
                        "warnings": outcome.warnings.into_iter().map(|message| json!({
                            "level": "warn",
                            "code": "dae_file_import_warning",
                            "message": message,
                        })).collect::<Vec<_>>(),
                    }),
                )
            }
            Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
        }
    })
}

pub(in crate::daed_product) fn api_preview_dae_config_file(
    _app: &AppState,
    request: &HttpRequest,
    _user: &UserRecord,
) -> HttpResponse {
    with_large_control_reclaim(|| {
        let body = match json_body(request) {
            Ok(body) => body,
            Err(err) => return HttpResponse::json(400, json!({"error": err})),
        };
        let content = body.get("content").and_then(Value::as_str).unwrap_or("");
        let name_prefix = body
            .get("namePrefix")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_IMPORTED_CONFIG_NAME_PREFIX);
        match preview_dae_file(content, name_prefix) {
            Ok(preview) => HttpResponse::json(
                200,
                json!({
                    "bundle": preview.bundle,
                    "warnings": preview.warnings.into_iter().map(|message| json!({
                        "level": "warn",
                        "code": "dae_file_import_warning",
                        "message": message,
                    })).collect::<Vec<_>>(),
                }),
            ),
            Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
        }
    })
}

fn with_large_control_reclaim(action: impl FnOnce() -> HttpResponse) -> HttpResponse {
    let response = {
        let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::LargeControl);
        action()
    };
    allocator_request_reclaim(AllocatorReclaimReason::LargeControlCompleted);
    response
}
