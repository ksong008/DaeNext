use super::*;

pub(in crate::daed_product) fn api_get_bundle(app: &AppState, user: &UserRecord) -> HttpResponse {
    match export_bundle(&app.state, user) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_put_bundle(
    app: &AppState,
    request: &HttpRequest,
    user: &UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match import_bundle(&app.state, &app.config_dir, &body, user) {
        Ok(imported) => HttpResponse::json(200, json!({"imported": imported})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_get_dae_config_file(app: &AppState) -> HttpResponse {
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

pub(in crate::daed_product) fn api_put_dae_config_file(
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

pub(in crate::daed_product) fn api_preview_dae_config_file(
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
