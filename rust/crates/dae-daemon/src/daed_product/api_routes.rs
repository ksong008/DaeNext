use super::*;
pub(super) fn route_request(app: &AppState, request: &HttpRequest) -> HttpResponse {
    if request.method == "OPTIONS" {
        return HttpResponse::empty(204);
    }
    if request.path == "/health" {
        return handle_health(request);
    }
    if let Some(api_path) = request.path.strip_prefix("/api") {
        let api_path = if api_path.is_empty() { "/" } else { api_path };
        return handle_api_request(app, request, api_path);
    }
    if app.api_only {
        return HttpResponse::json(
            404,
            json!({"error": "static WebUI serving is disabled by --api-only"}),
        );
    }
    serve_static_file(&app.web_root, request)
}

pub(super) fn handle_api_request(
    app: &AppState,
    request: &HttpRequest,
    api_path: &str,
) -> HttpResponse {
    match (request.method.as_str(), api_path) {
        ("GET", "/health") => handle_health(request),
        ("GET", "/auth/status") => api_auth_status(app),
        ("POST", "/auth/users") => api_create_user(app, request),
        ("POST", "/auth/token") => api_issue_token(app, request),
        _ => {
            let Some(user) = authenticate_request(app, request) else {
                return HttpResponse::json(401, json!({"error": "authentication required"}));
            };
            match (request.method.as_str(), api_path) {
                ("GET", "/user/me") => HttpResponse::json(200, user_resource(&user)),
                ("PATCH", "/user/me") => api_patch_user(app, request, user),
                ("POST", "/user/me/password") => api_update_password(app, request, user),
                ("GET", "/user/me/storage") => api_get_storage(request, user),
                ("PUT", "/user/me/storage") => api_set_storage(app, request, user),
                ("DELETE", "/user/me/storage") => api_delete_storage(app, request, user),
                ("POST", "/user/me/default-resources") => api_default_resources(app, request, user),
                ("GET", "/user/me/dae-bundle") => api_get_bundle(app, &user),
                ("PUT", "/user/me/dae-bundle") => api_put_bundle(app, request, &user),
                ("GET", "/user/me/dae-config-file") => api_get_dae_config_file(app),
                ("PUT", "/user/me/dae-config-file") => api_put_dae_config_file(app, request, &user),
                ("POST", "/user/me/dae-config-file/preview") => {
                    api_preview_dae_config_file(app, request, &user)
                }
                ("GET", "/general/state") => api_general_state(app),
                ("GET", "/general/cache-stats") => api_general_cache_stats(app),
                ("GET", "/general/interfaces") => api_general_interfaces(request),
                ("GET", "/runtime/overview") => api_runtime_overview(app, request),
                ("POST", "/runtime/reload") => api_runtime_reload(app, request),
                ("POST", "/runtime/stop") => api_runtime_stop(app),
                ("GET", "/runtime/log-level") => api_get_runtime_log_level(app),
                ("PATCH", "/runtime/log-level") => api_set_runtime_log_level(app, request),
                ("GET", "/events/runtime") => api_runtime_events(app, request),
                ("GET", "/events/logs") => api_log_events(app, request),
                ("GET", "/logs") => api_logs(app, request),
                ("DELETE", "/logs") => api_clear_logs(app),
                ("GET", "/logs/settings") => api_get_log_settings(app),
                ("PATCH", "/logs/settings") => api_set_log_settings(app, request),
                ("GET", "/nodes/latencies") => api_get_node_latencies(app),
                ("POST", "/nodes/latencies") => api_test_node_latencies(app, request),
                _ if api_path == "/configs"
                    || api_path.starts_with("/configs/")
                    || api_path == "/dns"
                    || api_path.starts_with("/dns/")
                    || api_path == "/routings"
                    || api_path.starts_with("/routings/") =>
                {
                    api_section_resource(app, request, api_path)
                }
                _ if api_path == "/nodes" || api_path.starts_with("/nodes/") => {
                    api_nodes(app, request, api_path)
                }
                _ if api_path == "/subscriptions" || api_path.starts_with("/subscriptions/") => {
                    api_subscriptions(app, request, api_path)
                }
                _ if api_path == "/groups" || api_path.starts_with("/groups/") => {
                    api_groups(app, request, api_path)
                }
                _ => HttpResponse::json(
                    404,
                    json!({"error": "not implemented in C10 local product surface"}),
                ),
            }
        }
    }
}

pub(super) fn handle_health(_request: &HttpRequest) -> HttpResponse {
    HttpResponse::json(200, json!({"healthCheck": 1}))
}

pub(super) fn api_auth_status(app: &AppState) -> HttpResponse {
    match user_count(&app.state) {
        Ok(count) => HttpResponse::json(200, json!({"numberUsers": count})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_create_user(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match create_user(&app.state, username, password) {
        Ok(token) => HttpResponse::json(201, json!({"token": token})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_issue_token(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match issue_token(&app.state, username, password) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(401, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_patch_user(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(username) = body.get("username").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE users SET username = ?1 WHERE id = ?2",
            params![username, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.username = username.to_owned();
    }
    if body
        .get("clearName")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET name = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = None;
    } else if body.get("name").is_some() {
        let value = body.get("name").and_then(Value::as_str).map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET name = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = value;
    }
    if body
        .get("clearAvatar")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = None;
    } else if body.get("avatar").is_some() {
        let value = body
            .get("avatar")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = value;
    }
    HttpResponse::json(200, user_resource(&user))
}

pub(super) fn api_update_password(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let current = required_str(&body, "currentPassword");
    let new_password = required_str(&body, "newPassword");
    let (current, new_password) = match (current, new_password) {
        (Some(current), Some(new_password)) => (current, new_password),
        _ => {
            return HttpResponse::json(
                400,
                json!({"error": "currentPassword and newPassword are required"}),
            );
        }
    };
    if hash_password(user.jwt_secret.as_bytes(), current) != user.password_hash {
        return HttpResponse::json(400, json!({"error": "incorrect password"}));
    }
    if let Err(err) = validate_password_strength(new_password) {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let secret = match random_secret_hex() {
        Ok(secret) => secret,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let password_hash = hash_password(secret.as_bytes(), new_password);
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
        params![password_hash, secret, user.id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    user.jwt_secret = secret;
    match signed_token(&user) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_get_storage(request: &HttpRequest, user: UserRecord) -> HttpResponse {
    let paths = request.query.get("path").cloned().unwrap_or_default();
    let values = query_json_storage(&user.json_storage, &paths);
    HttpResponse::json(200, json!({"values": values}))
}

pub(super) fn api_set_storage(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let values = string_array(&body, "values");
    if paths.len() != values.len() {
        return HttpResponse::json(400, json!({"error": "len(paths) != len(values)"}));
    }
    let updated = match set_json_storage(&mut user.json_storage, &paths, &values) {
        Ok(updated) => updated,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"updated": updated}))
}

pub(super) fn api_delete_storage(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let removed = match remove_json_storage(&mut user.json_storage, &paths) {
        Ok(removed) => removed,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

pub(super) fn api_default_resources(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match ensure_default_resources(&app.state, &body) {
        Ok(response) => {
            let paths = vec![
                "defaultConfigID".to_owned(),
                "defaultRoutingID".to_owned(),
                "defaultDNSID".to_owned(),
                "defaultGroupID".to_owned(),
                "mode".to_owned(),
            ];
            let values = vec![
                response["defaultConfigID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultRoutingID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultDNSID"].as_str().unwrap_or("").to_owned(),
                response["defaultGroupID"].as_str().unwrap_or("").to_owned(),
                response["mode"].as_str().unwrap_or("").to_owned(),
            ];
            if let Err(err) = set_json_storage(&mut user.json_storage, &paths, &values) {
                return HttpResponse::json(400, json!({"error": err}));
            }
            if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
                return HttpResponse::json(500, json!({"error": err.to_string()}));
            }
            HttpResponse::json(200, response)
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_section_resource(
    app: &AppState,
    request: &HttpRequest,
    api_path: &str,
) -> HttpResponse {
    if matches!(
        api_path,
        "/configs/parsed" | "/dns/parsed" | "/routings/parsed"
    ) {
        return api_section_preview(request, api_path);
    }
    if api_path == "/configs/flat-desc" {
        return HttpResponse::json(200, product_flatdesc());
    }
    let Some(kind) = SectionKind::from_path(api_path) else {
        return HttpResponse::json(404, json!({"error": "unknown section resource"}));
    };
    let suffix = api_path.trim_start_matches(kind.prefix());
    if suffix.is_empty() {
        return match request.method.as_str() {
            "GET" => list_sections(&app.state, kind),
            "POST" => create_section(&app.state, request, kind),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let parts = suffix
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid resource id"}));
    };
    if parts.len() == 2 && parts[1] == "select" {
        return match request.method.as_str() {
            "POST" => select_section(&app.state, kind, id),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown section resource path"}));
    }
    match request.method.as_str() {
        "GET" => get_section(&app.state, kind, id),
        "PUT" | "PATCH" => update_section(&app.state, request, kind, id),
        "DELETE" => delete_section(&app.state, kind, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

pub(super) fn api_nodes(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/nodes" {
        return match request.method.as_str() {
            "GET" => list_nodes_for_request(&app.state, request),
            "POST" => import_nodes(&app.state, request, None),
            "DELETE" => delete_nodes(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let Some(id) = api_path
        .strip_prefix("/nodes/")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return HttpResponse::json(400, json!({"error": "invalid node id"}));
    };
    match request.method.as_str() {
        "GET" => get_node(&app.state, id),
        "PUT" | "PATCH" => update_node(&app.state, request, id),
        "DELETE" => delete_node_by_id(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

pub(super) fn api_subscriptions(
    app: &AppState,
    request: &HttpRequest,
    api_path: &str,
) -> HttpResponse {
    if api_path == "/subscriptions" {
        return match request.method.as_str() {
            "GET" => list_subscriptions(&app.state, request),
            "POST" => create_subscription(&app.state, &app.config_dir, request),
            "DELETE" => delete_subscriptions(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let suffix = api_path.trim_start_matches("/subscriptions/");
    let parts = suffix.split('/').collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid subscription id"}));
    };
    if parts.len() == 2 && parts[1] == "nodes" {
        return match request.method.as_str() {
            "GET" => list_nodes(&app.state, Some(id)),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() == 2 && parts[1] == "refresh" {
        return match request.method.as_str() {
            "POST" => refresh_subscription(&app.state, &app.config_dir, &app.runtime, id),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown subscription path"}));
    }
    match request.method.as_str() {
        "GET" => get_subscription(&app.state, id),
        "PUT" | "PATCH" => update_subscription(&app.state, request, id),
        "DELETE" => delete_subscription_by_id(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

pub(super) fn api_groups(app: &AppState, request: &HttpRequest, api_path: &str) -> HttpResponse {
    if api_path == "/groups" {
        return match request.method.as_str() {
            "GET" => list_groups(&app.state),
            "POST" => create_group(&app.state, request),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    let suffix = api_path.trim_start_matches("/groups/");
    let parts = suffix.split('/').collect::<Vec<_>>();
    let Some(id) = parts.first().and_then(|value| value.parse::<i64>().ok()) else {
        return HttpResponse::json(400, json!({"error": "invalid group id"}));
    };
    if parts.len() == 2 && parts[1] == "nodes" {
        return match request.method.as_str() {
            "POST" => update_group_nodes(&app.state, request, id, true),
            "DELETE" => update_group_nodes(&app.state, request, id, false),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() == 2 && parts[1] == "subscriptions" {
        return match request.method.as_str() {
            "POST" => update_group_subscriptions(&app.state, request, id, true),
            "DELETE" => update_group_subscriptions(&app.state, request, id, false),
            _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
        };
    }
    if parts.len() != 1 {
        return HttpResponse::json(404, json!({"error": "unknown group path"}));
    }
    match request.method.as_str() {
        "GET" => get_group(&app.state, id),
        "PUT" | "PATCH" => update_group(&app.state, request, id),
        "DELETE" => delete_group(&app.state, id),
        _ => HttpResponse::json(405, json!({"error": "method not allowed"})),
    }
}

pub(super) fn api_general_state(app: &AppState) -> HttpResponse {
    match general_state_report(&app.state, &app.config_dir, &app.runtime) {
        Ok(report) => HttpResponse::json(200, report),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_general_cache_stats(app: &AppState) -> HttpResponse {
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let latency = count_table(&conn, "node_latency_results").unwrap_or(0);
    HttpResponse::json(
        200,
        json!({
            "dnsCacheEntries": 0,
            "nodeLatencyCacheEntries": latency,
            "routingCacheEntries": 0,
        }),
    )
}

pub(super) fn api_general_interfaces(request: &HttpRequest) -> HttpResponse {
    let up = query_bool(request, "up");
    let only_global_scope = query_bool(request, "onlyGlobalScope").unwrap_or(false);
    match list_system_interfaces(up, only_global_scope) {
        Ok(items) => HttpResponse::json(200, json!({"items": items})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_runtime_overview(app: &AppState, request: &HttpRequest) -> HttpResponse {
    HttpResponse::json(200, runtime_overview_report(app, request))
}
