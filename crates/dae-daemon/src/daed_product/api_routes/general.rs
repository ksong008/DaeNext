use super::*;

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

pub(super) fn api_ui_session_touch(
    app: &AppState,
    request: &HttpRequest,
    user_id: i64,
) -> HttpResponse {
    match app.ui_runtime.touch(user_id, request) {
        Ok(()) => HttpResponse::empty(204),
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            HttpResponse::json(400, json!({"error": error.to_string()}))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            HttpResponse::json(429, json!({"error": error.to_string()}))
        }
        Err(error) => HttpResponse::json(503, json!({"error": error.to_string()})),
    }
}

pub(super) fn api_ui_session_close(
    app: &AppState,
    request: &HttpRequest,
    user_id: i64,
) -> HttpResponse {
    match app.ui_runtime.close_hint(user_id, request) {
        Ok(_) => HttpResponse::empty(204),
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            HttpResponse::json(400, json!({"error": error.to_string()}))
        }
        Err(error) => HttpResponse::json(503, json!({"error": error.to_string()})),
    }
}
