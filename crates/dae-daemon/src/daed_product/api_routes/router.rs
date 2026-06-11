use super::*;

pub(in crate::daed_product) fn route_request(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
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
                    json!({"error": "not implemented in production local product surface"}),
                ),
            }
        }
    }
}

pub(super) fn handle_health(_request: &HttpRequest) -> HttpResponse {
    HttpResponse::json(200, json!({"healthCheck": 1}))
}
