use super::*;

#[cfg(test)]
pub(in crate::daed_product) fn route_request(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    route_request_with_context(app, request, ProductHttpRequestContext::default())
}

pub(in crate::daed_product) fn route_request_with_context(
    app: &AppState,
    request: &HttpRequest,
    context: ProductHttpRequestContext,
) -> HttpResponse {
    if request.method == "OPTIONS" {
        return HttpResponse::empty(204);
    }
    if request.path == "/health" {
        return handle_health(request);
    }
    if let Some(api_path) = request.path.strip_prefix("/api") {
        let api_path = if api_path.is_empty() { "/" } else { api_path };
        return handle_api_request(app, request, api_path, context);
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
    context: ProductHttpRequestContext,
) -> HttpResponse {
    let route = classify_product_api_route(&request.method, api_path);
    match route {
        ProductApiRoute::Health => return handle_health(request),
        ProductApiRoute::AuthStatus => return api_auth_status(app),
        ProductApiRoute::CreateUser => return api_create_user(app, request, context),
        ProductApiRoute::IssueToken => return api_issue_token(app, request, context),
        _ => {}
    }
    let user = match authenticate_request(app, request) {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::json(401, json!({"error": "authentication required"}));
        }
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    match route {
        ProductApiRoute::UserMe => HttpResponse::json(200, user_resource(&user)),
        ProductApiRoute::PatchUser => api_patch_user(app, request, user),
        ProductApiRoute::UpdatePassword => api_update_password(app, request, user, context),
        ProductApiRoute::GetStorage => api_get_storage(request, user),
        ProductApiRoute::SetStorage => api_set_storage(app, request, user),
        ProductApiRoute::DeleteStorage => api_delete_storage(app, request, user),
        ProductApiRoute::DefaultResources => api_default_resources(app, request, user),
        ProductApiRoute::SelectProfile => api_select_profile(&app.state, request),
        ProductApiRoute::GetBundle => api_get_bundle(app, &user),
        ProductApiRoute::PutBundle => api_put_bundle(app, request, &user),
        ProductApiRoute::GetDaeConfigFile => api_get_dae_config_file(app),
        ProductApiRoute::PutDaeConfigFile => api_put_dae_config_file(app, request, &user),
        ProductApiRoute::PreviewDaeConfigFile => api_preview_dae_config_file(app, request, &user),
        ProductApiRoute::GeneralState => api_general_state(app),
        ProductApiRoute::GeneralCacheStats => api_general_cache_stats(app),
        ProductApiRoute::GeneralInterfaces => api_general_interfaces(request),
        ProductApiRoute::GeodataStatus => api_geodata_status(app),
        ProductApiRoute::GeodataSettings => api_geodata_source_settings(app),
        ProductApiRoute::SetGeositeSource => {
            api_set_geodata_source(app, request, GeodataKind::Geosite)
        }
        ProductApiRoute::SetGeoipSource => api_set_geodata_source(app, request, GeodataKind::Geoip),
        ProductApiRoute::UpdateGeosite => api_update_geodata(app, GeodataKind::Geosite),
        ProductApiRoute::UpdateGeoip => api_update_geodata(app, GeodataKind::Geoip),
        ProductApiRoute::RuntimeOverview => api_runtime_overview(app, request),
        ProductApiRoute::TouchUiSession => api_ui_session_touch(app, request, user.id()),
        ProductApiRoute::CloseUiSession => api_ui_session_close(app, request, user.id()),
        ProductApiRoute::RuntimeReload => api_runtime_reload(app, request),
        ProductApiRoute::RuntimeStop => api_runtime_stop(app),
        ProductApiRoute::GetRuntimeLogLevel => api_get_runtime_log_level(app),
        ProductApiRoute::SetRuntimeLogLevel => api_set_runtime_log_level(app, request),
        ProductApiRoute::RuntimeEvents => api_runtime_events(app, request),
        ProductApiRoute::LogEvents => api_log_events(app, request),
        ProductApiRoute::Logs => api_logs(app, request),
        ProductApiRoute::ClearLogs => api_clear_logs(app),
        ProductApiRoute::GetLogSettings => api_get_log_settings(app),
        ProductApiRoute::SetLogSettings => api_set_log_settings(app, request),
        ProductApiRoute::GetNodeLatencies => api_get_node_latencies(app),
        ProductApiRoute::TestNodeLatencies => api_test_node_latencies(app, request),
        ProductApiRoute::GetNodeLatencyJob => api_get_node_latency_job(app),
        ProductApiRoute::CancelNodeLatencyJob => api_cancel_node_latency_job(app, request),
        ProductApiRoute::Sections => api_section_resource(app, request, api_path),
        ProductApiRoute::Nodes => api_nodes(app, request, api_path),
        ProductApiRoute::Subscriptions => api_subscriptions(app, request, api_path),
        ProductApiRoute::Groups => api_groups(app, request, api_path),
        ProductApiRoute::NotFound => HttpResponse::json(
            404,
            json!({"error": "not implemented in production local product surface"}),
        ),
        ProductApiRoute::Health
        | ProductApiRoute::AuthStatus
        | ProductApiRoute::CreateUser
        | ProductApiRoute::IssueToken => unreachable!("public routes returned before auth"),
    }
}

pub(super) fn handle_health(_request: &HttpRequest) -> HttpResponse {
    HttpResponse::json(200, json!({"healthCheck": 1}))
}
