use super::*;

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
            "GET" => list_groups(&app.state, request),
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
