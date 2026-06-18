use super::*;

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
            "GET" => list_sections(&app.state, request, kind),
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
