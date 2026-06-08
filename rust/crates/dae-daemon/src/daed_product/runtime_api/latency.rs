use super::*;

pub(in crate::daed_product) fn api_get_node_latencies(app: &AppState) -> HttpResponse {
    match list_node_latencies_value(&app.state, &app.runtime) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_test_node_latencies(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    match update_node_latencies(&app.state, &app.config_dir, &app.runtime, &ids) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}
