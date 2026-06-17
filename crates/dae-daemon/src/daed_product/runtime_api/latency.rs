use super::*;

pub(in crate::daed_product) fn api_get_node_latencies(app: &AppState) -> HttpResponse {
    let result = if app.latency_jobs.is_active() {
        list_stored_node_latencies_value(&app.state)
    } else {
        list_node_latencies_value(&app.state, &app.runtime)
    };
    match result {
        Ok(mut value) => {
            add_node_latency_job_value(&mut value, &app.latency_jobs);
            HttpResponse::json(200, value)
        }
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_get_node_latency_job(app: &AppState) -> HttpResponse {
    HttpResponse::json(200, current_node_latency_job_value(&app.latency_jobs))
}

pub(in crate::daed_product) fn api_test_node_latencies(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    match enqueue_node_latency_job(
        &app.state,
        &app.config_dir,
        Arc::clone(&app.runtime),
        Arc::clone(&app.latency_jobs),
        &ids,
    ) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}
