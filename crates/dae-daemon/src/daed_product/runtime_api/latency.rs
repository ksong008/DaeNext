use super::*;

pub(in crate::daed_product) fn api_get_node_latencies(app: &AppState) -> HttpResponse {
    let result = list_stored_node_latencies_value(&app.state);
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

pub(in crate::daed_product) fn api_cancel_node_latency_job(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err.to_string()})),
    };
    let Some(job_id) = body.get("id").and_then(Value::as_u64) else {
        return HttpResponse::json(400, json!({"error": "latency job id is required"}));
    };
    match cancel_node_latency_job_value(&app.latency_jobs, job_id) {
        Ok(value) => HttpResponse::json(200, value),
        Err(LatencyJobCancelError::NoCurrentJob) => HttpResponse::json(
            404,
            json!({"error": LatencyJobCancelError::NoCurrentJob.to_string()}),
        ),
        Err(err @ LatencyJobCancelError::JobIdMismatch { .. }) => {
            HttpResponse::json(409, json!({"error": err.to_string()}))
        }
        Err(err @ LatencyJobCancelError::ManagerUnavailable) => {
            HttpResponse::json(500, json!({"error": err.to_string()}))
        }
    }
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
