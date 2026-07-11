use super::*;

pub(in crate::daed_product) fn api_runtime_events(
    app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    let full = runtime_overview_report(app, request);
    thread::sleep(Duration::from_millis(200));
    let delta = runtime_overview_delta_report(app, request);
    sse_response_events(
        &[
            ("runtime.overview", full),
            ("runtime.overview.delta", delta),
        ],
        Some(LOG_STREAM_RETRY_MS),
    )
}

pub(in crate::daed_product) fn api_log_events(
    _app: &AppState,
    request: &HttpRequest,
) -> HttpResponse {
    match (
        log_level_filter_from_request(request),
        log_event_after_id_from_request(request),
    ) {
        (Ok(_), Ok(_)) => sse_response_events(&[], Some(LOG_STREAM_RETRY_MS)),
        (Err(err), _) | (_, Err(err)) => HttpResponse::json(400, json!({"error": err})),
    }
}

pub(in crate::daed_product) fn log_event_after_id_from_request(
    request: &HttpRequest,
) -> Result<Option<u64>, String> {
    let value = request
        .query
        .get("after_id")
        .or_else(|| request.query.get("afterId"))
        .and_then(|values| values.first())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    match value {
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| "invalid log event after_id".to_owned()),
        None => Ok(None),
    }
}
