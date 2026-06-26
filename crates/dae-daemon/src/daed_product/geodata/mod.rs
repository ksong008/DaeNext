use super::*;

mod file;
mod http;
mod source;
mod status;
#[cfg(test)]
mod tests;
mod time;
mod types;
mod update;

use source::{geodata_sources_status, reset_geodata_source_url, set_geodata_source_url};
pub(in crate::daed_product) use status::geodata_status;
pub(in crate::daed_product) use types::GeodataKind;
use update::update_geodata;

pub(in crate::daed_product) fn api_geodata_status(app: &AppState) -> HttpResponse {
    match geodata_status(app) {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_geodata_source_settings(app: &AppState) -> HttpResponse {
    match geodata_sources_status(&app.state) {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_set_geodata_source(
    app: &AppState,
    request: &HttpRequest,
    kind: GeodataKind,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let result = if body
        .get("restoreDefault")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        reset_geodata_source_url(&app.state, kind)
    } else {
        let Some(url) = body.get("url").and_then(Value::as_str) else {
            return HttpResponse::json(400, json!({"error": "geodata source url is required"}));
        };
        set_geodata_source_url(&app.state, kind, url)
    };
    match result {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => geodata_source_error_response(err),
    }
}

fn geodata_source_error_response(err: io::Error) -> HttpResponse {
    let status = match err.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => 400,
        _ => 500,
    };
    HttpResponse::json(status, json!({"error": err.to_string()}))
}

pub(in crate::daed_product) fn api_update_geodata(
    app: &AppState,
    kind: GeodataKind,
) -> HttpResponse {
    let response = match update_geodata(app, kind) {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => HttpResponse::json(
            500,
            json!({
                "error": err.to_string(),
                "kind": kind.response_key(),
            }),
        ),
    };
    let _ = allocator_reclaim(AllocatorReclaimReason::GeodataUpdate);
    response
}
