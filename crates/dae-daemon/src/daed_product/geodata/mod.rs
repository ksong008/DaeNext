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
mod update_admission;

use source::{GeodataSourceUrlUpdate, geodata_sources_status, update_geodata_source_settings};
pub(in crate::daed_product) use status::geodata_status;
pub(in crate::daed_product) use types::GeodataKind;
use update::update_geodata;
pub(in crate::daed_product) use update_admission::ProductGeodataUpdateCoordinator;

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
    let restore_default = body
        .get("restoreDefault")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let use_proxy = body.get("useProxy").and_then(Value::as_bool);
    let url = body.get("url").and_then(Value::as_str);
    if restore_default && url.is_some() {
        return HttpResponse::json(
            400,
            json!({"error": "restoreDefault and url cannot be set together"}),
        );
    }
    let url_update = if restore_default {
        GeodataSourceUrlUpdate::RestoreDefault
    } else if let Some(url) = url {
        GeodataSourceUrlUpdate::Set(url)
    } else {
        GeodataSourceUrlUpdate::Keep
    };
    let result = update_geodata_source_settings(&app.state, kind, url_update, use_proxy);
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
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => HttpResponse::json(
            409,
            json!({
                "error": err.to_string(),
                "kind": kind.response_key(),
            }),
        ),
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
