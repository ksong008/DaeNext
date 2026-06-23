use super::*;

mod file;
mod http;
mod status;
#[cfg(test)]
mod tests;
mod time;
mod types;
mod update;

pub(in crate::daed_product) use status::geodata_status;
pub(in crate::daed_product) use types::GeodataKind;
use update::update_geodata;

pub(in crate::daed_product) fn api_geodata_status(app: &AppState) -> HttpResponse {
    match geodata_status(app) {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn api_update_geodata(
    app: &AppState,
    kind: GeodataKind,
) -> HttpResponse {
    match update_geodata(app, kind) {
        Ok(status) => HttpResponse::json(200, status),
        Err(err) => HttpResponse::json(
            500,
            json!({
                "error": err.to_string(),
                "kind": kind.response_key(),
            }),
        ),
    }
}
