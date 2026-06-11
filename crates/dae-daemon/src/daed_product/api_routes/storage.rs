use super::*;

pub(super) fn api_get_storage(request: &HttpRequest, user: UserRecord) -> HttpResponse {
    let paths = request.query.get("path").cloned().unwrap_or_default();
    let values = query_json_storage(&user.json_storage, &paths);
    HttpResponse::json(200, json!({"values": values}))
}

pub(super) fn api_set_storage(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let values = string_array(&body, "values");
    if paths.len() != values.len() {
        return HttpResponse::json(400, json!({"error": "len(paths) != len(values)"}));
    }
    let updated = match set_json_storage(&mut user.json_storage, &paths, &values) {
        Ok(updated) => updated,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"updated": updated}))
}

pub(super) fn api_delete_storage(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let paths = string_array(&body, "paths");
    let removed = match remove_json_storage(&mut user.json_storage, &paths) {
        Ok(removed) => removed,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
        return HttpResponse::json(500, json!({"error": err.to_string()}));
    }
    HttpResponse::json(200, json!({"removed": removed}))
}

pub(super) fn api_default_resources(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    match ensure_default_resources(&app.state, &body) {
        Ok(response) => {
            let paths = vec![
                "defaultConfigID".to_owned(),
                "defaultRoutingID".to_owned(),
                "defaultDNSID".to_owned(),
                "defaultGroupID".to_owned(),
                "mode".to_owned(),
            ];
            let values = vec![
                response["defaultConfigID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultRoutingID"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                response["defaultDNSID"].as_str().unwrap_or("").to_owned(),
                response["defaultGroupID"].as_str().unwrap_or("").to_owned(),
                response["mode"].as_str().unwrap_or("").to_owned(),
            ];
            if let Err(err) = set_json_storage(&mut user.json_storage, &paths, &values) {
                return HttpResponse::json(400, json!({"error": err}));
            }
            if let Err(err) = save_json_storage(&app.state, user.id, &user.json_storage) {
                return HttpResponse::json(500, json!({"error": err.to_string()}));
            }
            HttpResponse::json(200, response)
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}
