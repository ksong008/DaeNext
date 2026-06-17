use super::*;

pub(super) fn api_auth_status(app: &AppState) -> HttpResponse {
    match user_count(&app.state) {
        Ok(count) => HttpResponse::json(200, json!({"numberUsers": count})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_create_user(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match create_user(&app.state, username, password) {
        Ok(token) => HttpResponse::json(201, json!({"token": token})),
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_issue_token(app: &AppState, request: &HttpRequest) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let username = required_str(&body, "username");
    let password = required_str(&body, "password");
    let (username, password) = match (username, password) {
        (Some(username), Some(password)) => (username, password),
        _ => {
            return HttpResponse::json(400, json!({"error": "username and password are required"}));
        }
    };
    match issue_token(&app.state, username, password) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(401, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_patch_user(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Some(username) = body.get("username").and_then(Value::as_str) {
        if let Err(err) = conn.execute(
            "UPDATE users SET username = ?1 WHERE id = ?2",
            params![username, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.username = username.to_owned();
    }
    if body
        .get("clearName")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET name = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = None;
    } else if body.get("name").is_some() {
        let value = body.get("name").and_then(Value::as_str).map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET name = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.name = value;
    }
    if body
        .get("clearAvatar")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = NULL WHERE id = ?1",
            params![user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = None;
    } else if body.get("avatar").is_some() {
        let value = body
            .get("avatar")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Err(err) = conn.execute(
            "UPDATE users SET avatar = ?1 WHERE id = ?2",
            params![value, user.id],
        ) {
            return HttpResponse::json(400, json!({"error": err.to_string()}));
        }
        user.avatar = value;
    }
    HttpResponse::json(200, user_resource(&user))
}

pub(super) fn api_update_password(
    app: &AppState,
    request: &HttpRequest,
    mut user: UserRecord,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let current = required_str(&body, "currentPassword");
    let new_password = required_str(&body, "newPassword");
    let (current, new_password) = match (current, new_password) {
        (Some(current), Some(new_password)) => (current, new_password),
        _ => {
            return HttpResponse::json(
                400,
                json!({"error": "currentPassword and newPassword are required"}),
            );
        }
    };
    if !verify_password_hash(&user.password_hash, user.jwt_secret.as_bytes(), current) {
        return HttpResponse::json(400, json!({"error": "incorrect password"}));
    }
    if let Err(err) = validate_password_strength(new_password) {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let secret = match random_secret_hex() {
        Ok(secret) => secret,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let password_hash = hash_password(secret.as_bytes(), new_password);
    let conn = match open_state_connection(&app.state) {
        Ok(conn) => conn,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    if let Err(err) = conn.execute(
        "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
        params![password_hash, secret, user.id],
    ) {
        return HttpResponse::json(400, json!({"error": err.to_string()}));
    }
    user.jwt_secret = secret;
    match signed_token(&user) {
        Ok(token) => HttpResponse::json(200, json!({"token": token})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}
