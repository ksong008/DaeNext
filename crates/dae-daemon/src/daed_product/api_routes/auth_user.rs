use super::*;

pub(super) fn api_auth_status(app: &AppState) -> HttpResponse {
    match user_count(&app.state) {
        Ok(count) => HttpResponse::json(200, json!({"numberUsers": count})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(super) fn api_create_user(
    app: &AppState,
    request: &HttpRequest,
    context: ProductHttpRequestContext,
) -> HttpResponse {
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
    let state = app.state.clone();
    let username_owned = username.to_owned();
    let password = password.to_owned();
    execute_auth_request(app, context, username, move || {
        ProductAuthJobOutcome::neutral(
            match create_user_with_auth_worker(&state, &username_owned, &password) {
                Ok(token) => HttpResponse::json(201, json!({"token": token})),
                Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
            },
        )
    })
}

pub(super) fn api_issue_token(
    app: &AppState,
    request: &HttpRequest,
    context: ProductHttpRequestContext,
) -> HttpResponse {
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
    let state = app.state.clone();
    let username_owned = username.to_owned();
    let password = password.to_owned();
    execute_auth_request(
        app,
        context,
        username,
        move || match issue_token_with_auth_worker(&state, &username_owned, &password) {
            Ok(token) => {
                ProductAuthJobOutcome::success(HttpResponse::json(200, json!({"token": token})))
            }
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                ProductAuthJobOutcome::credential_failure(HttpResponse::json(
                    401,
                    json!({"error": err.to_string()}),
                ))
            }
            Err(err) => ProductAuthJobOutcome::neutral(HttpResponse::json(
                401,
                json!({"error": err.to_string()}),
            )),
        },
    )
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
    match apply_user_profile_update(&conn, &body, &mut user) {
        Ok(()) => HttpResponse::json(200, user_resource(&user)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            HttpResponse::json(404, json!({"error": err.to_string()}))
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(in crate::daed_product) fn apply_user_profile_update(
    conn: &Connection,
    body: &Value,
    user: &mut UserRecord,
) -> io::Result<()> {
    let username = body
        .get("username")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| user.username().to_owned());
    let name =
        patched_optional_user_field(body, "name", "clearName", user.name().map(str::to_owned));
    let avatar = patched_optional_user_field(
        body,
        "avatar",
        "clearAvatar",
        user.avatar().map(str::to_owned),
    );
    let updated = conn
        .execute(
            "UPDATE users SET username = ?1, name = ?2, avatar = ?3 WHERE id = ?4",
            params![username, name, avatar, user.id()],
        )
        .map_err(sqlite_io_error)?;
    if updated == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "user not found"));
    }
    user.set_username(username);
    user.set_name(name);
    user.set_avatar(avatar);
    Ok(())
}

fn patched_optional_user_field(
    body: &Value,
    value_key: &str,
    clear_key: &str,
    current: Option<String>,
) -> Option<String> {
    if body
        .get(clear_key)
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        None
    } else if body.get(value_key).is_some() {
        body.get(value_key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        current
    }
}

pub(super) fn api_update_password(
    app: &AppState,
    request: &HttpRequest,
    user: UserRecord,
    context: ProductHttpRequestContext,
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
    let state = app.state.clone();
    let username = user.username().to_owned();
    let current = current.to_owned();
    let new_password = new_password.to_owned();
    execute_auth_request(app, context, &username, move || {
        update_password_auth_job(&state, user, &current, &new_password)
    })
}

fn update_password_auth_job(
    state: &Path,
    mut user: UserRecord,
    current: &str,
    new_password: &str,
) -> ProductAuthJobOutcome {
    if !verify_password_hash(user.password_hash(), user.jwt_secret().as_bytes(), current) {
        return ProductAuthJobOutcome::credential_failure(HttpResponse::json(
            400,
            json!({"error": "incorrect password"}),
        ));
    }
    if let Err(err) = validate_password_strength(new_password) {
        return ProductAuthJobOutcome::neutral(HttpResponse::json(400, json!({"error": err})));
    }
    let secret = match random_secret_hex() {
        Ok(secret) => secret,
        Err(err) => {
            return ProductAuthJobOutcome::neutral(HttpResponse::json(
                500,
                json!({"error": err.to_string()}),
            ));
        }
    };
    let password_hash = hash_password(secret.as_bytes(), new_password);
    let conn = match open_state_connection(state) {
        Ok(conn) => conn,
        Err(err) => {
            return ProductAuthJobOutcome::neutral(HttpResponse::json(
                500,
                json!({"error": err.to_string()}),
            ));
        }
    };
    if let Err(err) = conn.execute(
        "UPDATE users SET password_hash = ?1, jwt_secret = ?2 WHERE id = ?3",
        params![password_hash, secret, user.id()],
    ) {
        return ProductAuthJobOutcome::neutral(HttpResponse::json(
            400,
            json!({"error": err.to_string()}),
        ));
    }
    user.set_jwt_secret(secret);
    match signed_token(&user) {
        Ok(token) => {
            ProductAuthJobOutcome::success(HttpResponse::json(200, json!({"token": token})))
        }
        Err(err) => ProductAuthJobOutcome::neutral(HttpResponse::json(
            500,
            json!({"error": err.to_string()}),
        )),
    }
}

fn execute_auth_request<F>(
    app: &AppState,
    context: ProductHttpRequestContext,
    username: &str,
    action: F,
) -> HttpResponse
where
    F: FnOnce() -> ProductAuthJobOutcome + Send + 'static,
{
    match app.auth_runtime.execute(context.peer_ip, username, action) {
        Ok(response) => response,
        Err(ProductAuthExecutionError::Busy { retry_after }) => {
            let retry_after_seconds = retry_after.as_secs().max(1);
            let mut response = HttpResponse::json(
                429,
                json!({"error": "authentication is temporarily busy; retry later"}),
            );
            response
                .extra_headers
                .push(("Retry-After".to_owned(), retry_after_seconds.to_string()));
            response
        }
        Err(ProductAuthExecutionError::Unavailable) => HttpResponse::json(
            503,
            json!({"error": "authentication service is unavailable"}),
        ),
        Err(ProductAuthExecutionError::TimedOut) => {
            HttpResponse::json(503, json!({"error": "authentication service timed out"}))
        }
    }
}
