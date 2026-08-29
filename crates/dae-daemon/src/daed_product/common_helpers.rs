use super::*;

pub(super) fn authenticate_request(
    app: &AppState,
    request: &HttpRequest,
) -> io::Result<Option<UserRecord>> {
    let token = request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            if request.method == "GET"
                && (request.path == "/api/events/runtime" || request.path == "/api/events/logs")
            {
                request
                    .query
                    .get("access_token")
                    .and_then(|values| values.first())
                    .map(String::as_str)
            } else {
                None
            }
        });
    let Some(token) = token else {
        return Ok(None);
    };
    verify_token(&app.state, token)
}
