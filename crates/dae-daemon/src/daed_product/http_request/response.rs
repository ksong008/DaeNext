use super::*;

pub(in crate::daed_product) fn http_request_read_error_response(
    error: &HttpRequestReadError,
) -> Option<HttpResponse> {
    match error.kind() {
        HttpRequestReadErrorKind::IdleHeaderTimeout
        | HttpRequestReadErrorKind::ConnectionClosed => None,
        HttpRequestReadErrorKind::PartialHeaderTimeout => Some(HttpResponse::json(
            408,
            json!({
                "error": "request header read timeout",
                "errorCode": "request_header_timeout",
                "retryable": true,
            }),
        )),
        HttpRequestReadErrorKind::BodyTimeout => Some(HttpResponse::json(
            408,
            json!({
                "error": "request body read timeout",
                "errorCode": "request_body_timeout",
                "retryable": true,
            }),
        )),
        HttpRequestReadErrorKind::InvalidRequest | HttpRequestReadErrorKind::Io => {
            Some(HttpResponse::json(
                400,
                json!({
                    "error": format!("bad request: {error}")
                }),
            ))
        }
    }
}
