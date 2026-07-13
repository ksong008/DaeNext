use http::{Method, Request, Response};

use super::*;

pub(super) fn connect_udp_h3_request(
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
) -> Result<Request<()>, String> {
    let parts = connect_udp_request_parts(proxy, target, connect_udp_h3_plan(proxy)?)?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(parts.uri)
        .header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE)
        .body(())
        .map_err(|err| format!("build CONNECT-UDP H3 request: {err}"))?;
    request
        .extensions_mut()
        .insert(::h3::ext::Protocol::CONNECT_UDP);
    if let Some(authorization) = parts.authorization {
        request
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, authorization);
    }
    Ok(request)
}

pub(super) fn validate_connect_udp_h3_response<B>(response: &Response<B>) -> Result<(), String> {
    validate_connect_udp_response(response, "H3")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_response_requires_success_and_capsule_negotiation() {
        assert!(
            validate_connect_udp_h3_response(
                &Response::builder()
                    .status(200)
                    .header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE)
                    .body(())
                    .unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_connect_udp_h3_response(&Response::builder().status(200).body(()).unwrap())
                .is_err()
        );
        assert!(
            validate_connect_udp_h3_response(&Response::builder().status(407).body(()).unwrap())
                .is_err()
        );
    }
}
