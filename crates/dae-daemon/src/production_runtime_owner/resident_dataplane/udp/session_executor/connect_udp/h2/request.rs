use http::{Method, Request, Response};

use super::*;

const CONNECT_UDP_PROTOCOL: &str = "connect-udp";

pub(super) fn connect_udp_h2_request(
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
) -> Result<Request<()>, String> {
    let parts = connect_udp_request_parts(proxy, target, connect_udp_h2_plan(proxy)?)?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(parts.uri)
        .header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE)
        .body(())
        .map_err(|err| format!("build CONNECT-UDP H2 request: {err}"))?;
    request
        .extensions_mut()
        .insert(::h2::ext::Protocol::from_static(CONNECT_UDP_PROTOCOL));
    if let Some(authorization) = parts.authorization {
        request
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, authorization);
    }
    Ok(request)
}

pub(super) fn validate_connect_udp_h2_response<B>(response: &Response<B>) -> Result<(), String> {
    validate_connect_udp_response(response, "H2")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_requires_success_and_explicit_capsule_negotiation() {
        let accepted = Response::builder()
            .status(200)
            .header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE)
            .body(())
            .unwrap();
        validate_connect_udp_h2_response(&accepted).unwrap();

        let missing = Response::builder().status(200).body(()).unwrap();
        assert!(validate_connect_udp_h2_response(&missing).is_err());
        let rejected = Response::builder()
            .status(407)
            .header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE)
            .body(())
            .unwrap();
        assert!(validate_connect_udp_h2_response(&rejected).is_err());
    }

    #[test]
    fn protocol_constant_is_not_an_ordinary_connect_inference() {
        assert_eq!(CONNECT_UDP_PROTOCOL, "connect-udp");
        assert_ne!(CONNECT_UDP_PROTOCOL, "http");
        assert_ne!(CONNECT_UDP_PROTOCOL, "https");
    }
}
