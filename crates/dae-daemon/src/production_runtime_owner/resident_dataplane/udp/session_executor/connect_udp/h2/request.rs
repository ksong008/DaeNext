use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderValue, Method, Request, Response};

use super::*;

const CONNECT_UDP_PROTOCOL: &str = "connect-udp";
const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_TRUE: &str = "?1";

pub(super) fn connect_udp_h2_request(
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
) -> Result<Request<()>, String> {
    let plan = connect_udp_h2_plan(proxy)?;
    let authority = authority_from_host_port(&proxy.server_host, proxy.server_port);
    let uri = plan
        .target_template
        .expand_request_uri(target, &authority)
        .map_err(|err| format!("expand CONNECT-UDP H2 target URI: {err}"))?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header(CAPSULE_PROTOCOL_HEADER, CAPSULE_PROTOCOL_TRUE)
        .body(())
        .map_err(|err| format!("build CONNECT-UDP H2 request: {err}"))?;
    request
        .extensions_mut()
        .insert(::h2::ext::Protocol::from_static(CONNECT_UDP_PROTOCOL));
    if let Some(authorization) = basic_authorization(plan.authentication)? {
        request
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, authorization);
    }
    Ok(request)
}

pub(super) fn validate_connect_udp_h2_response<B>(response: &Response<B>) -> Result<(), String> {
    if !response.status().is_success() {
        return Err(format!(
            "CONNECT-UDP H2 proxy response status {}",
            response.status()
        ));
    }
    let negotiated = response
        .headers()
        .get(CAPSULE_PROTOCOL_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == CAPSULE_PROTOCOL_TRUE);
    if !negotiated {
        return Err(
            "CONNECT-UDP H2 response did not negotiate Capsule Protocol with capsule-protocol: ?1"
                .to_owned(),
        );
    }
    Ok(())
}

fn basic_authorization(
    authentication: &ResidentConnectUdpAuthPlan,
) -> Result<Option<HeaderValue>, String> {
    let ResidentConnectUdpAuthPlan::Basic { username, password } = authentication else {
        return Ok(None);
    };
    let encoded = STANDARD.encode(format!("{username}:{password}"));
    let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
        .map_err(|err| format!("build CONNECT-UDP Basic authorization: {err}"))?;
    value.set_sensitive(true);
    Ok(Some(value))
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
