use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderValue, Response, Uri};

use super::*;

pub(super) const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
pub(super) const CAPSULE_PROTOCOL_TRUE: &str = "?1";

pub(super) struct ConnectUdpRequestParts {
    pub(super) uri: Uri,
    pub(super) authorization: Option<HeaderValue>,
}

pub(super) fn connect_udp_request_parts(
    proxy: &ResidentProxyPlan,
    target: SocketAddr,
    plan: ConnectUdpPlanRef<'_>,
) -> Result<ConnectUdpRequestParts, String> {
    let authority = authority_from_host_port(&proxy.server_host, proxy.server_port);
    let uri = plan
        .target_template
        .expand_request_uri(target, &authority)
        .map_err(|err| format!("expand CONNECT-UDP target URI: {err}"))?;
    let authorization = match plan.authentication {
        ResidentConnectUdpAuthPlan::None => None,
        ResidentConnectUdpAuthPlan::Basic { username, password } => {
            let encoded = STANDARD.encode(format!("{username}:{password}"));
            let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
                .map_err(|err| format!("build CONNECT-UDP Basic authorization: {err}"))?;
            value.set_sensitive(true);
            Some(value)
        }
    };
    Ok(ConnectUdpRequestParts { uri, authorization })
}

pub(super) fn validate_connect_udp_response<B>(
    response: &Response<B>,
    transport: &str,
) -> Result<(), String> {
    if !response.status().is_success() {
        return Err(format!(
            "CONNECT-UDP {transport} proxy response status {}",
            response.status()
        ));
    }
    let negotiated = response
        .headers()
        .get(CAPSULE_PROTOCOL_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == CAPSULE_PROTOCOL_TRUE);
    if !negotiated {
        return Err(format!(
            "CONNECT-UDP {transport} response did not negotiate Capsule Protocol with capsule-protocol: ?1"
        ));
    }
    Ok(())
}
