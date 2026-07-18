use super::*;

pub(super) fn validate_resident_xhttp_primary_quic_tls_features(
    http_version: ResidentXhttpHttpVersion,
    fingerprint: Option<&ResidentUtlsFingerprintPlan>,
    node_tag: &str,
) -> Result<(), String> {
    if http_version != ResidentXhttpHttpVersion::H3 {
        return Ok(());
    }
    ResidentXhttpQuicTlsProvider::for_primary(fingerprint)
        .map(|_| ())
        .map_err(|err| format!("resident dataplane vless {err} for node {node_tag}"))
}

pub(super) fn validate_resident_xhttp_reality_http_version(
    http_version: ResidentXhttpHttpVersion,
    endpoint: &str,
    alpn: &[String],
    node_tag: &str,
) -> Result<(), String> {
    let reason = match http_version {
        ResidentXhttpHttpVersion::H1 => {
            "follows official HTTP/2 selection and does not admit single http/1.1 ALPN"
        }
        ResidentXhttpHttpVersion::H3 => {
            "does not admit HTTP/3 because the QUIC TLS carrier has no Reality executor"
        }
        ResidentXhttpHttpVersion::H2 => return Ok(()),
    };
    Err(format!(
        "resident dataplane vless xHTTP {endpoint} {reason} for node {node_tag}; got {}",
        alpn.join(",")
    ))
}
