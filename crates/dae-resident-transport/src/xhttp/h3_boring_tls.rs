use std::sync::Arc;

use super::h3_transport::xhttp_h3_transport_config;
use super::*;

#[cfg(test)]
pub fn build_chrome_boring_xhttp_h3_client_config(
    endpoint: &ResidentXhttpEndpointPlan,
    session_cache: Option<dae_outbound_quic::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, String> {
    let policy = chrome_boring_xhttp_h3_policy(endpoint)?;
    dae_outbound_quic::boring_quic::build_boring_quic_client_config_with_session_cache(
        &policy,
        Arc::new(xhttp_h3_transport_config()?),
        session_cache,
    )
    .map_err(|err| format!("build xHTTP H3 Chrome BoringSSL QUIC config: {err}"))
}

pub fn build_chrome_boring_xhttp_h3_client_config_with_system_ca(
    endpoint: &ResidentXhttpEndpointPlan,
    system_ca: Option<Arc<dae_outbound_quic::system_ca::SystemCaSnapshot>>,
    session_cache: Option<dae_outbound_quic::boring_quic::BoringQuicSessionCache>,
) -> Result<quinn::ClientConfig, String> {
    let policy = chrome_boring_xhttp_h3_policy(endpoint)?;
    dae_outbound_quic::boring_quic::build_boring_quic_client_config_with_session_cache_and_system_ca_snapshot(
        &policy,
        Arc::new(xhttp_h3_transport_config()?),
        session_cache,
        system_ca,
    )
    .map_err(|err| format!("build xHTTP H3 Chrome BoringSSL QUIC config: {err}"))
}

#[cfg(test)]
fn build_chrome_boring_xhttp_h3_crypto(
    endpoint: &ResidentXhttpEndpointPlan,
    _system_ca: Option<&dae_outbound_quic::system_ca::SystemCaSnapshot>,
) -> Result<quinn_boring::ClientConfig, String> {
    let policy = chrome_boring_xhttp_h3_policy(endpoint)?;
    dae_outbound_quic::boring_quic::build_boring_quic_client_crypto(&policy)
        .map_err(|err| format!("build xHTTP H3 Chrome BoringSSL QUIC crypto: {err}"))
}

fn chrome_boring_xhttp_h3_policy(
    endpoint: &ResidentXhttpEndpointPlan,
) -> Result<dae_outbound_quic::boring_quic::BoringQuicClientPolicy, String> {
    dae_outbound_quic::boring_quic::BoringQuicClientPolicy::new([b"h3".as_slice()])
        .map(|policy| {
            policy
                .allow_insecure(endpoint.allow_insecure)
                .zero_rtt(false)
                .client_hello_profile(
                    dae_outbound_quic::boring_quic::BoringQuicClientHelloProfile::Chrome,
                )
        })
        .map_err(|err| format!("build xHTTP H3 Chrome BoringSSL QUIC policy: {err}"))
}

#[cfg(test)]
#[path = "h3_boring_tls_tests.rs"]
pub mod tests;
