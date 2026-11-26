use dae_outbound_quic::boring_quic::{BoringQuicClientHelloProfile, BoringQuicClientPolicy};

use super::*;

pub(super) fn xhttp_h3_boring_policy(
    endpoint: &ResidentXhttpEndpointPlan,
    tls_provider: ResidentXhttpQuicTlsProvider,
) -> Result<BoringQuicClientPolicy, String> {
    let profile = match tls_provider {
        ResidentXhttpQuicTlsProvider::Boring => BoringQuicClientHelloProfile::Generic,
        ResidentXhttpQuicTlsProvider::ChromeBoring => BoringQuicClientHelloProfile::Chrome,
        ResidentXhttpQuicTlsProvider::ChromeBoringHybrid => {
            BoringQuicClientHelloProfile::ChromeHybrid
        }
        ResidentXhttpQuicTlsProvider::Chrome152 => BoringQuicClientHelloProfile::Chrome152,
    };
    BoringQuicClientPolicy::new([b"h3".as_slice()])
        .map(|policy| {
            policy
                .allow_insecure(endpoint.allow_insecure)
                .zero_rtt(false)
                .client_hello_profile(profile)
        })
        .map_err(|err| format!("build xHTTP H3 BoringSSL QUIC policy: {err}"))
}

#[cfg(test)]
#[path = "h3_boring_tls_tests.rs"]
pub mod tests;
