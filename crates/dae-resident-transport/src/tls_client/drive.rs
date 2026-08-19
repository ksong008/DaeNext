use super::*;
pub fn async_tls_underlay_name(client: &AsyncVlessTlsClient) -> &'static str {
    match &client.engine {
        AsyncVlessTlsEngine::RealityBoring { .. } => "reality-boringssl",
        AsyncVlessTlsEngine::Boring { .. } => "boringssl",
    }
}

pub fn async_resident_tls_underlay_name(client: &AsyncResidentTlsClient) -> &'static str {
    async_tls_underlay_name(client)
}
