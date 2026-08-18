pub(crate) use dae_resident_transport::{
    AsyncResidentTlsClient, AsyncVlessTlsClient, async_resident_tls_underlay_name,
    async_tls_underlay_name, clear_resident_tls_config_caches,
    open_async_resident_tls_client_with_binding,
    open_async_vless_tls_client_with_flow_at_candidates, open_async_xhttp_endpoint_tls_client,
    open_async_xhttp_endpoint_tls_client_at_candidates, open_proxy_tcp_stream_with_binding,
    take_boring_tls_io_profile_snapshot,
};
