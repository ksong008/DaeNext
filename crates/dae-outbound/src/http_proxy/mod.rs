pub use dae_outbound_core::http_proxy::{application_protocol, contract, link};
pub mod dataplane {
    pub use dae_outbound_stream::http_proxy::dataplane::*;
}
pub mod request {
    pub use dae_outbound_stream::http_proxy::request::*;
}

#[cfg(any(test, feature = "test-support"))]
mod tls_dataplane;

pub use dae_outbound_core::http_proxy::{EffectiveHttpProxyApplicationProtocol, HTTP_1_1_ALPN};
pub use dae_outbound_core::http_proxy::{HttpProxyLink, HttpScheme};
pub use dae_outbound_stream::http_proxy::{
    HttpConnectExchangeReport, HttpConnectOptions, HttpForwardRequest, HttpTransportMode,
    connect_exchange, connect_exchange_over_stream,
};
#[cfg(any(test, feature = "test-support"))]
pub use tls_dataplane::{HttpsProxyTlsExchangeReport, connect_exchange_over_tls_stream};
