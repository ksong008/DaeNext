use super::*;

mod client;
mod direct_exchange;

mod request {
    pub(crate) use dae_product_subscription::subscription_http_request;
}
mod response {
    pub(super) use dae_product_subscription::{
        SubscriptionHttpResponse, first_header, is_subscription_redirect,
        parse_subscription_http_response, subscription_http_response_limit,
    };
    #[cfg(test)]
    pub(crate) use dae_product_subscription::{
        decode_chunked_body, decode_chunked_body_with_limit, http_response_body_with_limit,
        read_subscription_http_response_with_limit,
    };
}

pub(super) use client::fetch_http_url_with_proxy_config;
#[cfg(test)]
pub(crate) use direct_exchange::subscription_tls_alpn_protocols;
#[cfg(test)]
pub(crate) use request::subscription_http_request;
#[cfg(test)]
pub(crate) use response::{
    decode_chunked_body, decode_chunked_body_with_limit, http_response_body_with_limit,
    read_subscription_http_response_with_limit,
};

const SUBSCRIPTION_HTTP_REDIRECT_LIMIT: usize = 8;
