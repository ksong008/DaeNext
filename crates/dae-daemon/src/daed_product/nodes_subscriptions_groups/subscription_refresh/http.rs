use super::*;

mod client;
mod request;
mod response;

pub(super) use client::fetch_http_url_with_proxy_config;
#[cfg(test)]
pub(crate) use request::subscription_http_request;
#[cfg(test)]
pub(crate) use response::{
    decode_chunked_body, decode_chunked_body_with_limit, http_response_body_with_limit,
    read_subscription_http_response_with_limit,
};

const SUBSCRIPTION_HTTP_REDIRECT_LIMIT: usize = 8;
