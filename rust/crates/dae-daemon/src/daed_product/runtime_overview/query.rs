use super::*;
pub(crate) fn query_u64(request: &HttpRequest, key: &str) -> Option<u64> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<u64>().ok())
}

pub(crate) fn query_usize(request: &HttpRequest, key: &str) -> Option<usize> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<usize>().ok())
}

pub(crate) fn query_bool(request: &HttpRequest, key: &str) -> Option<bool> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| parse_bool(value))
}

pub(crate) fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
