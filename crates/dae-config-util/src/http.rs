pub fn is_valid_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET"
            | "POST"
            | "PUT"
            | "PATCH"
            | "DELETE"
            | "COPY"
            | "HEAD"
            | "OPTIONS"
            | "LINK"
            | "UNLINK"
            | "PURGE"
            | "LOCK"
            | "UNLOCK"
            | "PROPFIND"
            | "CONNECT"
            | "TRACE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_method_whitelist_matches_golden_fixture() {
        let fixture = dae_golden::load_json("config/utils/common.json").unwrap();
        let methods = &fixture["http_methods"];

        for method in methods["valid"].as_array().unwrap() {
            assert!(is_valid_http_method(method.as_str().unwrap()));
        }
        for method in methods["invalid"].as_array().unwrap() {
            assert!(!is_valid_http_method(method.as_str().unwrap()));
        }
    }
}
