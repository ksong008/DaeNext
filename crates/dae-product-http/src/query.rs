use crate::HttpRequest;

pub fn query_u64(request: &HttpRequest, key: &str) -> Option<u64> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<u64>().ok())
}

pub fn query_usize(request: &HttpRequest, key: &str) -> Option<usize> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| value.parse::<usize>().ok())
}

pub fn query_bool(request: &HttpRequest, key: &str) -> Option<bool> {
    request
        .query
        .get(key)
        .and_then(|values| values.first())
        .and_then(|value| parse_bool(value))
}

pub fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn query_values_use_the_first_value_and_parse_strictly() {
        let request = HttpRequest {
            method: "GET".to_owned(),
            path: "/api/test".to_owned(),
            query: HashMap::from([
                ("u64".to_owned(), vec!["42".to_owned(), "43".to_owned()]),
                ("usize".to_owned(), vec!["7".to_owned()]),
                ("bool".to_owned(), vec![" YES ".to_owned()]),
            ]),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        assert_eq!(query_u64(&request, "u64"), Some(42));
        assert_eq!(query_usize(&request, "usize"), Some(7));
        assert_eq!(query_bool(&request, "bool"), Some(true));
        assert_eq!(query_u64(&request, "missing"), None);
        assert_eq!(query_usize(&request, "invalid"), None);
    }

    #[test]
    fn boolean_query_parser_accepts_documented_spellings_only() {
        for value in ["1", "true", "yes", "on", " TRUE "] {
            assert_eq!(parse_bool(value), Some(true), "{value}");
        }
        for value in ["0", "false", "no", "off", " OFF "] {
            assert_eq!(parse_bool(value), Some(false), "{value}");
        }
        for value in ["", "2", "maybe"] {
            assert_eq!(parse_bool(value), None, "{value}");
        }
    }
}
