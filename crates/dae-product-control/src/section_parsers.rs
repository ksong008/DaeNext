use serde_json::{Value, json};

pub fn parsed_dns_value(raw: &str) -> Value {
    json!({
        "dns": raw,
        "parsedDns": {
            "string": raw,
            "routing": {
                "request": {"string": ""},
                "response": {"string": ""}
            }
        }
    })
}

pub fn parsed_routing_value(raw: &str) -> Value {
    json!({
        "routing": raw,
        "parsedRouting": {
            "string": raw
        }
    })
}
