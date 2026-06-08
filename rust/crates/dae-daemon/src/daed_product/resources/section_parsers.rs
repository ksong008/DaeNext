use super::*;
pub(crate) fn parsed_dns_value(raw: &str) -> Value {
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

pub(crate) fn parsed_routing_value(raw: &str) -> Value {
    json!({
        "routing": raw,
        "parsedRouting": {
            "string": raw
        }
    })
}
