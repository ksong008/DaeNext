use serde_json::{Value, json};

const SUBSCRIPTION_IMPORT_ERROR_SAMPLE_LIMIT: usize = 8;

pub fn subscription_import_response_value(
    subscription_id: i64,
    link: &str,
    refresh_report: &Value,
) -> Value {
    let items = refresh_report["nodeImportResult"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let imported_node_count = items
        .iter()
        .filter(|item| {
            item.get("error").is_none_or(Value::is_null)
                && item.get("node").is_some_and(|node| !node.is_null())
        })
        .count();
    let errors = items
        .iter()
        .filter_map(|item| item.get("error").and_then(Value::as_str))
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .collect::<Vec<_>>();
    let failed_node_count = errors.len();
    let fetch_error = refresh_report
        .get("fetchError")
        .filter(|value| !value.is_null())
        .cloned();
    let refresh_error = refresh_report
        .get("refreshError")
        .filter(|value| !value.is_null())
        .cloned();
    let error = if let Some(message) = fetch_error
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
    {
        json!(format!(
            "subscription {subscription_id} was created, but its initial fetch failed: {message}"
        ))
    } else if let Some(message) = refresh_error
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
    {
        json!(format!(
            "subscription {subscription_id} was created, but its initial refresh failed: {message}"
        ))
    } else if failed_node_count != 0 {
        let detail = errors
            .iter()
            .take(SUBSCRIPTION_IMPORT_ERROR_SAMPLE_LIMIT)
            .copied()
            .collect::<Vec<_>>()
            .join("; ");
        let omitted = failed_node_count.saturating_sub(SUBSCRIPTION_IMPORT_ERROR_SAMPLE_LIMIT);
        let suffix = if omitted == 0 {
            String::new()
        } else {
            format!("; {omitted} additional errors omitted")
        };
        json!(format!(
            "subscription {subscription_id} was created, but {failed_node_count} node import(s) failed: {detail}{suffix}"
        ))
    } else {
        Value::Null
    };
    let partial_failure =
        fetch_error.is_some() || refresh_error.is_some() || failed_node_count != 0;
    json!({
        "link": link,
        "subscription": {"id": subscription_id},
        "subscriptionCreated": true,
        "importedNodeCount": imported_node_count,
        "failedNodeCount": failed_node_count,
        "partialFailure": partial_failure,
        "error": error,
        "fetchError": fetch_error.unwrap_or(Value::Null),
        "refreshError": refresh_error.unwrap_or(Value::Null),
        "nodeImportResult": items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_distinguishes_record_creation_from_nested_node_failure() {
        let value = subscription_import_response_value(
            7,
            "https://example.invalid/subscription",
            &json!({
                "nodeImportResult": [
                    {"link": "one", "error": null, "node": {"id": 11}},
                    {"link": "two", "error": "bad node", "node": null}
                ]
            }),
        );
        assert_eq!(value["subscriptionCreated"], json!(true));
        assert_eq!(value["importedNodeCount"], json!(1));
        assert_eq!(value["failedNodeCount"], json!(1));
        assert_eq!(value["partialFailure"], json!(true));
        assert!(value["error"].as_str().unwrap().contains("bad node"));
    }

    #[test]
    fn response_keeps_fetch_failure_out_of_node_import_counts() {
        let value = subscription_import_response_value(
            9,
            "https://example.invalid/subscription",
            &json!({
                "fetched": false,
                "fetchError": {
                    "code": "tls_unknown_issuer",
                    "message": "subscription TLS certificate is not issued by a trusted authority",
                    "retryable": false,
                },
                "nodeImportResult": [],
            }),
        );
        assert_eq!(value["subscriptionCreated"], true);
        assert_eq!(value["importedNodeCount"], 0);
        assert_eq!(value["failedNodeCount"], 0);
        assert_eq!(value["partialFailure"], true);
        assert_eq!(value["fetchError"]["code"], "tls_unknown_issuer");
        assert!(value["nodeImportResult"].as_array().unwrap().is_empty());
        assert!(
            value["error"]
                .as_str()
                .unwrap()
                .contains("initial fetch failed")
        );
        assert!(!value["error"].as_str().unwrap().contains("node import"));
    }
}
