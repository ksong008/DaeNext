use super::*;

const SUBSCRIPTION_IMPORT_ERROR_SAMPLE_LIMIT: usize = 8;

pub(super) fn subscription_import_response_value(
    subscription_id: i64,
    link: &str,
    node_import_result: Value,
) -> Value {
    let items = node_import_result.as_array().cloned().unwrap_or_default();
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
    let error = if failed_node_count == 0 {
        Value::Null
    } else {
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
    };
    json!({
        "link": link,
        "subscription": {"id": subscription_id},
        "subscriptionCreated": true,
        "importedNodeCount": imported_node_count,
        "failedNodeCount": failed_node_count,
        "partialFailure": failed_node_count != 0,
        "error": error,
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
            json!([
                {"link": "one", "error": null, "node": {"id": 11}},
                {"link": "two", "error": "bad node", "node": null}
            ]),
        );
        assert_eq!(value["subscriptionCreated"], json!(true));
        assert_eq!(value["importedNodeCount"], json!(1));
        assert_eq!(value["failedNodeCount"], json!(1));
        assert_eq!(value["partialFailure"], json!(true));
        assert!(value["error"].as_str().unwrap().contains("bad node"));
    }
}
