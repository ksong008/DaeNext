use super::*;

pub(crate) const GROUP_SUBSCRIPTION_FILTER_PREVIEW_PER_SUBSCRIPTION_SAMPLE_LIMIT: usize = 8;
pub(crate) const GROUP_SUBSCRIPTION_FILTER_PREVIEW_TOTAL_SAMPLE_LIMIT: usize = 64;

pub(crate) fn preview_group_subscription_filter(
    state: &Path,
    request: &HttpRequest,
) -> HttpResponse {
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let subscription_ids = integer_array(&body, "subscriptionIds");
    let name_filter_regex = match body.get("nameFilterRegex") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return HttpResponse::json(
                400,
                json!({"error": "nameFilterRegex must be a string or null"}),
            );
        }
    };
    match group_subscription_filter_preview_value(state, &subscription_ids, name_filter_regex) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            HttpResponse::json(400, json!({"error": err.to_string()}))
        }
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn group_subscription_filter_preview_value(
    state: &Path,
    subscription_ids: &[i64],
    name_filter_regex: Option<&str>,
) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let filter = compile_name_filter(name_filter_regex)?;
    let mut seen_subscription_ids = HashSet::new();
    let mut total_matched_count = 0usize;
    let mut total_sampled_count = 0usize;
    let mut items = Vec::new();

    for subscription_id in subscription_ids
        .iter()
        .copied()
        .filter(|id| seen_subscription_ids.insert(*id))
    {
        let mut matched_count = 0usize;
        let mut sample_matched_nodes = Vec::new();
        visit_subscription_nodes_matching_name_filter(
            &conn,
            subscription_id,
            filter.as_ref(),
            |node| {
                matched_count = matched_count.saturating_add(1);
                if sample_matched_nodes.len()
                    < GROUP_SUBSCRIPTION_FILTER_PREVIEW_PER_SUBSCRIPTION_SAMPLE_LIMIT
                    && total_sampled_count < GROUP_SUBSCRIPTION_FILTER_PREVIEW_TOTAL_SAMPLE_LIMIT
                {
                    sample_matched_nodes.push(node);
                    total_sampled_count = total_sampled_count.saturating_add(1);
                }
            },
        )?;
        total_matched_count = total_matched_count.saturating_add(matched_count);
        let sample_truncated = matched_count > sample_matched_nodes.len();
        items.push(json!({
            "subscriptionId": subscription_id,
            "matchedCount": matched_count,
            "sampleMatchedNodes": sample_matched_nodes,
            "sampleTruncated": sample_truncated,
        }));
    }

    Ok(json!({
        "matchedCount": total_matched_count,
        "items": items,
    }))
}
