use super::*;
use dae_product_subscription::{
    NewSubscriptionRecord, SubscriptionRecordUpdate, get_subscription_value,
    list_subscriptions_value,
};

pub(crate) fn list_subscriptions(state: &Path, request: &HttpRequest) -> HttpResponse {
    let expand_nodes = request
        .query
        .get("expand")
        .map(|values| values.iter().any(|value| value == "nodes"))
        .unwrap_or(false);
    match list_subscriptions_value(state, expand_nodes) {
        Ok(value) => HttpResponse::json(200, value),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn create_subscription(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    request: &HttpRequest,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let link = body.get("link").and_then(Value::as_str).unwrap_or("");
    if link.is_empty() {
        return HttpResponse::json(400, json!({"error": "link is required"}));
    }
    if let Some(cron_exp) = body.get("cronExp").and_then(Value::as_str)
        && let Err(err) = validate_subscription_cron_expression(cron_exp)
    {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let tag = body.get("tag").and_then(Value::as_str);
    let use_proxy = body
        .get("useProxy")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let id = match dae_product_subscription::create_subscription_record(
        state,
        NewSubscriptionRecord {
            link,
            cron_exp: body
                .get("cronExp")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_SUBSCRIPTION_CRON_EXP),
            cron_enable: body
                .get("cronEnable")
                .and_then(Value::as_bool)
                .unwrap_or(DEFAULT_SUBSCRIPTION_CRON_ENABLE),
            status: DEFAULT_SUBSCRIPTION_STATUS,
            tag,
            use_proxy,
            updated_at: &now_text(),
        },
    ) {
        Ok(id) => id,
        Err(dae_product_subscription::SubscriptionMutationError::TagConflict) => {
            return subscription_tag_conflict_response();
        }
        Err(error) => return HttpResponse::json(400, json!({"error": error.to_string()})),
    };
    notify_subscription_scheduler();
    let import_log_message = format!("subscription {id} imported");
    let _ = append_log_for_config(config_dir, state, "info", &import_log_message);
    let import_report = refresh_subscription_from_remote(control_runtime, state, config_dir, id)
        .unwrap_or_else(|_| {
            json!({
                "link": link,
                "fetched": false,
                "fetchError": Value::Null,
                "refreshError": {
                    "code": "refresh_failed",
                    "message": "subscription refresh could not be completed",
                    "retryable": true,
                },
                "refreshOutcome": "refresh-error-preserved",
                "preservedExistingNodes": true,
                "runtimeInputChanged": false,
                "nodeImportResult": []
            })
        });
    let mut response =
        subscription_import_result::subscription_import_response_value(id, link, &import_report);
    copy_subscription_refresh_fields(&import_report, &mut response);
    let outcome = SubscriptionRefreshOutcome::from_report(&import_report);
    apply_runtime_after_subscription_change(
        state,
        config_dir,
        runtime,
        outcome.requests_runtime_apply(),
        "subscription-create",
    )
    .insert_into(&mut response);
    HttpResponse::json(201, response)
}

pub(crate) fn get_subscription(state: &Path, id: i64) -> HttpResponse {
    match get_subscription_value(state, id) {
        Ok(Some(value)) => HttpResponse::json(200, value),
        Ok(None) => HttpResponse::json(404, json!({"error": "subscription not found"})),
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

pub(crate) fn update_subscription(state: &Path, request: &HttpRequest, id: i64) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    let body = match json_body(request) {
        Ok(body) => body,
        Err(err) => return HttpResponse::json(400, json!({"error": err})),
    };
    let link = body.get("link").and_then(Value::as_str);
    let tag_present = body.get("tag").is_some();
    let tag = body.get("tag").and_then(Value::as_str);
    let cron_exp = body.get("cronExp").and_then(Value::as_str);
    if let Some(cron_exp) = cron_exp
        && let Err(err) = validate_subscription_cron_expression(cron_exp)
    {
        return HttpResponse::json(400, json!({"error": err}));
    }
    let cron_enable = body
        .get("cronEnable")
        .and_then(Value::as_bool)
        .map(|value| value as i64);
    let use_proxy = body
        .get("useProxy")
        .and_then(Value::as_bool)
        .map(|value| value as i64);
    let updated = match dae_product_subscription::update_subscription_record(
        state,
        SubscriptionRecordUpdate {
            id,
            link,
            tag_present,
            tag,
            cron_exp,
            cron_enable: cron_enable.map(|value| value != 0),
            use_proxy: use_proxy.map(|value| value != 0),
            updated_at: &now_text(),
        },
    ) {
        Ok(updated) => updated,
        Err(dae_product_subscription::SubscriptionMutationError::TagConflict) => {
            return subscription_tag_conflict_response();
        }
        Err(error) => return HttpResponse::json(400, json!({"error": error.to_string()})),
    };
    if !updated {
        return HttpResponse::json(404, json!({"error": "subscription not found"}));
    }
    notify_subscription_scheduler();
    get_subscription(state, id)
}

pub(crate) fn refresh_subscription(
    control_runtime: &ProductControlRuntime,
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    id: i64,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    notify_subscription_scheduler();
    match refresh_subscription_from_remote(control_runtime, state, config_dir, id) {
        Ok(mut report) => {
            let outcome = SubscriptionRefreshOutcome::from_report(&report);
            let (level, message) = if outcome.fetched {
                ("info", format!("subscription {id} refreshed"))
            } else {
                ("warn", format!("subscription {id} refresh fetch failed"))
            };
            let _ = append_log_for_config(config_dir, state, level, &message);
            apply_runtime_after_subscription_change(
                state,
                config_dir,
                runtime,
                outcome.requests_runtime_apply(),
                "subscription-refresh",
            )
            .insert_into(&mut report);
            if let Some(subscription) = get_subscription_value(state, id)
                .ok()
                .flatten()
                .and_then(|value| value.as_object().cloned())
                && let Value::Object(map) = &mut report
            {
                for (key, value) in subscription {
                    map.insert(key, value);
                }
            }
            HttpResponse::json(200, report)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            HttpResponse::json(404, json!({"error": err.to_string()}))
        }
        Err(err) => HttpResponse::json(400, json!({"error": err.to_string()})),
    }
}

pub(crate) fn delete_subscriptions(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    request: &HttpRequest,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    let body = json_body(request).unwrap_or_else(|_| json!({}));
    let ids = integer_array(&body, "ids");
    let removed = match delete_subscriptions_by_ids(state, &ids) {
        Ok(removed) => removed,
        Err(err) => return HttpResponse::json(500, json!({"error": err.to_string()})),
    };
    let mut response = json!({"removed": removed});
    apply_runtime_after_subscription_change(
        state,
        config_dir,
        runtime,
        removed != 0,
        "subscription-delete-bulk",
    )
    .insert_into(&mut response);
    HttpResponse::json(200, response)
}

pub(crate) fn delete_subscription_by_id(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
    id: i64,
) -> HttpResponse {
    let _reclaim_busy = allocator_reclaim_busy(AllocatorReclaimBusyKind::Subscription);
    match delete_subscription(state, id) {
        Ok(removed) => {
            let mut response = json!({"removed": removed});
            apply_runtime_after_subscription_change(
                state,
                config_dir,
                runtime,
                removed != 0,
                "subscription-delete",
            )
            .insert_into(&mut response);
            HttpResponse::json(200, response)
        }
        Err(err) => HttpResponse::json(500, json!({"error": err.to_string()})),
    }
}

fn copy_subscription_refresh_fields(source: &Value, target: &mut Value) {
    let (Value::Object(source), Value::Object(target)) = (source, target) else {
        return;
    };
    for key in [
        "fetched",
        "fetchedAt",
        "refreshOutcome",
        "sourceKind",
        "sourceNodeCount",
        "admittedNodeCount",
        "invalidNodeCount",
        "notAdmittedNodeCount",
        "preservedExistingNodes",
        "runtimeInputChanged",
        "fetchError",
        "refreshError",
    ] {
        if let Some(value) = source.get(key) {
            target.insert(key.to_owned(), value.clone());
        }
    }
}

fn subscription_tag_conflict_response() -> HttpResponse {
    HttpResponse::json(
        409,
        json!({
            "error": "a subscription with this tag already exists; update it or choose a different tag",
            "errorCode": "subscription_tag_conflict",
            "retryable": false,
        }),
    )
}
